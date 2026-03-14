/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aidl/Gtest.h>
#include <aidl/Vintf.h>
#include <aidl/android/hardware/wifi/IWifi.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/binder_status.h>
#include <dirent.h>
#include <gtest/gtest.h>
#include <net/if.h>
#include <unistd.h>

#include <cstdlib>
#include <sstream>
#include <vector>

#include "netlink_helper.h"

namespace {
using aidl::android::hardware::wifi::IWifi;

constexpr uint32_t WONDER_VENDOR_ID = 0x001A11;
constexpr char WONDER_INTERFACE_NAME[] = "wonder0";
constexpr char WONDER_PHY_NAME[] = "wonder";

enum WonderVendorSubCmd {
  SUBCMD_SET_CHANNEL = 0x1,
  SUBCMD_SET_BSSID_FILTER = 0x2,
  SUBCMD_SET_TX_RATE = 0x3,
  SUBCMD_SET_REGULATORY_DOMAIN = 0x4,
  SUBCMD_GET_MAC_ADDRESS = 0x5,
};
}  // namespace

// The main test class for wlc HAL.
class WonderTest : public ::testing::TestWithParam<std::string> {
 public:
  virtual void SetUp() override {
    std::system("cmd wifi set-scan-always-available disabled");
    std::system("cmd wifi start-restricting-auto-join-to-subscription-id -1");

    ASSERT_TRUE(helper_.Init()) << "NetlinkHelper Init failed";
    bool wonder_enabled = false;
    std::string status;
    // Check for the default wonder device node.
    if (android::base::ReadFileToString(
            "/sys/firmware/devicetree/base/wonder-device/status", &status)) {
      wonder_enabled = (status.find("okay") != std::string::npos);
    } else {
      // If vendors do not use the default path, they must create an alias node
      // "wonder" that points to the actual wonder-device node.
      std::string alias_path;
      if (android::base::ReadFileToString(
              "/sys/firmware/devicetree/base/aliases/wonder", &alias_path)) {
        if (!alias_path.empty()) {
          if (alias_path.back() == '\0') {
            alias_path.pop_back();
          }
          if (android::base::ReadFileToString(
                  "/sys/firmware/devicetree/base" + alias_path + "/status",
                  &status)) {
            wonder_enabled = (status.find("okay") != std::string::npos);
          }
        }
      }
    }

    if (!wonder_enabled) {
      GTEST_SKIP() << "Wonder device not enabled, skipping test";
    }
    // Try to add the interface. If this fails with EPERM, it
    // might be that the process lacks CAP_NET_ADMIN.
    if (!helper_.AddInterface(WONDER_PHY_NAME, WONDER_INTERFACE_NAME,
                              NL80211_IFTYPE_ADHOC)) {
      LOG(WARNING) << "Failed to add interface " << WONDER_INTERFACE_NAME
                   << ". Checking if it already exists...";
      // If it already exists, we can still proceed.
      ASSERT_TRUE(if_nametoindex(WONDER_INTERFACE_NAME) > 0);
    }
  }
  virtual void TearDown() override {
    helper_.RemoveInterface(WONDER_INTERFACE_NAME);
    std::system("cmd wifi stop-restricting-auto-join-to-subscription-id");
    std::system("cmd wifi set-scan-always-available enabled");
  }
  bool SendVendorCmd(WonderVendorSubCmd subCmd, const std::string& hexData) {
    return helper_.SendVendorCommand(WONDER_INTERFACE_NAME, WONDER_VENDOR_ID,
                                     static_cast<uint32_t>(subCmd),
                                     ParseHex(hexData));
  }

 protected:
  NetlinkHelper helper_;

 private:
  std::vector<uint8_t> ParseHex(const std::string& hex) {
    std::vector<uint8_t> data;
    std::stringstream ss(hex);
    std::string s;
    while (ss >> s) {
      uint32_t val;
      if (sscanf(s.c_str(), "0x%x", &val) == 1) {
        data.push_back(static_cast<uint8_t>(val));
      }
    }
    return data;
  }
};

TEST_P(WonderTest, SetChannel) {
  // This command sets the channel to 5745 MHz with a 80 MHz bandwidth.
  const std::string data =
      "0x08 0x00 0x01 0x00 0x71 0x16 0x00 0x00 0x06 0x00 0x02 0x00 0x02 0x00";
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_CHANNEL, data));
}

TEST_P(WonderTest, SetBssidFilter) {
  // This command enables a filter for the BSSID 24:05:88:00:00:01. The filter
  // type 0 corresponds to the BSSID filter.
  const std::string data =
      "0x08 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x18 0x00 0x02 0x00 0x05 0x00"
      " 0x01 0x00 0x01 0x00 0x00 0x00 0x0a 0x00 0x02 0x00 0x24"
      " 0x05 0x88 0x00 0x00 0x01 0x00 0x00";
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_BSSID_FILTER, data));
}

TEST_P(WonderTest, SetTxRate) {
  // This command sets a fixed transmission rate with specific preamble,
  // bandwidth, GI, NSS, and MCS values.
  const std::string data =
      "0x08 0x00 0x01 0x00 0x03 0x00 0x00 0x00 0x06 0x00 0x02 0x00 0x02 0x00"
      " 0x00 0x00 0x08 0x00 0x03 0x00 0x02 0x00 0x00 0x00 0x05"
      " 0x00 0x04 0x00 0x02 0x00 0x00 0x00 0x05 0x00 0x05 0x00"
      " 0x09 0x00 0x00 0x00";
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_TX_RATE, data));
}

TEST_P(WonderTest, SetRegulatoryDomain) {
  // This command sets the regulatory domain to United States (US).
  const std::string data = "0x07 0x00 0x01 0x00 0x55 0x53 0x00 0x0";
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_REGULATORY_DOMAIN, data));
}

TEST_P(WonderTest, GetInterfaceMacAddress) {
  // Bring the interface up
  ASSERT_TRUE(helper_.SetInterfaceUp(WONDER_INTERFACE_NAME, true));
  // This command queries the driver for its MAC address. It requires no
  // payload.
  ASSERT_TRUE(SendVendorCmd(SUBCMD_GET_MAC_ADDRESS, "0x1"));
}

TEST_P(WonderTest, IbssJoin) {
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_CHANNEL,
      "0x08 0x00 0x01 0x00 0x71 0x16 0x00 0x00 0x06 0x00 0x02 0x00 0x02 0x00"));
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_BSSID_FILTER,
      "0x08 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x18 0x00 0x02 0x00 0x05 0x00"
      " 0x01 0x00 0x01 0x00 0x00 0x00 0x0a 0x00 0x02 0x00 0x24 0x05 0x88 0x00"
      " 0x00 0x01 0x00 0x00"));
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_TX_RATE,
      "0x08 0x00 0x01 0x00 0x03 0x00 0x00 0x00 0x06 0x00 0x02 0x00 0x02 0x00"
      " 0x00 0x00 0x08 0x00 0x03 0x00 0x02 0x00 0x00 0x00 0x05 0x00 0x04 0x00"
      " 0x02 0x00 0x00 0x00 0x05 0x00 0x05 0x00 0x09 0x00 0x00 0x00"));
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_REGULATORY_DOMAIN,
                            "0x07 0x00 0x01 0x00 0x55 0x53 0x00 0x0"));
  // Bring the interface up
  ASSERT_TRUE(helper_.SetInterfaceUp(WONDER_INTERFACE_NAME, true));
  // This command queries the driver for its MAC address. It requires no
  // payload.
  ASSERT_TRUE(SendVendorCmd(SUBCMD_GET_MAC_ADDRESS, "0x1"));
  // Trigger scan to establish connection more quickly
  ASSERT_TRUE(helper_.TriggerScan(WONDER_INTERFACE_NAME));
}

TEST_P(WonderTest, SetFixedTxRate) {
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_CHANNEL,
      "0x08 0x00 0x01 0x00 0x71 0x16 0x00 0x00 0x06 0x00 0x02 0x00 0x02 0x00"));
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_BSSID_FILTER,
      "0x08 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x18 0x00 0x02 0x00 0x05 0x00"
      " 0x01 0x00 0x01 0x00 0x00 0x00 0x0a 0x00 0x02 0x00 0x00 0x25 0x00 0xff"
      " 0x94 0x73 0x00 0x00"));
  ASSERT_TRUE(SendVendorCmd(
      SUBCMD_SET_TX_RATE,
      "0x08 0x00 0x01 0x00 0x02 0x00 0x00 0x00 0x06 0x00 0x02 0x00 0x00 0x00"
      " 0x00 0x00 0x08 0x00 0x03 0x00 0x00 0x00 0x00 0x00 0x05 0x00 0x04 0x00"
      " 0x01 0x00 0x00 0x00 0x05 0x00 0x05 0x00 0x07 0x00 0x00 0x00"));
  ASSERT_TRUE(SendVendorCmd(SUBCMD_SET_REGULATORY_DOMAIN,
                            "0x07 0x00 0x01 0x00 0x55 0x53 0x00 0x0"));
  ASSERT_TRUE(helper_.SetInterfaceUp(WONDER_INTERFACE_NAME, true));
}

INSTANTIATE_TEST_SUITE_P(
    PerInstance, WonderTest,
    testing::ValuesIn(android::getAidlHalInstanceNames(IWifi::descriptor)),
    android::PrintInstanceNameToString);

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ABinderProcess_setThreadPoolMaxThreadCount(1);
  ABinderProcess_startThreadPool();
  return RUN_ALL_TESTS();
}
