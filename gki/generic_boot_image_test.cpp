/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <filesystem>
#include <optional>

#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <kver/kernel_release.h>
#include <vintf/VintfObject.h>
#include <vintf/parse_string.h>

#include "ramdisk_utils.h"

using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::kver::KernelRelease;
using android::vintf::RuntimeInfo;
using android::vintf::Version;
using android::vintf::VintfObject;
using testing::IsSupersetOf;

// Returns true iff the device has the specified feature.
static bool deviceSupportsFeature(const char *feature) {
  bool device_supports_feature = false;
  FILE *p = popen("pm list features", "re");
  if (p) {
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, p) > 0) {
      if (strstr(line, feature)) {
        device_supports_feature = true;
        break;
      }
    }
    if (line) {
      free(line);
      line = NULL;
    }
    pclose(p);
  }
  return device_supports_feature;
}

static bool isTV() {
  return deviceSupportsFeature("android.software.leanback");
}

std::optional<std::string> get_config(
    const std::map<std::string, std::string>& configs, const std::string& key) {
  auto it = configs.find(key);
  if (it == configs.end()) {
    return std::nullopt;
  }
  return it->second;
}

class GenericBootImageTest : public testing::Test {
 public:
  void SetUp() override {
    auto vintf = VintfObject::GetInstance();
    ASSERT_NE(nullptr, vintf);
    runtime_info = vintf->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION |
                                         RuntimeInfo::FetchFlag::CONFIG_GZ);
    ASSERT_NE(nullptr, runtime_info);

    const auto& configs = runtime_info->kernelConfigs();
    if (get_config(configs, "CONFIG_ARM") == "y") {
      GTEST_SKIP() << "Skipping on 32-bit ARM devices";
    }
    // Technically, the test should also be skipped on CONFIG_X86 and
    // CONFIG_X86_64, and only run on CONFIG_ARM64,
    // but we want to keep this test passing on virtual
    // device targets, and we don't have any requests to skip this test
    // on x86 / x86_64 as of 2022-06-07.

    int firstApiLevel = std::stoi(android::base::GetProperty("ro.product.first_api_level", "0"));
    if (isTV() && firstApiLevel <= __ANDROID_API_S__) {
      GTEST_SKIP() << "Skipping on TV devices";
    }
  }
  std::shared_ptr<const RuntimeInfo> runtime_info;
};

TEST_F(GenericBootImageTest, KernelReleaseFormat) {
  // On "GKI 2.0" with 5.10+ kernels, VTS runs once with the device kernel,
  // so this test is meaningful.
  if (runtime_info->kernelVersion().dropMinor() < Version{5, 10}) {
    GTEST_SKIP() << "Exempt generic kernel image (GKI) test on kernel "
                 << runtime_info->kernelVersion()
                 << ". Only required on 5.10+.";
  }

  const std::string& release = runtime_info->osRelease();
  ASSERT_TRUE(
      KernelRelease::Parse(release, true /* allow_suffix */).has_value())
      << "Kernel release '" << release
      << "' does not have generic kernel image (GKI) release format. It must "
         "match this regex:\n"
      << R"(^(?P<w>\d+)[.](?P<x>\d+)[.](?P<y>\d+)-(?P<z>android\d+)-(?P<k>\d+).*$)"
      << "\nExample: 5.4.42-android12-0-something";
}

TEST_F(GenericBootImageTest, GenericRamdisk) {
  // On "GKI 2.0" with 5.10+ kernels, VTS runs once with the device kernel,
  // so this test is meaningful.
  if (runtime_info->kernelVersion().dropMinor() < Version{5, 10}) {
    GTEST_SKIP() << "Exempt generic ramdisk test on kernel "
                 << runtime_info->kernelVersion()
                 << ". Only required on 5.10+.";
  }

  using std::filesystem::recursive_directory_iterator;

  std::string slot_suffix = GetProperty("ro.boot.slot_suffix", "");
  std::string boot_path = "/dev/block/by-name/boot" + slot_suffix;
  if (0 != access(boot_path.c_str(), F_OK)) {
    int saved_errno = errno;
    FAIL() << "Can't access " << boot_path << ": " << strerror(saved_errno);
  }

  auto extracted_ramdisk = android::ExtractRamdiskToDirectory(boot_path);
  ASSERT_RESULT_OK(extracted_ramdisk);

  std::set<std::string> actual_files;
  std::filesystem::path extracted_ramdisk_path((*extracted_ramdisk)->path);
  for (auto& p : recursive_directory_iterator(extracted_ramdisk_path)) {
    if (p.is_directory()) continue;
    EXPECT_TRUE(p.is_regular_file())
        << "Unexpected non-regular file " << p.path();
    auto rel_path = p.path().lexically_relative(extracted_ramdisk_path);
    actual_files.insert(rel_path.string());
  }

  std::set<std::string> generic_ramdisk_allowlist{
      "init",
      "system/etc/ramdisk/build.prop",
  };
  if (GetBoolProperty("ro.debuggable", false)) {
    EXPECT_THAT(actual_files, IsSupersetOf(generic_ramdisk_allowlist))
        << "Missing files required by non-debuggable generic ramdisk.";
    std::set<std::string> debuggable_allowlist{
        "adb_debug.prop",
        "force_debuggable",
        "userdebug_plat_sepolicy.cil",
    };
    generic_ramdisk_allowlist.insert(debuggable_allowlist.begin(),
                                     debuggable_allowlist.end());
    EXPECT_THAT(generic_ramdisk_allowlist, IsSupersetOf(actual_files))
        << "Contains files disallowed by debuggable generic ramdisk";
  } else {
    EXPECT_EQ(actual_files, generic_ramdisk_allowlist);
  }
}
