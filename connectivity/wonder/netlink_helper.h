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

#pragma once

#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <string>
#include <vector>

class NetlinkHelper {
 public:
  NetlinkHelper();
  ~NetlinkHelper();
  bool Init();
  bool AddInterface(const std::string& phyName, const std::string& ifName,
                    uint32_t type);
  bool RemoveInterface(const std::string& ifName);
  bool SetInterfaceUp(const std::string& ifName, bool up);
  bool SendVendorCommand(const std::string& ifName, uint32_t vendorId,
                         uint32_t subCmd, const std::vector<uint8_t>& data);
  bool TriggerScan(const std::string& ifName);
  int GetPhyIndex(const std::string& phyName);

 private:
  struct nl_sock* sock_;
  int nl80211_id_;
  int GetIfIndex(const std::string& ifName);
  int WaitForAck();
};
