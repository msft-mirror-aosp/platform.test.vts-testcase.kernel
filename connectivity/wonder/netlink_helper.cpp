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

#include "netlink_helper.h"

#include <android-base/logging.h>
#include <fcntl.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace {
int error_handler(struct sockaddr_nl* /*nla*/, struct nlmsgerr* err,
                  void* arg) {
  int* ret = static_cast<int*>(arg);
  *ret = err->error;
  return NL_STOP;
}

int finish_handler(struct nl_msg* /*msg*/, void* arg) {
  int* ret = static_cast<int*>(arg);
  *ret = 0;
  return NL_SKIP;
}

int ack_handler(struct nl_msg* /*msg*/, void* arg) {
  int* ret = static_cast<int*>(arg);
  *ret = 0;
  return NL_STOP;
}
}  // namespace

NetlinkHelper::NetlinkHelper() : sock_(nullptr), nl80211_id_(-1) {}

NetlinkHelper::~NetlinkHelper() {
  if (sock_) {
    nl_socket_free(sock_);
    sock_ = nullptr;
  }
}

bool NetlinkHelper::Init() {
  if (sock_) {
    nl_socket_free(sock_);
    sock_ = nullptr;
  }
  sock_ = nl_socket_alloc();
  if (!sock_) {
    LOG(ERROR) << "Failed to allocate netlink socket";
    return false;
  }
  // Set CLOEXEC on the socket to prevent leaking to child processes
  int fd = nl_socket_get_fd(sock_);
  if (fd >= 0) {
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) {
      fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
  }

  if (genl_connect(sock_) < 0) {
    LOG(ERROR) << "Failed to connect to generic netlink";
    nl_socket_free(sock_);
    sock_ = nullptr;
    return false;
  }
  nl80211_id_ = genl_ctrl_resolve(sock_, "nl80211");
  if (nl80211_id_ < 0) {
    LOG(ERROR) << "Failed to resolve nl80211 family id";
    nl_socket_free(sock_);
    sock_ = nullptr;
    return false;
  }
  return true;
}

int NetlinkHelper::GetIfIndex(const std::string& ifName) {
  return if_nametoindex(ifName.c_str());
}

int NetlinkHelper::GetPhyIndex(const std::string& phyName) {
  char buf[200];
  snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", phyName.c_str());
  FILE* fp = fopen(buf, "r");
  if (!fp) {
    LOG(INFO) << "Failed to open " << buf;
    return -1;
  }
  int index = -1;
  char line[32];
  if (fgets(line, sizeof(line), fp)) {
    if (sscanf(line, "%d", &index) != 1) {
      LOG(INFO) << "Failed to read phy index from " << buf;
      index = -1;
    }
  }
  fclose(fp);
  return index;
}

int NetlinkHelper::WaitForAck() {
  int ret = 1;
  struct nl_cb* cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    LOG(ERROR) << "Failed to allocate netlink callbacks";
    return -ENOMEM;
  }
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);

  while (ret > 0) {
    int err = nl_recvmsgs(sock_, cb);
    if (err < 0) {
      if (err == -NLE_PERM) {
        LOG(ERROR) << "nl_recvmsgs failed: Operation not permitted (NLE_PERM). "
                   << "Check CAP_NET_ADMIN capabilities.";
      } else {
        LOG(ERROR) << "nl_recvmsgs failed: " << nl_geterror(err) << " (" << err
                   << ")";
      }
      ret = err;
      break;
    }
  }
  nl_cb_put(cb);
  return ret;
}

bool NetlinkHelper::AddInterface(const std::string& phyName,
                                 const std::string& ifName, uint32_t type) {
  int phyIdx = GetPhyIndex(phyName);
  if (phyIdx < 0) {
    LOG(ERROR) << "Could not find phy index for " << phyName;
    return false;
  }

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) {
    LOG(ERROR) << "Failed to allocate nl_msg";
    return false;
  }

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id_, 0,
              NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_NEW_INTERFACE, 0);
  nla_put_u32(msg, NL80211_ATTR_WIPHY, phyIdx);
  nla_put_string(msg, NL80211_ATTR_IFNAME, ifName.c_str());
  nla_put_u32(msg, NL80211_ATTR_IFTYPE, type);

  int err = nl_send_auto_complete(sock_, msg);
  nlmsg_free(msg);
  if (err < 0) {
    LOG(ERROR) << "nl_send_auto_complete failed: " << nl_geterror(err);
    return false;
  }

  int ret = WaitForAck();
  if (ret < 0 && ret != -EEXIST) {
    LOG(ERROR) << "Failed to add interface: " << strerror(-ret) << " (" << ret
               << ")";
    return false;
  } else if (ret == -EEXIST) {
    LOG(INFO) << "Interface " << ifName << " already exists";
  } else {
    LOG(INFO) << "Successfully added interface via Netlink: " << ifName;
  }

  return true;
}

bool NetlinkHelper::RemoveInterface(const std::string& ifName) {
  int ifIdx = GetIfIndex(ifName);
  if (ifIdx <= 0) {
    // Already removed
    return true;
  }

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) {
    LOG(ERROR) << "Failed to allocate nl_msg";
    return false;
  }

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id_, 0,
              NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_DEL_INTERFACE, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifIdx);

  int err = nl_send_auto_complete(sock_, msg);
  nlmsg_free(msg);
  if (err < 0) {
    LOG(ERROR) << "nl_send_auto_complete failed: " << nl_geterror(err);
    return false;
  }

  int ret = WaitForAck();
  if (ret < 0 && ret != -ENODEV) {
    LOG(ERROR) << "Failed to remove interface: " << strerror(-ret) << " ("
               << ret << ")";
    return false;
  } else if (ret == -ENODEV) {
    LOG(INFO) << "Interface " << ifName << " not found";
  } else {
    LOG(INFO) << "Successfully removed interface via Netlink: " << ifName;
  }

  return true;
}

bool NetlinkHelper::SetInterfaceUp(const std::string& ifName, bool up) {
  struct ifreq ifr = {};
  // Use SOCK_CLOEXEC to prevent leaking to child processes
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    LOG(ERROR) << "Failed to create socket for ioctl";
    return false;
  }
  strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    LOG(ERROR) << "SIOCGIFFLAGS failed for " << ifName;
    close(fd);
    return false;
  }
  if (up) {
    ifr.ifr_flags |= IFF_UP;
  } else {
    ifr.ifr_flags &= ~IFF_UP;
  }
  bool success = (ioctl(fd, SIOCSIFFLAGS, &ifr) >= 0);
  if (!success) {
    LOG(ERROR) << "SIOCSIFFLAGS failed for " << ifName;
  }
  close(fd);
  return success;
}

bool NetlinkHelper::SendVendorCommand(const std::string& ifName,
                                      uint32_t vendorId, uint32_t subCmd,
                                      const std::vector<uint8_t>& data) {
  int ifIdx = GetIfIndex(ifName);
  if (ifIdx <= 0) {
    LOG(ERROR) << "Could not find interface index for " << ifName;
    return false;
  }

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) {
    LOG(ERROR) << "Failed to allocate nl_msg";
    return false;
  }

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id_, 0,
              NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_VENDOR, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifIdx);
  nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendorId);
  nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subCmd);

  // Always put the attribute, even if data is empty, some drivers might expect
  // it
  nla_put(msg, NL80211_ATTR_VENDOR_DATA, data.size(), data.data());

  int err = nl_send_auto_complete(sock_, msg);
  nlmsg_free(msg);
  if (err < 0) {
    LOG(ERROR) << "nl_send_auto_complete failed: " << nl_geterror(err);
    return false;
  }

  int ret = WaitForAck();
  if (ret < 0) {
    LOG(ERROR) << "SendVendorCommand failed: " << strerror(-ret) << " (" << ret
               << ")";
  }
  return ret >= 0;
}

bool NetlinkHelper::TriggerScan(const std::string& ifName) {
  int ifIdx = GetIfIndex(ifName);
  if (ifIdx <= 0) {
    LOG(ERROR) << "Could not find interface index for " << ifName;
    return false;
  }

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) {
    LOG(ERROR) << "Failed to allocate nl_msg";
    return false;
  }

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id_, 0,
              NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_TRIGGER_SCAN, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifIdx);

  // ssids is a nested attribute
  struct nlattr* ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
  nla_put(msg, 1, 0, NULL);
  nla_nest_end(msg, ssids);

  int err = nl_send_auto_complete(sock_, msg);
  nlmsg_free(msg);
  if (err < 0) {
    LOG(ERROR) << "nl_send_auto_complete failed: " << nl_geterror(err);
    return false;
  }

  int ret = WaitForAck();
  if (ret < 0) {
    LOG(ERROR) << "TriggerScan failed: " << strerror(-ret) << " (" << ret
               << ")";
  }
  return ret >= 0;
}
