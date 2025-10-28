/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <vintf/VintfObject.h>

using android::vintf::KernelVersion;
using android::vintf::RuntimeInfo;
using android::vintf::VintfObject;

/*
 * Tests that the device supports the memfd_class sepolicy capability if the vendor API level
 * is greater than or equal to 202604.
 */
TEST(KernelMemfdClassSELinuxTest, KernelSupportsMemfdClass) {
  KernelVersion kernel_version = VintfObject::GetInstance()
                                         ->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION)
                                         ->kernelVersion();
  /* memfd_class support is available on kernel version 6.12+. */
  if (kernel_version < KernelVersion(6, 12, 0)) {
    GTEST_SKIP() << "Exempt from memfd_class selinux support test: kernel version must be at least"
                 << " 6.12.";
  }
  /*
   * ro.vendor.api_level is the VSR API level, which is calculated
   * as:
   *
   * vendor.api_level = min(ro.product.first_api_level, ro.board.[first_]api_level)
   *
   * If ro.board.api_level is defined, it is used for the comparison instead
   * of ro.board.first_api_level.
   */
  const int vendor_api_level = android::base::GetIntProperty("ro.vendor.api_level", -1);

  /*
   * Ensure that we run this test for devices launching with Android 17+, but not
   * devices that are upgrading to Android 17+.
   */
  const int min_vendor_api_level = 202604;
  if (vendor_api_level < min_vendor_api_level) {
    GTEST_SKIP() << "Exempt from memfd_class selinux support test: ro.vendor.api_level ("
                 << vendor_api_level << ") < " << min_vendor_api_level;
  }

  std::string supported;
  ASSERT_TRUE(android::base::ReadFileToString("/sys/fs/selinux/policy_capabilities/memfd_class",
                                              &supported));
  ASSERT_EQ(android::base::Trim(supported), "1") << "VSR-3.5.2-004: Devices with vendor API level "
                                                 << "202604+ must support the memfd_class sepolicy "
                                                 << "capability.";
}
