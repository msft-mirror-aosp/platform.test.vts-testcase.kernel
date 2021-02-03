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

#include <sys/utsname.h>

#include <gtest/gtest.h>
#include <kver/kernel_release.h>
#include <vintf/VintfObject.h>
#include <vintf/parse_string.h>

using android::kver::KernelRelease;
using android::vintf::RuntimeInfo;
using android::vintf::Version;
using android::vintf::VintfObject;

TEST(Gki, KernelReleaseFormat) {
  auto vintf = VintfObject::GetInstance();
  ASSERT_NE(nullptr, vintf);
  auto ri = vintf->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION);
  ASSERT_NE(nullptr, ri);

  // GKI release format is only enabled on 5.4+ branches
  if (ri->kernelVersion().dropMinor() < Version{5, 4}) {
    GTEST_SKIP() << "Exempt GKI release format check on kernel "
                 << ri->kernelVersion() << " (before 5.4.y)";
  }

  const std::string& release = ri->osRelease();
  ASSERT_TRUE(
      KernelRelease::Parse(release, true /* allow_suffix */).has_value())
      << "Kernel release '" << release
      << "' does not have generic kernel image (GKI) release format. It must "
         "match this regex:\n"
      << R"(^(?P<w>\d+)[.](?P<x>\d+)[.](?P<y>\d+)-(?P<z>android\d+)-(?P<k>\d+).*$)"
      << "\nExample: 5.4.42-android12-0-something";
}
