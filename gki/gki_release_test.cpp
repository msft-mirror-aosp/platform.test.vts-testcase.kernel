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

using android::kver::KernelRelease;

TEST(Gki, KernelReleaseFormat) {
  struct utsname buf;
  auto result = uname(&buf);
  int saved_errno = errno;
  ASSERT_EQ(0, result) << "Cannot call uname: " << strerror(saved_errno);

  std::string release = buf.release;
  ASSERT_TRUE(
      KernelRelease::Parse(release, true /* allow_suffix */).has_value())
      << "Kernel release '" << release
      << "' does not have generic kernel image (GKI) release format. It must "
         "match this regex:\n"
      << R"(^(?P<w>\d+)[.](?P<x>\d+)[.](?P<y>\d+)-(?P<z>android\d+)-(?P<k>\d+).*$)"
      << "\nExample: 5.4.42-android12-0-something";
}
