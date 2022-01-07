/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <fcntl.h>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <storage_literals/storage_literals.h>
using android::storage_literals::operator""_MiB;

class SystemDlkmPartitionTest : public testing::Test {
 public:
  void SetUp() override {}
};

TEST_F(SystemDlkmPartitionTest, SystemDlkmPartition) {
  // Only Test for the Android T+ feature launch devices
  if (android::base::GetIntProperty("ro.product.first_api_level", 0) <
      __ANDROID_API_T__) {
    GTEST_SKIP() << "Exempt system_dlkm partition test on product "
                 << "first api level < Android T";
  }

  const std::string slot_suffix =
      android::base::GetProperty("ro.boot.slot_suffix", "");
  const std::string system_dlkm_path =
      "/dev/block/by-name/system_dlkm" + slot_suffix;

  // Verify access to the partition
  ASSERT_EQ(0, access(system_dlkm_path.c_str(), F_OK)) << strerror(errno);

  // Open & retrieve partition stats
  auto fd = android::base::unique_fd(open(system_dlkm_path.c_str(), O_RDONLY));
  ASSERT_LE(0, fd) << strerror(errno);

  struct stat s;
  ASSERT_EQ(0, fstat(fd, &s)) << strerror(errno);

  // Validate partition size as per requirement
  uint64_t size;
  ASSERT_TRUE(S_ISBLK(s.st_mode)) << "Not a block device: " << system_dlkm_path;
  ASSERT_EQ(0, ioctl(fd, BLKGETSIZE64, &size)) << strerror(errno);
  EXPECT_GE(size, 64_MiB) << "Size of system_dlkm partition found to be "
                          << size << " bytes must be at least " << 64_MiB
                          << " bytes";
}
