/*
 * Copyright (C) 2024 The Android Open Source Project
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
 *
 */
#include <android-base/logging.h>
#include <gtest/gtest.h>

#include <libdm/loop_control.h>
#include <logwrap/logwrap.h>

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <linux/f2fs.h>
#include <linux/fs.h>

#include <chrono>
#include <fstream>

using LoopDevice = android::dm::LoopDevice;
using namespace std::chrono_literals;

static const char* kMkfsPath = "/system/bin/make_f2fs";
static const char* kMountPath = "/system/bin/mount";
static const char* kUmountPath = "/system/bin/umount";

static const char* kTestFilePath = "/data/local/tmp/mnt/test";

namespace android {

class F2fsTest : public testing::Test {
  void SetUp() override {
    int fd = open("/data/local/tmp/img", O_RDWR | O_TRUNC | O_CREAT,
                  (S_IRWXU | S_IRGRP | S_IROTH));
    int flags = FS_COMPR_FL;
    int res;

    page_size = getpagesize();
    std::string block_size = std::to_string(page_size);
    ASSERT_NE(fd, -1);
    res = ftruncate(fd, 100 << 20);  // 100 MB
    ASSERT_EQ(res, 0);
    close(fd);

    std::vector<const char*> make_fs_argv = {
        kMkfsPath, "-f",          "-O", "extra_attr", "-O", "project_quota",
        "-O",      "compression", "-O", "casefold",   "-C", "utf8",
        "-g",      "android",
    };
    make_fs_argv.push_back("-w");
    make_fs_argv.push_back(block_size.c_str());
    make_fs_argv.push_back("-b");
    make_fs_argv.push_back(block_size.c_str());
    make_fs_argv.push_back("/data/local/tmp/img");

    res = logwrap_fork_execvp(make_fs_argv.size(), make_fs_argv.data(), nullptr,
                              false, LOG_KLOG, true, nullptr);
    ASSERT_EQ(res, 0);
    mkdir("/data/local/tmp/mnt", (S_IRWXU | S_IRGRP | S_IROTH));

    LoopDevice loop_dev("/data/local/tmp/img", 10s);
    ASSERT_TRUE(loop_dev.valid());

    ASSERT_EQ(mount(loop_dev.device().c_str(), "data/local/tmp/mnt", "f2fs", 0,
                    "compress_mode=user"),
              0);
    test_data1 = malloc(page_size);
    ASSERT_NE(test_data1, nullptr);
    memset(test_data1, 0x41, page_size);
    test_data2 = malloc(page_size);
    ASSERT_NE(test_data2, nullptr);
    memset(test_data2, 0x61, page_size);
  }
  void TearDown() override {
    ASSERT_EQ(umount2("/data/local/tmp/mnt", MNT_DETACH), 0);
    ASSERT_EQ(unlink("/data/local/tmp/img"), 0);
    ASSERT_EQ(rmdir("/data/local/tmp/mnt"), 0);
    free(test_data1);
    free(test_data2);
  }

 protected:
  void* test_data1;
  void* test_data2;
  int page_size;
};

TEST_F(F2fsTest, test_normal_lseek) {
  char buf[page_size];
  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
                (S_IRWXU | S_IRGRP | S_IROTH));
  ASSERT_NE(fd, -1);

  ASSERT_EQ(lseek(fd, 1024 * page_size, SEEK_SET), 1024 * page_size);
  for (int i = 0; i < 1024; i++) {
    ASSERT_EQ(write(fd, test_data1, page_size), page_size);
  }
  fsync(fd);
  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * page_size);
  lseek(fd, 0, SEEK_SET);
  write(fd, test_data2, page_size);
  fsync(fd);
  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);

  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), page_size);
  ASSERT_EQ(lseek(fd, page_size + 904, SEEK_DATA), 1024 * page_size);
}

TEST_F(F2fsTest, test_compressed_lseek) {
  char buf[page_size];

  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
                (S_IRWXU | S_IRGRP | S_IROTH));
  ASSERT_NE(fd, -1);

  int flags = FS_COMPR_FL;
  ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
  ASSERT_EQ(lseek(fd, 1024 * page_size, SEEK_SET), 1024 * page_size);
  for (int i = 0; i < 1024; i++) {
    ASSERT_EQ(write(fd, test_data1, page_size), page_size);
  }
  fsync(fd);
  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * page_size);
  ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
  lseek(fd, 0, SEEK_SET);
  write(fd, test_data2, page_size);
  fsync(fd);
  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);
  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), page_size);
  ASSERT_EQ(lseek(fd, page_size + 904, SEEK_DATA), 1024 * page_size);
}

TEST_F(F2fsTest, test_sparse_decompress) {
  char buf[page_size];
  int res;

  int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
                (S_IRWXU | S_IRGRP | S_IROTH));
  ASSERT_NE(fd, -1);
  int flags = FS_COMPR_FL;

  ASSERT_NE(fd, -1);

  ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
  res = lseek(fd, 1024 * page_size, SEEK_SET);
  ASSERT_EQ(res, 1024 * page_size);
  for (int i = 0; i < 1024; i++) {
    res = write(fd, test_data1, page_size);
    ASSERT_EQ(res, page_size);
  }
  fsync(fd);
  ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
  lseek(fd, 0, SEEK_SET);
  write(fd, test_data2, page_size);
  fsync(fd);
  int pid = fork();
  if (pid == 0) {
    // If this fails, we must reset the device or it will be left in a bad state
    exit(ioctl(fd, F2FS_IOC_DECOMPRESS_FILE));
  }
  int status;
  int time = 0;
  while (time < 50) {
    res = waitpid(pid, &status, WNOHANG);
    if (res) {
      ASSERT_EQ(pid, res);
      ASSERT_EQ(WIFEXITED(status), true);
      ASSERT_EQ(WEXITSTATUS(status), 0);
      break;
    }
    sleep(5);
    time += 5;
  }
  if (!res) {
    std::ofstream reboot_trigger("/proc/sysrq-trigger");
    reboot_trigger << "c";
    reboot_trigger.close();
    return;
  }
  close(fd);
  // Check for corruption
  fd = open(kTestFilePath, O_RDONLY);
  ASSERT_NE(fd, -1);
  res = read(fd, buf, page_size);
  ASSERT_EQ(res, page_size);
  ASSERT_EQ(memcmp(buf, test_data2, page_size), 0);

  char empty_buf[page_size];
  memset(empty_buf, 0, page_size);
  for (int i = 1; i < 1024; i++) {
    res = read(fd, buf, page_size);
    ASSERT_EQ(res, page_size);
    ASSERT_EQ(memcmp(buf, empty_buf, page_size), 0);
  }
  for (int i = 0; i < 1024; i++) {
    res = read(fd, buf, page_size);
    ASSERT_EQ(res, page_size);
    ASSERT_EQ(memcmp(buf, test_data1, page_size), 0);
  }
  close(fd);
}

TEST_F(F2fsTest, test_casefolding_ignorable_codepoint) {
  const char* kTestFolder = "/data/local/tmp/mnt/cf/";
  const char* kTestFileCase1Path = "/data/local/tmp/mnt/cf/❤";  // u2764
  const char* kTestFileCase2Path = "/data/local/tmp/mnt/cf/❤️";  // u2764 + ufe0f
  struct stat stat1;
  struct stat stat2;

  ASSERT_EQ(mkdir(kTestFolder, (S_IRWXU | S_IRGRP | S_IROTH)), 0);
  int fd = open(kTestFolder, O_RDONLY | O_DIRECTORY);
  ASSERT_NE(fd, -1);
  int flag = FS_CASEFOLD_FL;
  ASSERT_EQ(ioctl(fd, FS_IOC_SETFLAGS, &flag), 0);
  close(fd);

  fd = open(kTestFileCase1Path, O_RDWR | O_TRUNC | O_CREAT,
            (S_IRWXU | S_IRGRP | S_IROTH));
  ASSERT_NE(fd, -1);
  ASSERT_NE(fstat(fd, &stat1), -1);
  close(fd);

  fd = open(kTestFileCase2Path, O_RDWR | O_TRUNC | O_CREAT,
            (S_IRWXU | S_IRGRP | S_IROTH));
  ASSERT_NE(fd, -1);
  ASSERT_NE(fstat(fd, &stat2), -1);
  close(fd);

  ASSERT_EQ(stat1.st_ino, stat2.st_ino);
}

}  // namespace android
