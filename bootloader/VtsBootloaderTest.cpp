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

#include <android-base/properties.h>
#include <android-base/test_utils.h>
#include <android/api-level.h>
#include <gtest/gtest.h>
#include <meminfo/sysmeminfo.h>

class VtsBootloaderTest : public ::testing::Test {
 protected:
  static int BoardApiLevel() {
    int api_level = android::base::GetIntProperty("ro.board.api_level", 0);
    if (api_level == 0) {
      // Vendor API level that a specific chipset (SoC) was first signed on GRF.
      // This value is missing for non-GRF devices.
      api_level =
          android::base::GetIntProperty("ro.board.first_api_level", 202604);
    }
    return api_level;
  }

  // Returns the total memory of the device in bytes.
  static uint64_t GetTotalMemoryBytes() {
    std::string ddr_size_str =
        android::base::GetProperty("ro.boot.ddr_size", "");
    if (!ddr_size_str.empty()) {
      auto memoryBytes = android::meminfo::ParseSizeToBytes(ddr_size_str);
      if (memoryBytes.has_value()) {
        return *memoryBytes;
      }
    }

    return 0;
  }
};

/**
 * Checks that the property ro.boot.ddr_size has been set and it has a value
 * greater than zero. This check only applies to devices which have set:
 *
 *  - ro.board.first_api_level or ro.board.api_level to 202604
 */
TEST_F(VtsBootloaderTest, BootloaderSetDdrSizeProperty) {
  int board_api_level = BoardApiLevel();
  if (board_api_level < 202604) {
    GTEST_SKIP() << "The androidboot.ddr_size (ro.boot.ddr_size) "
                 << "property is not required for board API level "
                 << board_api_level;
  }

  uint64_t totalMemoryBytes = GetTotalMemoryBytes();
  ASSERT_TRUE(totalMemoryBytes > 0);
}
