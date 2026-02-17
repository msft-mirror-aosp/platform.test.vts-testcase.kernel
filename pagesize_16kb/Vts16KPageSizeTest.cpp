/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <elf.h>
#include <elfutils/elf-file.h>
#include <gtest/gtest.h>
#include <meminfo/sysmeminfo.h>
#include <procinfo/process_map.h>
#include <iomanip>

using ::android::elfutils::ElfFile;

class Vts16KPageSizeTest : public ::testing::Test {
  protected:
    // Android API level that the vendor partition (vendor image) currently conforms to. (previously
    // numbered in same style as Android API level but now it says that if the device's currently
    // installed vendor software is modern enough to meet the YYYYMM requirements)
    static int VendorApiLevel() {
        // "ro.vendor.api_level" is added in Android T.
        // Undefined indicates S or below
        return android::base::GetIntProperty("ro.vendor.api_level", __ANDROID_API_S__);
    }

    static int BoardApiLevel() {
        int api_level = android::base::GetIntProperty("ro.board.api_level", 0);
        if (api_level == 0) {
            // Vendor API level that a specific chipset (SoC) was first signed on GRF.
            // This value is missing for non-GRF devices.
            api_level = android::base::GetIntProperty("ro.board.first_api_level", 202604);
        }
        return api_level;
    }

    static int ProductPageSize() {
        return android::base::GetIntProperty("ro.product.page_size", 0);
    }

    static int BootPageSize() {
        return android::base::GetIntProperty("ro.boot.hardware.cpu.pagesize", 0);
    }

    static bool NoBionicPageSizeMacroProperty() {
        // "ro.product.build.no_bionic_page_size_macro" was added in Android V and is
        // set to true when Android is build with PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true.
        return android::base::GetBoolProperty("ro.product.build.no_bionic_page_size_macro", false);
    }

    static std::string Architecture() { return android::base::GetProperty("ro.bionic.arch", ""); }

    std::optional<int64_t> GetMinLoadSegmentAlignment(const std::string& filepath) {
        std::unique_ptr<ElfFile> elfFile = ElfFile::create(filepath);
        if (!elfFile) return std::nullopt;

        return elfFile->getMinLoadSegmentAlignment();
    }

    static void SetUpTestSuite() {
        if (VendorApiLevel() < 202404 && ProductPageSize() != 16384) {
            GTEST_SKIP() << "16kB support is only required on V and later releases as well as on "
                            "products directly booting with 16kB kernels.";
        }
    }

    /*
     * x86_64 also needs to be at least 16KB aligned, since Android
     * supports page size emulation in x86_64 for app development.
     */
    int64_t RequiredLoadSegmentAlignment() {
        if (mArch == "arm64" || mArch == "aarch64" || mArch == "x86_64") {
            return 0x4000;
        } else {
            return 0x1000;
        }
    }

    // Returns the total memory of the device in bytes.
    static uint64_t GetTotalMemoryBytes() {
        std::string ddr_size_str = android::base::GetProperty("ro.boot.ddr_size", "");
        if (!ddr_size_str.empty()) {
            auto memoryBytes = android::meminfo::ParseSizeToBytes(ddr_size_str);
            if (memoryBytes.has_value()) {
                return *memoryBytes;
            }
        }

        return 0;
    }

    bool IsDeviceArm64() { return mArch == "arm64" || mArch == "aarch64"; }

    const std::string mArch = Architecture();
};

/**
 * Checks the max-page-size of init against the architecture's
 * required max-page-size.
 *
 * Note: a more comprehensive version of this test exists in
 * elf_alignment_test. This has turned out to be a canary test
 * to give visibility on this when checking all 16K tests.
 */
// @VsrTest = 3.14.1
TEST_F(Vts16KPageSizeTest, InitMaxPageSizeTest) {
    constexpr char initPath[] = "/system/bin/init";

    int64_t expectedMinLoadAlign = RequiredLoadSegmentAlignment();
    std::optional<int64_t> initMinLoadAlign = GetMinLoadSegmentAlignment(initPath);
    ASSERT_TRUE(initMinLoadAlign.has_value())
            << "Failed to get minimum PT_LOAD p_align of: " << initPath;

    ASSERT_EQ(*initMinLoadAlign % expectedMinLoadAlign, 0)
            << "ELF " << initPath << " with min PT_LOAD alignment:  " << *initMinLoadAlign
            << " was not built with the required max-page-size " << expectedMinLoadAlign;
}

/**
 * Checks if the vendor's build was compiled with the define
 * PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO based on the product property
 * ro.product.build.no_bionic_page_size_macro.
 */
// @VsrTest = 3.14.2
TEST_F(Vts16KPageSizeTest, NoBionicPageSizeMacro) {
    /**
     * TODO(b/315034809): switch to error when final decision is made.
     */
    if (!NoBionicPageSizeMacroProperty())
        GTEST_SKIP() << "Device was not built with: PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true";
}

/**
 * Checks if the device has page size which was set using TARGET_BOOTS_16K
 */
TEST_F(Vts16KPageSizeTest, ProductPageSize) {
    // We can't set the default value to be 4096 since device which will have 16KB page size and
    // doesn't set TARGET_BOOTS_16K, won't have this property and will fail the test.
    int requiredPageSize = ProductPageSize();
    if (requiredPageSize != 0) {
        int currentPageSize = getpagesize();
        ASSERT_EQ(requiredPageSize, currentPageSize);
    } else {
        GTEST_SKIP() << "Device was not built with option TARGET_BOOTS_16K = true";
    }
}

/**
 * Check boot reported or CPU reported page size that is currently being used.
 */
TEST_F(Vts16KPageSizeTest, BootPageSize) {
    ASSERT_EQ(BootPageSize(), getpagesize());
}

/**
 * Check that the process VMAs are page aligned. This is mostly to ensure
 * x86_64 16KiB page size emulation is working correctly.
 */
TEST_F(Vts16KPageSizeTest, ProcessVmasArePageAligned) {
    ASSERT_TRUE(android::procinfo::ReadProcessMaps(
            getpid(), [&](const android::procinfo::MapInfo& mapinfo) {
                EXPECT_EQ(mapinfo.start % getpagesize(), 0u)
                        << "Start: 0x" << std::hex << mapinfo.start << " of " << mapinfo.name
                        << " is not page-aligned";
                EXPECT_EQ(mapinfo.end % getpagesize(), 0u)
                        << "End: 0x" << std::hex << mapinfo.end << " of " << mapinfo.name
                        << " is not page-aligned";
            }));
}

/**
 * The platform ELFs are built with separate loadable segments.
 * This means that the ELF mappings should be completely covered by
 * the backing file, and should not generate a SIGBUS on reading.
 */
void fault_file_pages(const android::procinfo::MapInfo& mapinfo) {
    std::vector<uint8_t> first_bytes;

    for (size_t i = mapinfo.start; i < mapinfo.end; i += getpagesize()) {
        first_bytes.push_back(*(reinterpret_cast<uint8_t*>(i)));
    }

    if (first_bytes.size() > 0) exit(0);

    exit(1);
}

/**
 * Ensure that apps don't crash with SIGBUS when attempting to read
 * file mapped platform ELFs.
 */
TEST_F(Vts16KPageSizeTest, CanReadProcessFileMappedContents) {
    // random accesses may trigger MTE on hwasan builds
    SKIP_WITH_HWASAN;

    std::vector<android::procinfo::MapInfo> maps;

    ASSERT_TRUE(android::procinfo::ReadProcessMaps(
            getpid(), [&](const android::procinfo::MapInfo& mapinfo) {
                if ((mapinfo.flags & PROT_READ) == 0) return;

                // Don't check anonymous mapping.
                if (!android::base::StartsWith(mapinfo.name, "/")) return;

                // Skip devices
                if (android::base::StartsWith(mapinfo.name, "/dev/")) return;

                maps.push_back(mapinfo);
            }));

    for (const auto& map : maps) {
        ASSERT_EXIT(fault_file_pages(map), ::testing::ExitedWithCode(0), "")
                << "Failed to read maps: " << map.name;
    }
}

static inline void setUnsetBackcompat() {
    const std::string prop = "bionic.linker.16kb.app_compat.enabled";

    // save and set the default
    const std::string defaultValue = android::base::GetProperty(prop, "false");

    // set and verify property.
    ASSERT_TRUE(android::base::SetProperty(prop, "true"));
    ASSERT_EQ(android::base::GetProperty(prop, "false"), "true");

    ASSERT_TRUE(android::base::SetProperty(prop, "fatal"));
    ASSERT_EQ(android::base::GetProperty(prop, "false"), "fatal");

    // reset
    ASSERT_TRUE(android::base::SetProperty(prop, defaultValue));
}

TEST_F(Vts16KPageSizeTest, BackCompatSupport) {
    // Backcompat support is added in Android B
    int apiLevel = VendorApiLevel();
    if (apiLevel < 36 /* Android B */) {
        GTEST_SKIP() << "16 KB backcompat support is only required on Android B and later release";
    }

    setUnsetBackcompat();
}

static inline void setUnsetPackageManagerCompat() {
    const std::string prop = "pm.16kb.app_compat.disabled";

    // save and set the default
    bool defaultValue = android::base::GetBoolProperty(prop, false);
    // set and verify property.
    ASSERT_TRUE(android::base::SetProperty(prop, "true"));
    ASSERT_TRUE(android::base::GetBoolProperty(prop, false));

    // reset
    ASSERT_TRUE(android::base::SetProperty(prop, std::to_string(defaultValue)));
}

TEST_F(Vts16KPageSizeTest, PackageManagerDisableBackCompat) {
    // Package manager support for backcompat is added in Android B
    int apiLevel = VendorApiLevel();
    if (apiLevel < 36 /* Android B */) {
        GTEST_SKIP() << "16 KB backcompat support in package manager is only required on Android B "
                        "and later release";
    }

    setUnsetPackageManagerCompat();
}

/**
 * Checks if the device which has set ro.board.first_api_level or ro.board.api_level to 202604
 * implements the 16 KB dev option by checking if the property ro.product.build.16k_page.enabled
 * is true
 */
TEST_F(Vts16KPageSizeTest, DeviceOption16KBEnabled) {
    if (android::base::GetBoolProperty("ro.hardware.16kb_cpu_unsupported", false)) {
        GTEST_SKIP() << "16 KB developer option not required if CPU is unsupported.";
    }

    if (android::base::GetBoolProperty("ro.hardware.16kb_hardware_unsupported", false)) {
        GTEST_SKIP() << "16 KB developer option not required if hardware is unsupported.";
    }

    int productPageSize = ProductPageSize();
    if (productPageSize == 16384) {
        GTEST_SKIP() << "Developer option for 16 KB page size is required for devices booting with "
                        "4 KB page size!";
    }

    if (!IsDeviceArm64()) {
        GTEST_SKIP()
                << "Developer option for 16 KB page size is required for devices running on arm64!";
    }

    // Also note the VendorApiLevel() in test setup which requires this entire test suite to run
    // on ro.vendor.api_level >= 202404.
    int board_api_level = BoardApiLevel();
    if (board_api_level < 202604) {
        GTEST_SKIP() << "Developer option for 16 KB page size is not required for board api level "
                     << board_api_level;
    }

    uint64_t totalMemoryBytes = GetTotalMemoryBytes();
    ASSERT_TRUE(totalMemoryBytes != 0);
    uint64_t eight_gb_bytes = 8ULL * 1000 * 1000 * 1000;
    if (totalMemoryBytes < eight_gb_bytes) {
        GTEST_SKIP() << "Device has less than 8GB of RAM, skipping test.";
    }

    ASSERT_TRUE(android::base::GetBoolProperty("ro.product.build.16k_page.enabled", false));
}
