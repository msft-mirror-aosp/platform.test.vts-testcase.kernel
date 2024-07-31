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
#include <android/api-level.h>
#include <elf.h>
#include <gtest/gtest.h>
#include <libelf64/parse.h>

class Vts16KPageSizeTest : public ::testing::Test {
  protected:
    static int VendorApiLevel() {
        // "ro.vendor.api_level" is added in Android T.
        // Undefined indicates S or below
        return android::base::GetIntProperty("ro.vendor.api_level", __ANDROID_API_S__);
    }

    static int ProductPageSize() {
        return android::base::GetIntProperty("ro.product.page_size", 0);
    }

    static bool NoBionicPageSizeMacroProperty() {
        // "ro.product.build.no_bionic_page_size_macro" was added in Android V and is
        // set to true when Android is build with PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true.
        return android::base::GetBoolProperty("ro.product.build.no_bionic_page_size_macro", false);
    }

    static std::string Architecture() { return android::base::GetProperty("ro.bionic.arch", ""); }

    static ssize_t MaxPageSize(const std::string& filepath) {
        ssize_t maxPageSize = -1;

        android::elf64::Elf64Binary elf;

        if (!android::elf64::Elf64Parser::ParseElfFile(filepath, elf)) {
            return -1;
        }

        for (int i = 0; i < elf.phdrs.size(); i++) {
            Elf64_Phdr phdr = elf.phdrs[i];

            if ((phdr.p_type != PT_LOAD) || !(phdr.p_type & PF_X)) {
                continue;
            }

            maxPageSize = phdr.p_align;
            break;
        }

        return maxPageSize;
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
    size_t RequiredMaxPageSize() {
        if (mArch == "arm64" || mArch == "aarch64" || mArch == "x86_64") {
            return 0x4000;
        } else {
            return 0x1000;
        }
    }

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

    ssize_t expectedMaxPageSize = RequiredMaxPageSize();
    ASSERT_NE(expectedMaxPageSize, -1)
            << "Failed to get required max page size for arch: " << mArch;

    ssize_t initMaxPageSize = MaxPageSize(initPath);
    ASSERT_NE(initMaxPageSize, -1) << "Failed to get max page size of ELF: " << initPath;

    ASSERT_EQ(initMaxPageSize % expectedMaxPageSize, 0)
            << "ELF " << initPath << " with page size " << initMaxPageSize
            << " was not built with the required max-page-size " << expectedMaxPageSize;
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
