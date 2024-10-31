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
 */

#include <chrono>
#include <cstdint>
#include <format>
#include <limits>
#include <regex>
#include <sstream>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <gtest/gtest.h>
#include <kver/kernel_release.h>
#include <tinyxml2.h>
#include <vintf/Version.h>
#include <vintf/VintfObject.h>

using android::vintf::KernelVersion;
using android::vintf::RuntimeInfo;
using android::vintf::Version;
using android::vintf::VintfObject;

namespace {

const std::string kernel_lifetimes_config_path =
    "/system/etc/kernel/kernel-lifetimes.xml";

bool parseDate(std::string_view date_string,
               std::chrono::year_month_day& date) {
  const std::regex date_regex("(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)");
  std::cmatch date_match;
  if (!std::regex_match(date_string.data(), date_match, date_regex)) {
    return false;
  }

  uint32_t year, month, day;
  android::base::ParseUint(date_match[1].str(), &year);
  android::base::ParseUint(date_match[2].str(), &month);
  android::base::ParseUint(date_match[3].str(), &day);
  date = std::chrono::year_month_day(std::chrono::year(year),
                                     std::chrono::month(month),
                                     std::chrono::day(day));
  return true;
}

KernelVersion parseKernelVersion(std::string_view kernel_version_string) {
  const std::regex kernel_version_regex("(\\d+)\\.(\\d+)\\.(\\d+)");
  std::cmatch kernel_version_match;
  if (!std::regex_match(kernel_version_string.data(), kernel_version_match,
                        kernel_version_regex)) {
    return {};
  }

  uint32_t v, mj, mi;
  android::base::ParseUint(kernel_version_match[1].str(), &v);
  android::base::ParseUint(kernel_version_match[2].str(), &mj);
  android::base::ParseUint(kernel_version_match[3].str(), &mi);
  return KernelVersion(v, mj, mi);
}

}  // namespace

class EolEnforcementTest : public testing::Test {
 public:
  virtual void SetUp() override {
    // Get current date.
    today = std::chrono::year_month_day(std::chrono::floor<std::chrono::days>(
        std::chrono::system_clock::now()));

    // Get runtime info.
    auto vintf = VintfObject::GetInstance();
    ASSERT_NE(vintf, nullptr);
    runtime_info = vintf->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION |
                                         RuntimeInfo::FetchFlag::CONFIG_GZ);
    ASSERT_NE(runtime_info, nullptr);
  }

  bool isReleaseEol(std::string_view date) const;

  std::chrono::year_month_day today;
  std::shared_ptr<const RuntimeInfo> runtime_info;
};

bool EolEnforcementTest::isReleaseEol(std::string_view date_string) const {
  std::chrono::year_month_day date;
  if (!parseDate(date_string, date)) {
    ADD_FAILURE() << "Failed to parse date string: " << date_string;
  }
  return today > date;
}

TEST_F(EolEnforcementTest, KernelNotEol) {
  ASSERT_GE(runtime_info->kernelVersion().dropMinor(), (Version{4, 14}))
      << "Kernel versions below 4.14 are EOL";

  std::string kernel_lifetimes_content;
  ASSERT_TRUE(android::base::ReadFileToString(kernel_lifetimes_config_path,
                                              &kernel_lifetimes_content))
      << "Failed to read approved OGKI builds config at "
      << kernel_lifetimes_config_path;

  tinyxml2::XMLDocument kernel_lifetimes_xml;
  const auto xml_error =
      kernel_lifetimes_xml.Parse(kernel_lifetimes_content.c_str());
  ASSERT_EQ(xml_error, tinyxml2::XMLError::XML_SUCCESS)
      << "Failed to parse approved builds config: "
      << tinyxml2::XMLDocument::ErrorIDToName(xml_error);

  const auto kernel_version = runtime_info->kernelVersion();
  std::string branch_name;
  if (kernel_version.dropMinor() < Version{5, 4}) {
    branch_name = std::format("android-{}.{}", kernel_version.version,
                              kernel_version.majorRev);
  } else {
    const auto kernel_release = android::kver::KernelRelease::Parse(
        android::vintf::VintfObject::GetRuntimeInfo()->osRelease(),
        /* allow_suffix = */ true);
    ASSERT_TRUE(kernel_release.has_value())
        << "Failed to parse the kernel release string";
    branch_name =
        std::format("android{}-{}.{}", kernel_release->android_release(),
                    kernel_version.version, kernel_version.majorRev);
  }

  tinyxml2::XMLElement* branch_element = nullptr;
  const auto kernels_element = kernel_lifetimes_xml.RootElement();
  for (auto branch = kernels_element->FirstChildElement("branch"); branch;
       branch = branch->NextSiblingElement("branch")) {
    if (branch->Attribute("name", branch_name.c_str())) {
      branch_element = branch;
      break;
    }
  }
  ASSERT_NE(branch_element, nullptr)
      << "Branch '" << branch_name << "' not found in approved builds config";

  // Test against branch EOL is there are no releases for the branch.
  if (const auto no_releases = branch_element->FirstChildElement("no-releases");
      no_releases != nullptr) {
    std::chrono::year_month_day eol;
    ASSERT_TRUE(parseDate(branch_element->Attribute("eol"), eol))
        << "Failed to parse branch '" << branch_name
        << "' EOL date: " << branch_element->Attribute("eol");
    EXPECT_GE(eol, today);
    return;
  }

  // Test against kernel release EOL.
  const auto lts_versions = branch_element->FirstChildElement("lts-versions");
  const auto release_version =
      std::format("{}.{}.{}", kernel_version.version, kernel_version.majorRev,
                  kernel_version.minorRev);
  tinyxml2::XMLElement* latest_release = nullptr;
  KernelVersion latest_kernel_version;
  for (auto release = lts_versions->FirstChildElement("release"); release;
       release = release->NextSiblingElement("release")) {
    if (release->Attribute("version", release_version.c_str())) {
      EXPECT_FALSE(isReleaseEol(release->Attribute("eol")));
      return;
    } else if (auto kernel_version =
                   parseKernelVersion(release->Attribute("version"));
               latest_release == nullptr ||
               kernel_version > latest_kernel_version) {
      latest_release = release;
      latest_kernel_version = kernel_version;
    }
  }

  // If current kernel version is newer than the latest kernel version found in
  // the config, then this might be a kernel release which is yet to get a
  // release config. Test against the latest kernel release version if this is
  // the case.
  if (kernel_version > latest_kernel_version) {
    EXPECT_FALSE(isReleaseEol(latest_release->Attribute("eol")));
  } else {
    FAIL() << "Kernel release '" << release_version << "' is not recognised";
  }
}
