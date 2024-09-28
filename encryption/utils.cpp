/*
 * Copyright (C) 2020 The Android Open Source Project
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

// Utility functions for VtsKernelEncryptionTest.

#include <algorithm>
#include <fstream>

#include <LzmaLib.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_sb.h>
#include <ext4_utils/ext4_utils.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <linux/magic.h>
#include <mntent.h>
#include <openssl/cmac.h>
#include <unistd.h>

#include "Keymaster.h"
#include "vts_kernel_encryption.h"

using android::base::ParseInt;
using android::base::Split;
using android::base::StartsWith;
using namespace android::dm;

namespace android {
namespace kernel {

enum KdfVariant {
  KDF_VARIANT_V1 = 0,
  KDF_VARIANT_LEGACY = 1,
  KDF_VARIANT_REARRANGED = 2,
  KDF_VARIANT_COUNT,
};

// Context in fixed input string comprises of software provided context,
// padding to eight bytes (if required) and the key policy.
static const std::vector<std::vector<uint8_t>> HwWrappedEncryptionKeyContexts =
    {
        // "v1"
        {'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n', 'c', 'r', 'y',
         'p',  't',  'i',  'o',  'n',  ' ',  'k',  'e',  'y', 0x0, 0x0, 0x0,
         0x00, 0x00, 0x00, 0x02, 0x43, 0x00, 0x82, 0x50, 0x0, 0x0, 0x0, 0x0},
        // Below for "legacy && kdf tied to Trusted Execution
        // Environment(TEE)".
        // Where as above caters ( "all latest targets" || ("legacy && kdf
        // not tied to TEE)).
        // "legacykdf"
        {'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n', 'c', 'r', 'y',
         'p',  't',  'i',  'o',  'n',  ' ',  'k',  'e',  'y', 0x0, 0x0, 0x0,
         0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0x82, 0x18, 0x0, 0x0, 0x0, 0x0},
        // "rearranged"
        {
            'i',  'n',  'l',  'i',  'n',  'e',  ' ',  'e',  'n',
            'c',  'r',  'y',  'p',  't',  'i',  'o',  'n',  ' ',
            's',  't',  'o',  'r',  'a',  'g',  'e',  'k',  'e',
            'y',  ' ',  'c',  't',  'x',  0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x70, 0x18, 0x72, 0x00, 0x00, 0x00, 0x00,
        }};

static const std::vector<std::vector<uint8_t>> HwWrappedEncryptionKeyLabels = {
    // "v1"
    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
    // "legacykdf"
    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
    // "rearranged"
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    },
};

static const std::vector<std::vector<uint8_t>> SwSecretContexts = {
    // "v1"
    {
        'r',  'a',  'w',  ' ',  's', 'e', 'c',  'r',  'e',  't',
        0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x00, 0x00, 0x00, 0x02,
        0x17, 0x00, 0x80, 0x50, 0x0, 0x0, 0x0,  0x0,
    },
    // "legacykdf"
    {
        'r',  'a',  'w',  ' ',  's', 'e', 'c',  'r',  'e',  't',
        0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x00, 0x00, 0x00, 0x02,
        0x17, 0x00, 0x80, 0x50, 0x0, 0x0, 0x0,  0x0,
    },
    // "rearranged"
    {
        'd', 'e', 'r', 'i', 'v', 'e', ' ', 'r', 'a', 'w', ' ',
        's', 'e', 'c', 'r', 'e', 't', ' ', 'c', 'o', 'n', 't',
        'e', 'x', 't', ' ', 'a', 'b', 'c', 'd', 'e', 'f',
    }};

static const std::vector<std::vector<uint8_t>> SwSecretLabels = {
    // "v1"
    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
    // "legacykdf"
    {0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
    // "rearranged"
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    },
};

static bool GetKdfVariantId(KdfVariant *kdf_id) {
  std::string kdf =
      android::base::GetProperty("ro.crypto.hw_wrapped_keys.kdf", "v1");

  if (kdf == "v1") {
    *kdf_id = KDF_VARIANT_V1;
  } else if (kdf == "legacykdf") {
    *kdf_id = KDF_VARIANT_LEGACY;
  } else if (kdf == "rearranged") {
    *kdf_id = KDF_VARIANT_REARRANGED;
  } else {
    ADD_FAILURE() << "Unknown KDF: " << kdf;
    return false;
  }
  return true;
}

static void GetKdfContextLabelByKdfId(KdfVariant kdf_id,
                                      std::vector<uint8_t> *ctx,
                                      std::vector<uint8_t> *lbl) {
  *ctx = HwWrappedEncryptionKeyContexts[kdf_id];
  *lbl = HwWrappedEncryptionKeyLabels[kdf_id];
}

static void GetSwSecretContextLabelByKdfId(KdfVariant kdf_id,
                                           std::vector<uint8_t> *ctx,
                                           std::vector<uint8_t> *lbl) {
  *ctx = SwSecretContexts[kdf_id];
  *lbl = SwSecretLabels[kdf_id];
}

// Offset in bytes to the filesystem superblock, relative to the beginning of
// the block device
constexpr int kExt4SuperBlockOffset = 1024;
constexpr int kF2fsSuperBlockOffset = 1024;

// For F2FS: the offsets in bytes to the filesystem magic number and filesystem
// UUID, relative to the beginning of the block device
constexpr int kF2fsMagicOffset = kF2fsSuperBlockOffset;
constexpr int kF2fsUuidOffset = kF2fsSuperBlockOffset + 108;

// hw-wrapped key size in bytes
constexpr int kHwWrappedKeySize = 32;

std::string Errno() { return std::string(": ") + strerror(errno); }

// Recursively deletes the file or directory at |path|, if it exists.
void DeleteRecursively(const std::string &path) {
  if (unlink(path.c_str()) == 0 || errno == ENOENT) return;
  ASSERT_EQ(EISDIR, errno) << "Failed to unlink " << path << Errno();

  std::unique_ptr<DIR, int (*)(DIR *)> dirp(opendir(path.c_str()), closedir);
  // If the directory was assigned an encryption policy that the kernel lacks
  // crypto API support for, then opening it will fail, and it will be empty.
  // So, we have to allow opening the directory to fail.
  if (dirp != nullptr) {
    struct dirent *entry;
    while ((entry = readdir(dirp.get())) != nullptr) {
      std::string filename(entry->d_name);
      if (filename != "." && filename != "..")
        DeleteRecursively(path + "/" + filename);
    }
  }
  ASSERT_EQ(0, rmdir(path.c_str()))
      << "Failed to remove directory " << path << Errno();
}

// Generates some "random" bytes.  Not secure; this is for testing only.
void RandomBytesForTesting(std::vector<uint8_t> &bytes) {
  for (size_t i = 0; i < bytes.size(); i++) {
    bytes[i] = rand();
  }
}

// Generates a "random" key.  Not secure; this is for testing only.
std::vector<uint8_t> GenerateTestKey(size_t size) {
  std::vector<uint8_t> key(size);
  RandomBytesForTesting(key);
  return key;
}

std::string BytesToHex(const std::vector<uint8_t> &bytes) {
  std::ostringstream o;
  for (uint8_t b : bytes) {
    o << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  return o.str();
}

bool GetFirstApiLevel(int *first_api_level) {
  *first_api_level =
      android::base::GetIntProperty("ro.product.first_api_level", 0);
  if (*first_api_level == 0) {
    ADD_FAILURE() << "ro.product.first_api_level is unset";
    return false;
  }
  GTEST_LOG_(INFO) << "ro.product.first_api_level = " << *first_api_level;
  return true;
}

// Gets the UUID of the filesystem that uses |fs_blk_device| as its main block
// device. |fs_type| gives the filesystem type.
//
// Unfortunately there's no kernel API to get the UUID; instead we have to read
// it from the filesystem superblock.
static bool GetFilesystemUuid(const std::string &fs_blk_device,
                              const std::string &fs_type,
                              FilesystemUuid *fs_uuid) {
  android::base::unique_fd fd(
      open(fs_blk_device.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to open fs block device " << fs_blk_device
                  << Errno();
    return false;
  }

  if (fs_type == "ext4") {
    struct ext4_super_block sb;

    if (pread(fd, &sb, sizeof(sb), kExt4SuperBlockOffset) != sizeof(sb)) {
      ADD_FAILURE() << "Error reading ext4 superblock from " << fs_blk_device
                    << Errno();
      return false;
    }
    if (sb.s_magic != cpu_to_le16(EXT4_SUPER_MAGIC)) {
      ADD_FAILURE() << "Failed to find ext4 superblock on " << fs_blk_device;
      return false;
    }
    static_assert(sizeof(sb.s_uuid) == kFilesystemUuidSize);
    memcpy(fs_uuid->bytes, sb.s_uuid, kFilesystemUuidSize);
  } else if (fs_type == "f2fs") {
    // Android doesn't have an f2fs equivalent of libext4_utils, so we have to
    // hard-code the offset to the magic number and UUID.

    __le32 magic;
    if (pread(fd, &magic, sizeof(magic), kF2fsMagicOffset) != sizeof(magic)) {
      ADD_FAILURE() << "Error reading f2fs superblock from " << fs_blk_device
                    << Errno();
      return false;
    }
    if (magic != cpu_to_le32(F2FS_SUPER_MAGIC)) {
      ADD_FAILURE() << "Failed to find f2fs superblock on " << fs_blk_device;
      return false;
    }
    if (pread(fd, fs_uuid->bytes, kFilesystemUuidSize, kF2fsUuidOffset) !=
        kFilesystemUuidSize) {
      ADD_FAILURE() << "Failed to read f2fs filesystem UUID from "
                    << fs_blk_device << Errno();
      return false;
    }
  } else {
    ADD_FAILURE() << "Unknown filesystem type " << fs_type;
    return false;
  }
  return true;
}

// Gets the raw block device corresponding to |fs_blk_device| that is one of a
// filesystem's mounted block devices. By "raw block device" we mean a block
// device from which we can read the encrypted file contents and filesystem
// metadata.  When metadata encryption is disabled, this is simply
// |fs_blk_device|.  When metadata encryption is enabled, then |fs_blk_device|
// is a dm-default-key device and the "raw block device" is the parent of this
// dm-default-key device.
//
// We don't just use the block device listed in the fstab, because (a) it can be
// a logical partition name which needs extra code to map to a block device, and
// (b) due to block-level checkpointing, there can be a dm-bow device between
// the fstab partition and dm-default-key.  dm-bow can remap sectors, but for
// encryption testing we don't want any sector remapping.  So the correct block
// device to read ciphertext from is the one directly underneath dm-default-key.
static bool GetRawBlockDevice(const std::string &fs_blk_device,
                              std::string *raw_blk_device) {
  DeviceMapper &dm = DeviceMapper::Instance();

  if (!dm.IsDmBlockDevice(fs_blk_device)) {
    GTEST_LOG_(INFO)
        << fs_blk_device
        << " is not a device-mapper device; metadata encryption is disabled";
    *raw_blk_device = fs_blk_device;
    return true;
  }
  const std::optional<std::string> name =
      dm.GetDmDeviceNameByPath(fs_blk_device);
  if (!name) {
    ADD_FAILURE() << "Failed to get name of device-mapper device "
                  << fs_blk_device;
    return false;
  }

  std::vector<DeviceMapper::TargetInfo> table;
  if (!dm.GetTableInfo(*name, &table)) {
    ADD_FAILURE() << "Failed to get table of device-mapper device " << *name;
    return false;
  }
  if (table.size() != 1) {
    GTEST_LOG_(INFO) << fs_blk_device
                     << " has multiple device-mapper targets; assuming "
                        "metadata encryption is disabled";
    *raw_blk_device = fs_blk_device;
    return true;
  }
  const std::string target_type = dm.GetTargetType(table[0].spec);
  if (target_type != "default-key") {
    GTEST_LOG_(INFO) << fs_blk_device << " is a dm-" << target_type
                     << " device, not dm-default-key; assuming metadata "
                        "encryption is disabled";
    *raw_blk_device = fs_blk_device;
    return true;
  }
  std::optional<std::string> parent =
      dm.GetParentBlockDeviceByPath(fs_blk_device);
  if (!parent) {
    ADD_FAILURE() << "Failed to get parent of dm-default-key device " << *name;
    return false;
  }
  *raw_blk_device = *parent;
  return true;
}

// Gets information about a filesystem's block devices
static bool GetFsBlockDeviceList(FilesystemInfo *fs_info,
                                 const std::string &mnt_fsname) {
  // Add a default block device
  DiskMapEntry map_entry;
  map_entry.start_blkaddr = 0;
  map_entry.end_blkaddr = INT64_MAX - 1;
  map_entry.fs_blk_device = mnt_fsname;

  if (!GetRawBlockDevice(map_entry.fs_blk_device, &map_entry.raw_blk_device)) {
    ADD_FAILURE() << "Broken block device path of the default disk";
    return false;
  }
  fs_info->disk_map.push_back(map_entry);

  if (fs_info->type != "f2fs") return true;

  // This requires a kernel patch, f238eff95f48 ("f2fs: add a proc entry show
  // disk layout"), merged in v6.9
  static constexpr std::string_view kDevBlockPrefix("/dev/block/");
  const std::string proc_path = "/proc/fs/f2fs/" +
                                mnt_fsname.substr(kDevBlockPrefix.length()) +
                                "/disk_map";
  std::ifstream proc_fs(proc_path.c_str());
  if (!proc_fs.is_open()) {
    GTEST_LOG_(INFO) << proc_path
                     << " does not exist (expected on pre-6.9 kernels)";
    return true;
  }

  std::string line;
  bool first_device = true;
  while (std::getline(proc_fs, line)) {
    if (!android::base::StartsWith(line, "Disk: ")) {
      continue;
    }
    if (first_device) {
      fs_info->disk_map.erase(fs_info->disk_map.begin());
      first_device = false;
    }
    DiskMapEntry map_entry;
    std::vector<std::string> data = Split(line, "\t ");
    if (!ParseInt(data[3], &map_entry.start_blkaddr)) {
      ADD_FAILURE() << "Broken first block address in the address range";
      return false;
    }
    if (!ParseInt(data[5], &map_entry.end_blkaddr)) {
      ADD_FAILURE() << "Broken last block address in the address range";
      return false;
    }
    map_entry.fs_blk_device = data[7];
    if (!GetRawBlockDevice(map_entry.fs_blk_device,
                           &map_entry.raw_blk_device)) {
      ADD_FAILURE() << "Broken block device path in the disk map entry";
      return false;
    }
    fs_info->disk_map.push_back(map_entry);
  }
  return true;
}

// Gets the block device list and type of the filesystem mounted on
// |mountpoint|. The block device list has all the block device information
// along with the address space ranges configured by the mounted filesystem.
static bool GetFsBlockDeviceListAndType(const std::string &mountpoint,
                                        FilesystemInfo *fs_info) {
  std::unique_ptr<FILE, int (*)(FILE *)> mnts(setmntent("/proc/mounts", "re"),
                                              endmntent);
  if (!mnts) {
    ADD_FAILURE() << "Failed to open /proc/mounts" << Errno();
    return false;
  }
  struct mntent *mnt;
  while ((mnt = getmntent(mnts.get())) != nullptr) {
    if (mnt->mnt_dir == mountpoint) {
      fs_info->type = mnt->mnt_type;
      return GetFsBlockDeviceList(fs_info, mnt->mnt_fsname);
    }
  }
  ADD_FAILURE() << "No /proc/mounts entry found for " << mountpoint;
  return false;
}

// Gets information about the filesystem mounted on |mountpoint|.
bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *fs_info) {
  if (!GetFsBlockDeviceListAndType(mountpoint, fs_info)) return false;

  // This disk_map[0] always indicates the main block device which the
  // filesystem contains its superblock.
  if (!GetFilesystemUuid(fs_info->disk_map[0].fs_blk_device, fs_info->type,
                         &fs_info->uuid))
    return false;

  GTEST_LOG_(INFO) << " Filesystem mounted on " << mountpoint
                   << " has type: " << fs_info->type << ", UUID is "
                   << BytesToHex(fs_info->uuid.bytes);

  for (const DiskMapEntry &map_entry : fs_info->disk_map) {
    GTEST_LOG_(INFO) << "Block device: " << map_entry.fs_blk_device << " ("
                     << map_entry.raw_blk_device << ") ranging from "
                     << map_entry.start_blkaddr << " to "
                     << map_entry.end_blkaddr;
  }
  return true;
}

// Returns true if the given data seems to be random.
//
// Check compressibility rather than byte frequencies.  Compressibility is a
// stronger test since it also detects repetitions.
//
// To check compressibility, use LZMA rather than DEFLATE/zlib/gzip because LZMA
// compression is stronger and supports a much larger dictionary.  DEFLATE is
// limited to a 32 KiB dictionary.  So, data repeating after 32 KiB (or more)
// would not be detected with DEFLATE.  But LZMA can detect it.
bool VerifyDataRandomness(const std::vector<uint8_t> &bytes) {
  // To avoid flakiness, allow the data to be compressed a tiny bit by chance.
  // There is at most a 2^-32 chance that random data can be compressed to be 4
  // bytes shorter.  In practice it's even lower due to compression overhead.
  size_t destLen = bytes.size() - std::min<size_t>(4, bytes.size());
  std::vector<uint8_t> dest(destLen);
  uint8_t outProps[LZMA_PROPS_SIZE];
  size_t outPropsSize = LZMA_PROPS_SIZE;
  int ret;

  ret = LzmaCompress(dest.data(), &destLen, bytes.data(), bytes.size(),
                     outProps, &outPropsSize,
                     6,               // compression level (0 <= level <= 9)
                     bytes.size(),    // dictionary size
                     -1, -1, -1, -1,  // lc, lp, bp, fb (-1 selects the default)
                     1);              // number of threads

  if (ret == SZ_ERROR_OUTPUT_EOF) return true;  // incompressible

  if (ret == SZ_OK) {
    ADD_FAILURE() << "Data is not random!  Compressed " << bytes.size()
                  << " to " << destLen << " bytes";
  } else {
    ADD_FAILURE() << "LZMA compression error: ret=" << ret;
  }
  return false;
}

static bool TryPrepareHwWrappedKey(Keymaster &keymaster,
                                   const std::string &master_key_string,
                                   std::string *exported_key_string,
                                   bool rollback_resistance) {
  // This key is used to drive a CMAC-based KDF
  auto paramBuilder =
      km::AuthorizationSetBuilder().AesEncryptionKey(kHwWrappedKeySize * 8);
  if (rollback_resistance) {
    paramBuilder.Authorization(km::TAG_ROLLBACK_RESISTANCE);
  }
  paramBuilder.Authorization(km::TAG_STORAGE_KEY);

  std::string wrapped_key_blob;
  if (keymaster.importKey(paramBuilder, master_key_string, &wrapped_key_blob) &&
      keymaster.exportKey(wrapped_key_blob, exported_key_string)) {
    return true;
  }
  // It's fine for Keymaster not to support hardware-wrapped keys, but
  // if generateKey works, importKey must too.
  if (keymaster.generateKey(paramBuilder, &wrapped_key_blob) &&
      keymaster.exportKey(wrapped_key_blob, exported_key_string)) {
    ADD_FAILURE() << "generateKey succeeded but importKey failed";
  }
  return false;
}

bool CreateHwWrappedKey(std::vector<uint8_t> *master_key,
                        std::vector<uint8_t> *exported_key) {
  *master_key = GenerateTestKey(kHwWrappedKeySize);

  Keymaster keymaster;
  if (!keymaster) {
    ADD_FAILURE() << "Unable to find keymaster";
    return false;
  }
  std::string master_key_string(master_key->begin(), master_key->end());
  std::string exported_key_string;
  // Make two attempts to create a key, first with and then without
  // rollback resistance.
  if (TryPrepareHwWrappedKey(keymaster, master_key_string, &exported_key_string,
                             true) ||
      TryPrepareHwWrappedKey(keymaster, master_key_string, &exported_key_string,
                             false)) {
    exported_key->assign(exported_key_string.begin(),
                         exported_key_string.end());
    return true;
  }
  GTEST_LOG_(INFO) << "Skipping test because device doesn't support "
                      "hardware-wrapped keys";
  return false;
}

static void PushBigEndian32(uint32_t val, std::vector<uint8_t> *vec) {
  for (int i = 24; i >= 0; i -= 8) {
    vec->push_back((val >> i) & 0xFF);
  }
}

static void RearrangeFixedInputString(
    KdfVariant kdf_id, std::vector<uint8_t> *fixed_input_string) {
  if (kdf_id != KDF_VARIANT_REARRANGED) {
    return;
  }

  // Rearrange the fixed-input string, reversing the order that the blocks are
  // processed:
  // ABCD-EFGH-IJKL-MNO
  // into
  // LMNO-HIJK-DEFG-ABC
  size_t len = fixed_input_string->size();
  std::vector<uint8_t> tmp(len);
  for (size_t j = 0; j < len; j += kAesBlockSize) {
    size_t to_copy = std::min((size_t)kAesBlockSize, len - j);
    std::copy(fixed_input_string->cbegin() + len - j - to_copy,
              fixed_input_string->cbegin() + len - j, tmp.begin() + j);
  }
  std::copy(tmp.cbegin(), tmp.cend(), fixed_input_string->begin());
}

static void GetFixedInputString(KdfVariant kdf_id, uint32_t counter,
                                const std::vector<uint8_t> &label,
                                const std::vector<uint8_t> &context,
                                uint32_t derived_key_len,
                                std::vector<uint8_t> *fixed_input_string) {
  PushBigEndian32(counter, fixed_input_string);
  fixed_input_string->insert(fixed_input_string->end(), label.begin(),
                             label.end());
  fixed_input_string->push_back(0);
  fixed_input_string->insert(fixed_input_string->end(), context.begin(),
                             context.end());
  PushBigEndian32(derived_key_len, fixed_input_string);

  // If applicable, rearrange the fixed-input string
  RearrangeFixedInputString(kdf_id, fixed_input_string);
}

static bool AesCmacKdfHelper(KdfVariant kdf_id, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &label,
                             const std::vector<uint8_t> &context,
                             uint32_t output_key_size,
                             std::vector<uint8_t> *output_data) {
  GTEST_LOG_(INFO) << "KDF ID = " << kdf_id;
  output_data->resize(output_key_size);
  for (size_t count = 0; count < (output_key_size / kAesBlockSize); count++) {
    std::vector<uint8_t> fixed_input_string;
    GetFixedInputString(kdf_id, count + 1, label, context,
                        (output_key_size * 8), &fixed_input_string);
    GTEST_LOG_(INFO) << "Fixed Input (block: " << count
                     << "): " << BytesToHex(fixed_input_string);
    if (!AES_CMAC(output_data->data() + (kAesBlockSize * count), key.data(),
                  key.size(), fixed_input_string.data(),
                  fixed_input_string.size())) {
      ADD_FAILURE()
          << "AES_CMAC failed while deriving subkey from HW wrapped key";
      return false;
    }
  }
  return true;
}

static bool DeriveHwWrappedEncryptionKeyByKdfId(
    KdfVariant kdf_id, const std::vector<uint8_t> &master_key,
    std::vector<uint8_t> *enc_key) {
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> label;
  GetKdfContextLabelByKdfId(kdf_id, &ctx, &label);
  return AesCmacKdfHelper(kdf_id, master_key, label, ctx, kAes256XtsKeySize,
                          enc_key);
}

bool DeriveHwWrappedEncryptionKey(const std::vector<uint8_t> &master_key,
                                  std::vector<uint8_t> *enc_key) {
  KdfVariant kdf_id;
  if (!GetKdfVariantId(&kdf_id)) {
    return false;
  }
  return DeriveHwWrappedEncryptionKeyByKdfId(kdf_id, master_key, enc_key);
}

static bool DeriveHwWrappedRawSecretByKdfId(
    KdfVariant kdf_id, const std::vector<uint8_t> &master_key,
    std::vector<uint8_t> *secret) {
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> label;
  GetSwSecretContextLabelByKdfId(kdf_id, &ctx, &label);
  return AesCmacKdfHelper(kdf_id, master_key, label, ctx, kAes256KeySize,
                          secret);
}

bool DeriveHwWrappedRawSecret(const std::vector<uint8_t> &master_key,
                              std::vector<uint8_t> *secret) {
  KdfVariant kdf_id;
  if (!GetKdfVariantId(&kdf_id)) {
    return false;
  }
  return DeriveHwWrappedRawSecretByKdfId(kdf_id, master_key, secret);
}

TEST(UtilsTest, TestKdfVariants) {
  std::vector<KdfVariant> kdf_ids = {
      KDF_VARIANT_V1,
      KDF_VARIANT_LEGACY,
      KDF_VARIANT_REARRANGED,
  };

  std::vector<std::vector<uint8_t>> expected_keys = {
      // "v1"
      {
          0xcb, 0xe5, 0xdb, 0x40, 0x21, 0x5a, 0x3d, 0x38, 0x6d, 0x61, 0xe5,
          0x4e, 0xf2, 0xf8, 0xa7, 0x81, 0x4b, 0x00, 0xba, 0xcf, 0x35, 0xb3,
          0x16, 0xf8, 0x8e, 0x68, 0xe8, 0x9a, 0x47, 0xab, 0xba, 0xb4, 0x83,
          0x4c, 0x27, 0xda, 0xc8, 0xa9, 0x1a, 0xe1, 0xc3, 0x30, 0x4f, 0x31,
          0xb5, 0xf2, 0x20, 0x2c, 0x14, 0x98, 0x96, 0x61, 0xba, 0xfc, 0xcc,
          0x56, 0xcf, 0x62, 0x12, 0xd8, 0xb1, 0xf7, 0x26, 0x91,
      },
      // "legacykdf"
      {
          0x63, 0x61, 0xf8, 0x02, 0xb3, 0x7a, 0xa6, 0x4a, 0x07, 0x57, 0x84,
          0xbe, 0xde, 0x23, 0x41, 0xf1, 0xd9, 0x23, 0x6e, 0x64, 0x6c, 0x70,
          0x46, 0x0f, 0x15, 0xb3, 0x7c, 0xe5, 0xff, 0x43, 0xa5, 0x4f, 0x15,
          0xd9, 0x56, 0x93, 0x34, 0x3d, 0x52, 0x8b, 0x67, 0x37, 0x2a, 0x7f,
          0x38, 0x3e, 0xd8, 0xe7, 0xc4, 0x5e, 0xd0, 0x89, 0x9e, 0x02, 0x82,
          0x54, 0x53, 0xc9, 0x41, 0x9a, 0xaf, 0xa3, 0x69, 0x5f,
      },
      // "rearranged"
      {
          0xdb, 0xa0, 0xa6, 0x7e, 0x47, 0x1b, 0xe3, 0x9f, 0xd1, 0xec, 0x28,
          0x99, 0x45, 0xf5, 0x21, 0x45, 0xdf, 0x12, 0x93, 0x7a, 0x0b, 0x42,
          0x91, 0x5f, 0x7c, 0x71, 0x1f, 0xeb, 0x47, 0x40, 0x3e, 0x6a, 0xe5,
          0xb7, 0xb5, 0x29, 0x68, 0xa8, 0xcc, 0x63, 0x5d, 0x10, 0xab, 0x8b,
          0x87, 0x24, 0xef, 0x5d, 0xec, 0x62, 0x36, 0xd8, 0x1a, 0x1b, 0x38,
          0x78, 0x08, 0xc4, 0x07, 0xce, 0x01, 0xc5, 0x63, 0x88,
      },
  };

  std::vector<std::vector<uint8_t>> expected_secrets = {
      // "v1"
      {
          0xe2, 0x6f, 0xb1, 0x9b, 0x4f, 0xb6, 0x26, 0x6f, 0xc7, 0xc5, 0xfc,
          0x96, 0x54, 0xef, 0xad, 0x64, 0x3c, 0xfe, 0xbc, 0x64, 0xc0, 0x97,
          0x34, 0x11, 0x55, 0x19, 0x55, 0x95, 0xc2, 0x8d, 0x5e, 0xc9,
      },
      // "legacykdf"
      {
          0xe2, 0x6f, 0xb1, 0x9b, 0x4f, 0xb6, 0x26, 0x6f, 0xc7, 0xc5, 0xfc,
          0x96, 0x54, 0xef, 0xad, 0x64, 0x3c, 0xfe, 0xbc, 0x64, 0xc0, 0x97,
          0x34, 0x11, 0x55, 0x19, 0x55, 0x95, 0xc2, 0x8d, 0x5e, 0xc9,
      },
      // "rearranged"
      {
          0x4e, 0xf0, 0x6e, 0x6a, 0xa9, 0x84, 0x10, 0x46, 0x67, 0x86, 0x3f,
          0x15, 0x08, 0x7c, 0x12, 0xbb, 0xfb, 0x8e, 0x47, 0x15, 0x14, 0x5b,
          0xc0, 0x6b, 0x59, 0x82, 0xab, 0xd4, 0x19, 0x83, 0x85, 0xb4,
      },
  };

  ASSERT_EQ(kdf_ids.size(), KDF_VARIANT_COUNT);
  ASSERT_EQ(expected_keys.size(), KDF_VARIANT_COUNT);
  ASSERT_EQ(expected_secrets.size(), KDF_VARIANT_COUNT);

  const std::vector<uint8_t> master_key = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };

  GTEST_LOG_(INFO) << "Master Key: " << BytesToHex(master_key);
  for (size_t i = 0; i < KDF_VARIANT_COUNT; i++) {
    std::vector<uint8_t> out_key;
    EXPECT_TRUE(
        DeriveHwWrappedEncryptionKeyByKdfId(kdf_ids[i], master_key, &out_key));
    GTEST_LOG_(INFO) << "Key        (id: " << i << "): " << BytesToHex(out_key);
    GTEST_LOG_(INFO) << "Exp Key    (id: " << i
                     << "): " << BytesToHex(expected_keys[i]);
    EXPECT_EQ(out_key, expected_keys[i]);
    std::vector<uint8_t> out_sec;
    EXPECT_TRUE(
        DeriveHwWrappedRawSecretByKdfId(kdf_ids[i], master_key, &out_sec));
    GTEST_LOG_(INFO) << "Secret     (id: " << i << "): " << BytesToHex(out_sec);
    GTEST_LOG_(INFO) << "Exp Secret (id: " << i
                     << "): " << BytesToHex(expected_secrets[i]);
    EXPECT_EQ(out_sec, expected_secrets[i]);
  }
}

}  // namespace kernel
}  // namespace android
