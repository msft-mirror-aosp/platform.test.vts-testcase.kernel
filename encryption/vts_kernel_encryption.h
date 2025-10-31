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
#pragma once

#include <gtest/gtest.h>
#include <stdint.h>

#include <ostream>
#include <string>
#include <vector>

namespace android {
namespace kernel {

class Cipher {
 public:
  virtual ~Cipher() {}
  bool Encrypt(const std::vector<uint8_t> &key, const uint8_t *iv,
               const uint8_t *src, uint8_t *dst, int nbytes) const {
    if (key.size() != keysize()) {
      ADD_FAILURE() << "Bad key size";
      return false;
    }
    return DoCrypt(key.data(), iv, src, dst, nbytes, true);
  }
  bool Decrypt(const std::vector<uint8_t> &key, const uint8_t *iv,
               const uint8_t *src, uint8_t *dst, int nbytes) const {
    if (key.size() != keysize()) {
      ADD_FAILURE() << "Bad key size";
      return false;
    }
    return DoCrypt(key.data(), iv, src, dst, nbytes, false);
  }
  virtual int keysize() const = 0;
  virtual int ivsize() const = 0;

 protected:
  virtual bool DoCrypt(const uint8_t *key, const uint8_t *iv,
                       const uint8_t *src, uint8_t *dst, int nbytes,
                       bool encrypt) const = 0;
};

// aes_256_xts.cpp

constexpr int kAesBlockSize = 16;
constexpr int kAes256KeySize = 32;
constexpr int kAes256XtsKeySize = 2 * kAes256KeySize;

class Aes256XtsCipher : public Cipher {
 public:
  int keysize() const { return kAes256XtsKeySize; }
  int ivsize() const { return kAesBlockSize; }

 private:
  bool DoCrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *src,
               uint8_t *dst, int nbytes, bool encrypt) const;
};

// adiantum.cpp

constexpr int kAdiantumKeySize = 32;

// It's variable-length in general, but the Linux kernel always uses 32.
constexpr int kAdiantumIVSize = 32;

class AdiantumCipher : public Cipher {
 public:
  int keysize() const { return kAdiantumKeySize; }
  int ivsize() const { return kAdiantumIVSize; }

 private:
  bool DoCrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *src,
               uint8_t *dst, int nbytes, bool encrypt) const;
};

// utils.cpp

std::string Errno();

void DeleteRecursively(const std::string &path);

void RandomBytesForTesting(std::vector<uint8_t> &bytes);

std::string BytesToHex(const std::vector<uint8_t> &bytes);

template <size_t N>
static inline std::string BytesToHex(const uint8_t (&array)[N]) {
  return BytesToHex(std::vector<uint8_t>(&array[0], &array[N]));
}

bool GetFirstApiLevel(int *first_api_level);

constexpr int kFilesystemUuidSize = 16;

struct FilesystemUuid {
  uint8_t bytes[kFilesystemUuidSize];
};

struct DiskMapEntry {
  std::string fs_blk_device;
  std::string raw_blk_device;
  int64_t start_blkaddr;
  int64_t end_blkaddr;
};

struct FilesystemInfo {
  std::string type;
  FilesystemUuid uuid;
  int block_size;  // block size in bytes, typically 4096 or 16384

  // The filesystem's block devices in sorted order of filesystem block address.
  // The covered addresses are guaranteed to be contiguous and non-overlapping.
  // The first device, starting at address 0, is the filesystem's "main" block
  // device.
  // Note, the disk_map's end_blkaddr is inclusive like below:
  // [disk number]   [start_blkaddr]   [end_blkaddr]
  // 0               0                 X - 1
  // 1               X                 Y - 1
  // 2               Y                 Z
  std::vector<DiskMapEntry> disk_map;
};

bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *info);

bool VerifyDataRandomness(const std::vector<uint8_t> &bytes);

enum class KeyType {
  // Raw key.
  kRaw,
  // Legacy hardware-wrapped key, corresponding to "wrappedkey_v0" in fstab
  kHwWrappedV0,
};

std::ostream &operator<<(std::ostream &os, KeyType key_type);

// A test key for file-based encryption or metadata encryption
struct StorageKey {
  // The type of the key
  KeyType type;

  // The bytes that should be added to the kernel to encrypt data using this
  // key.  For a raw key, this is just the raw key.  For a HW-wrapped key, this
  // is the ephemerally-wrapped key.
  std::vector<uint8_t> kernel_key;

  // The key with which data on-disk is actually encrypted (except when using
  // fscrypt with a raw key).  For a raw key, this is just the raw key.  For a
  // HW-wrapped key, this is a subkey that is derived from the raw class key.
  //
  // Note: in the case of fscrypt with a raw key, the data on-disk is actually
  // encrypted with a subkey derived from the raw key.  So, this field doesn't
  // directly apply in that case.
  std::vector<uint8_t> inline_encryption_key;

  // The HKDF-SHA512 key from which any needed subkeys associated with this key
  // are derived by the kernel.  For a raw key, this is just the raw key.  For a
  // HW-wrapped key, this is another subkey derived from the raw class key.
  std::vector<uint8_t> sw_secret;
};

bool GenerateStorageKey(KeyType type, size_t size, StorageKey *key);

}  // namespace kernel
}  // namespace android
