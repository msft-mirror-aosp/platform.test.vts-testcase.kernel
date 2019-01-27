/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <linux/bpf.h>
#include <stdint.h>

#define ELF_SEC(NAME) __attribute__((section(NAME), used))

#define TEST_PROG_NAME "test_prog"

#define COOKIE_STATS_MAP_A 0xc001eaaaffffffff
#define COOKIE_STATS_MAP_B 0xc001eaabffffffff
#define CONFIGURATION_MAP 0xc0f1a10affffffff

struct stats_value {
  uint64_t rxPackets;
  uint64_t rxBytes;
  uint64_t txPackets;
  uint64_t txBytes;
};
