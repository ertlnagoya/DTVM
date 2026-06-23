// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H
#define ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace zen::runtime {

struct EVMMemorySpecializationProfile {
  uint8_t SkipLeadingZeroLimbStores = 0;
  bool HasFullCallDataLoad0Window = false;
  bool HasKnownCallDataLoad0Low64 = false;
  uint64_t KnownCallDataLoad0Low64 = 0;
};

struct EVMMemorySpecializationCodegenKey {
  uint8_t SkipLeadingZeroLimbStores = 0;
};

inline EVMMemorySpecializationCodegenKey getEVMMemorySpecializationCodegenKey(
    const EVMMemorySpecializationProfile &Profile) {
  return {Profile.SkipLeadingZeroLimbStores};
}

inline EVMMemorySpecializationProfile
deriveEVMMemorySpecializationProfileFromCallData(const uint8_t *InputData,
                                                 size_t InputSize) {
  EVMMemorySpecializationProfile Profile;
  uint8_t Word[32] = {};
  const size_t CopySize = std::min(InputSize, sizeof(Word));
  if (CopySize != 0 && InputData != nullptr) {
    std::memcpy(Word, InputData, CopySize);
  }

  for (size_t I = 0; I < 24; ++I) {
    if (Word[I] != 0) {
      return Profile;
    }
  }

  uint64_t Low64 = 0;
  for (size_t I = 24; I < 32; ++I) {
    Low64 = (Low64 << 8) | static_cast<uint64_t>(Word[I]);
  }

  if (Low64 <= 8) {
    Profile.SkipLeadingZeroLimbStores = 2;
  } else if (Low64 <= 16) {
    Profile.SkipLeadingZeroLimbStores = 1;
  }
  return Profile;
}

} // namespace zen::runtime

#endif // ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H
