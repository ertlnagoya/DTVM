// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_PRECOMPILES_HPP
#define ZEN_TESTS_EVM_PRECOMPILES_HPP

#include "evm/evm.h"
#include "host/evm/crypto.h"
#ifndef MCLBN_FP_UNIT_SIZE
#define MCLBN_FP_UNIT_SIZE 4
#endif
#ifndef MCLBN_FR_UNIT_SIZE
#define MCLBN_FR_UNIT_SIZE 4
#endif
#include <mcl/bn.h>
#ifndef MCLBN_IO_SERIALIZE
#define MCLBN_IO_SERIALIZE 512
#endif
#ifndef MCLBN_IO_BIG_ENDIAN
#define MCLBN_IO_BIG_ENDIAN 8192
#endif
#include <algorithm>
#include <array>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <vector>

namespace zen::evm::precompile {

inline bool isCanonicalPrecompileAddress(const evmc::address &Addr,
                                         uint8_t Suffix) noexcept {
  for (size_t I = 0; I + 1 < sizeof(Addr.bytes); ++I) {
    if (Addr.bytes[I] != 0) {
      return false;
    }
  }
  return Addr.bytes[sizeof(Addr.bytes) - 1] == Suffix;
}

inline bool isIdentityPrecompile(const evmc::address &Addr) noexcept {
  return isCanonicalPrecompileAddress(Addr, 0x04);
}

inline bool isSha256Precompile(const evmc::address &Addr) noexcept {
  return isCanonicalPrecompileAddress(Addr, 0x02);
}

inline bool isEcRecoverPrecompile(const evmc::address &Addr) noexcept {
  return isCanonicalPrecompileAddress(Addr, 0x01);
}

inline bool isRipemd160Precompile(const evmc::address &Addr) noexcept {
  return isCanonicalPrecompileAddress(Addr, 0x03);
}

inline bool isBn256AddPrecompile(const evmc::address &Addr,
                                 evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isCanonicalPrecompileAddress(Addr, 0x06);
}

inline bool isBn256MulPrecompile(const evmc::address &Addr,
                                 evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isCanonicalPrecompileAddress(Addr, 0x07);
}

inline bool isBn256PairingPrecompile(const evmc::address &Addr,
                                     evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isCanonicalPrecompileAddress(Addr, 0x08);
}

inline bool isModExpPrecompile(const evmc::address &Addr,
                               evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isCanonicalPrecompileAddress(Addr, 0x05);
}

inline bool isBlake2bPrecompile(const evmc::address &Addr,
                                evmc_revision Revision) noexcept {
  if (Revision < EVMC_ISTANBUL) {
    return false;
  }
  return isCanonicalPrecompileAddress(Addr, 0x09);
}

inline evmc::Result executeIdentity(const evmc_message &Msg,
                                    std::vector<uint8_t> &ReturnData) {
  constexpr uint64_t BaseGas = 15;
  constexpr uint64_t GasPerWord = 3;
  const uint64_t InputSize = Msg.input_size;
  const uint64_t WordCount = (InputSize + 31) / 32;
  const uint64_t GasCost = BaseGas + WordCount * GasPerWord;
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint8_t *Input =
      InputSize == 0 ? nullptr : static_cast<const uint8_t *>(Msg.input_data);
  if (Input == nullptr || InputSize == 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  ReturnData.assign(Input, Input + InputSize);
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline uint32_t rotr32(uint32_t Value, unsigned Shift) noexcept {
  return (Value >> Shift) | (Value << (32 - Shift));
}

inline std::array<uint8_t, 32> sha256Digest(const uint8_t *Data,
                                            size_t Size) noexcept {
  static constexpr std::array<uint32_t, 64> K = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
      0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
      0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
      0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
      0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
      0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
      0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
      0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
      0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
      0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

  std::array<uint32_t, 8> H = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U,
                               0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
                               0x1f83d9abU, 0x5be0cd19U};

  std::vector<uint8_t> Msg;
  if (Data != nullptr && Size != 0) {
    Msg.assign(Data, Data + Size);
  }
  Msg.push_back(0x80);
  while ((Msg.size() % 64) != 56) {
    Msg.push_back(0);
  }
  const uint64_t BitLen = static_cast<uint64_t>(Size) * 8;
  for (int I = 7; I >= 0; --I) {
    Msg.push_back(static_cast<uint8_t>((BitLen >> (I * 8)) & 0xff));
  }

  std::array<uint32_t, 64> W = {};
  for (size_t Offset = 0; Offset < Msg.size(); Offset += 64) {
    for (size_t I = 0; I < 16; ++I) {
      const size_t Base = Offset + I * 4;
      W[I] = (static_cast<uint32_t>(Msg[Base]) << 24) |
             (static_cast<uint32_t>(Msg[Base + 1]) << 16) |
             (static_cast<uint32_t>(Msg[Base + 2]) << 8) |
             static_cast<uint32_t>(Msg[Base + 3]);
    }
    for (size_t I = 16; I < 64; ++I) {
      const uint32_t S0 =
          rotr32(W[I - 15], 7) ^ rotr32(W[I - 15], 18) ^ (W[I - 15] >> 3);
      const uint32_t S1 =
          rotr32(W[I - 2], 17) ^ rotr32(W[I - 2], 19) ^ (W[I - 2] >> 10);
      W[I] = W[I - 16] + S0 + W[I - 7] + S1;
    }

    uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
    uint32_t E = H[4], F = H[5], G = H[6], HH = H[7];
    for (size_t I = 0; I < 64; ++I) {
      const uint32_t S1 = rotr32(E, 6) ^ rotr32(E, 11) ^ rotr32(E, 25);
      const uint32_t Ch = (E & F) ^ ((~E) & G);
      const uint32_t Temp1 = HH + S1 + Ch + K[I] + W[I];
      const uint32_t S0 = rotr32(A, 2) ^ rotr32(A, 13) ^ rotr32(A, 22);
      const uint32_t Maj = (A & B) ^ (A & C) ^ (B & C);
      const uint32_t Temp2 = S0 + Maj;

      HH = G;
      G = F;
      F = E;
      E = D + Temp1;
      D = C;
      C = B;
      B = A;
      A = Temp1 + Temp2;
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
    H[5] += F;
    H[6] += G;
    H[7] += HH;
  }

  std::array<uint8_t, 32> Digest = {};
  for (size_t I = 0; I < H.size(); ++I) {
    Digest[I * 4] = static_cast<uint8_t>(H[I] >> 24);
    Digest[I * 4 + 1] = static_cast<uint8_t>(H[I] >> 16);
    Digest[I * 4 + 2] = static_cast<uint8_t>(H[I] >> 8);
    Digest[I * 4 + 3] = static_cast<uint8_t>(H[I]);
  }
  return Digest;
}

inline evmc::Result executeSha256(const evmc_message &Msg,
                                  std::vector<uint8_t> &ReturnData) {
  constexpr uint64_t BaseGas = 60;
  constexpr uint64_t GasPerWord = 12;
  const uint64_t InputSize = Msg.input_size;
  const uint64_t WordCount = (InputSize + 31) / 32;
  const uint64_t GasCost = BaseGas + WordCount * GasPerWord;
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint8_t *Input =
      InputSize == 0 ? nullptr : static_cast<const uint8_t *>(Msg.input_data);
  const auto Digest = sha256Digest(Input, InputSize);
  ReturnData.assign(Digest.begin(), Digest.end());
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline evmc::Result executeEcRecover(const evmc_message &Msg,
                                     std::vector<uint8_t> &ReturnData) {
  constexpr uint64_t GasCost = 3000;
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  ReturnData.clear();

  uint8_t Input[128] = {0};
  if (Msg.input_data != nullptr && Msg.input_size != 0) {
    const auto CopyLen = std::min<size_t>(sizeof(Input), Msg.input_size);
    std::memcpy(Input, Msg.input_data, CopyLen);
  }

  if (!std::all_of(Input + 32, Input + 63,
                   [](uint8_t Byte) { return Byte == 0; })) {
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  int RecoveryId = -1;
  if (Input[63] == 27 || Input[63] == 28) {
    RecoveryId = static_cast<int>(Input[63] - 27);
  } else if (Input[63] == 0 || Input[63] == 1) {
    RecoveryId = static_cast<int>(Input[63]);
  } else {
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
  using BNCTXPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
  using ECGroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
  using ECPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
  using ECKeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
  using ECDSASigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

  BNCTXPtr Ctx(BN_CTX_new(), &BN_CTX_free);
  ECGroupPtr Group(EC_GROUP_new_by_curve_name(NID_secp256k1), &EC_GROUP_free);
  if (!Ctx || !Group) {
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  BN_CTX_start(Ctx.get());
  BIGNUM *Field = BN_CTX_get(Ctx.get());
  BIGNUM *A = BN_CTX_get(Ctx.get());
  BIGNUM *B = BN_CTX_get(Ctx.get());
  BIGNUM *OrderRaw = BN_CTX_get(Ctx.get());
  BIGNUM *Zero = BN_CTX_get(Ctx.get());
  if (!Field || !A || !B || !OrderRaw || !Zero) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }
  BN_zero(Zero);

  if (EC_GROUP_get_curve(Group.get(), Field, A, B, Ctx.get()) != 1 ||
      EC_GROUP_get_order(Group.get(), OrderRaw, Ctx.get()) != 1) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  BNPtr R(BN_bin2bn(Input + 64, 32, nullptr), &BN_free);
  BNPtr S(BN_bin2bn(Input + 96, 32, nullptr), &BN_free);
  BNPtr Hash(BN_bin2bn(Input, 32, nullptr), &BN_free);
  if (!R || !S || !Hash) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }
  if (BN_is_zero(R.get()) || BN_is_zero(S.get()) ||
      BN_cmp(R.get(), OrderRaw) >= 0 || BN_cmp(S.get(), OrderRaw) >= 0) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  BNPtr X(BN_dup(R.get()), &BN_free);
  if (!X || BN_cmp(X.get(), Field) >= 0) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  std::array<uint8_t, 33> Compressed = {};
  Compressed[0] = static_cast<uint8_t>(0x02 + RecoveryId);
  if (BN_bn2binpad(X.get(), Compressed.data() + 1, 32) != 32) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  ECPointPtr RecoverPoint(EC_POINT_new(Group.get()), &EC_POINT_free);
  ECPointPtr OrderCheck(EC_POINT_new(Group.get()), &EC_POINT_free);
  ECPointPtr SR(EC_POINT_new(Group.get()), &EC_POINT_free);
  ECPointPtr MinusEG(EC_POINT_new(Group.get()), &EC_POINT_free);
  ECPointPtr Sum(EC_POINT_new(Group.get()), &EC_POINT_free);
  ECPointPtr PubKey(EC_POINT_new(Group.get()), &EC_POINT_free);
  if (!RecoverPoint || !OrderCheck || !SR || !MinusEG || !Sum || !PubKey) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  if (EC_POINT_oct2point(Group.get(), RecoverPoint.get(), Compressed.data(),
                         Compressed.size(), Ctx.get()) != 1 ||
      EC_POINT_mul(Group.get(), OrderCheck.get(), nullptr, RecoverPoint.get(),
                   OrderRaw, Ctx.get()) != 1 ||
      EC_POINT_is_at_infinity(Group.get(), OrderCheck.get()) != 1) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  BNPtr MinusHash(BN_new(), &BN_free);
  BNPtr RInv(BN_mod_inverse(nullptr, R.get(), OrderRaw, Ctx.get()), &BN_free);
  if (!MinusHash || !RInv ||
      BN_mod_sub(MinusHash.get(), Zero, Hash.get(), OrderRaw, Ctx.get()) != 1 ||
      EC_POINT_mul(Group.get(), SR.get(), nullptr, RecoverPoint.get(), S.get(),
                   Ctx.get()) != 1 ||
      EC_POINT_mul(Group.get(), MinusEG.get(), MinusHash.get(), nullptr,
                   nullptr, Ctx.get()) != 1 ||
      EC_POINT_add(Group.get(), Sum.get(), SR.get(), MinusEG.get(),
                   Ctx.get()) != 1 ||
      EC_POINT_mul(Group.get(), PubKey.get(), nullptr, Sum.get(), RInv.get(),
                   Ctx.get()) != 1) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  ECKeyPtr Key(EC_KEY_new_by_curve_name(NID_secp256k1), &EC_KEY_free);
  ECDSASigPtr Sig(ECDSA_SIG_new(), &ECDSA_SIG_free);
  if (!Key || !Sig) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }
  BNPtr SigR(BN_dup(R.get()), &BN_free);
  BNPtr SigS(BN_dup(S.get()), &BN_free);
  if (!SigR || !SigS ||
      ECDSA_SIG_set0(Sig.get(), SigR.release(), SigS.release()) != 1 ||
      EC_KEY_set_public_key(Key.get(), PubKey.get()) != 1 ||
      ECDSA_do_verify(Input, 32, Sig.get(), Key.get()) != 1) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }

  std::array<uint8_t, 65> EncodedPubKey = {};
  if (EC_POINT_point2oct(Group.get(), PubKey.get(),
                         POINT_CONVERSION_UNCOMPRESSED, EncodedPubKey.data(),
                         EncodedPubKey.size(),
                         Ctx.get()) != EncodedPubKey.size()) {
    BN_CTX_end(Ctx.get());
    return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                        nullptr, 0);
  }
  BN_CTX_end(Ctx.get());

  std::vector<uint8_t> PubKeyBytes(EncodedPubKey.begin() + 1,
                                   EncodedPubKey.end());
  const auto HashBytes = zen::host::evm::crypto::keccak256(PubKeyBytes);
  ReturnData.assign(32, 0);
  std::memcpy(ReturnData.data() + 12, HashBytes.data() + 12, 20);
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline bool ensureBn254Initialized() noexcept {
  static const bool Initialized = []() {
    const int Ret = mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR);
    if (Ret != 0) {
      return false;
    }
    mclBn_verifyOrderG1(0);
    mclBn_verifyOrderG2(1);
    return true;
  }();
  return Initialized;
}

inline uint64_t bn256AddGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 150 : 500;
}

inline uint64_t bn256MulGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 6000 : 40000;
}

inline uint64_t bn256PairingBaseGas(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 45000 : 100000;
}

inline uint64_t bn256PairingPerPairGas(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 34000 : 80000;
}

inline bool isAllZero(const uint8_t *Data, size_t Size) noexcept {
  for (size_t I = 0; I < Size; ++I) {
    if (Data[I] != 0) {
      return false;
    }
  }
  return true;
}

inline void copyPaddedInput(std::vector<uint8_t> &Dst, const evmc_message &Msg,
                            size_t Size) {
  Dst.assign(Size, 0);
  if (Msg.input_data == nullptr || Msg.input_size == 0) {
    return;
  }
  const size_t CopyLen = std::min<size_t>(Size, Msg.input_size);
  std::memcpy(Dst.data(), Msg.input_data, CopyLen);
}

inline bool bn254DeserializeFp(mclBnFp *X, const uint8_t *Buf) noexcept {
  return mclBnFp_setStr(X, reinterpret_cast<const char *>(Buf), 32,
                        MCLBN_IO_SERIALIZE | MCLBN_IO_BIG_ENDIAN) == 0;
}

inline bool bn254SerializeFp(uint8_t *Buf, const mclBnFp *X) noexcept {
  return mclBnFp_getStr(reinterpret_cast<char *>(Buf), 32, X,
                        MCLBN_IO_SERIALIZE | MCLBN_IO_BIG_ENDIAN) == 32;
}

inline bool bn254DeserializeG1(mclBnG1 *P, const uint8_t *Buf) noexcept {
  if (isAllZero(Buf, 64)) {
    mclBnG1_clear(P);
    return true;
  }
  if (!bn254DeserializeFp(&P->x, Buf) || !bn254DeserializeFp(&P->y, Buf + 32)) {
    return false;
  }
  mclBnFp_setInt32(&P->z, 1);
  return mclBnG1_isValid(P) == 1;
}

inline bool bn254SerializeG1(uint8_t *Buf, mclBnG1 *P) noexcept {
  if (mclBnG1_isZero(P)) {
    std::memset(Buf, 0, 64);
    return true;
  }
  mclBnG1_normalize(P, P);
  return bn254SerializeFp(Buf, &P->x) && bn254SerializeFp(Buf + 32, &P->y);
}

inline bool bn254DeserializeFp2(mclBnFp2 *X, const uint8_t *Buf) noexcept {
  return bn254DeserializeFp(&X->d[1], Buf) &&
         bn254DeserializeFp(&X->d[0], Buf + 32);
}

inline bool bn254DeserializeG2(mclBnG2 *P, const uint8_t *Buf) noexcept {
  if (isAllZero(Buf, 128)) {
    mclBnG2_clear(P);
    return true;
  }
  if (!bn254DeserializeFp2(&P->x, Buf) ||
      !bn254DeserializeFp2(&P->y, Buf + 64)) {
    return false;
  }
  mclBnFp_setInt32(&P->z.d[0], 1);
  mclBnFp_clear(&P->z.d[1]);
  return mclBnG2_isValid(P) == 1;
}

inline bool bn254SerializeG2(uint8_t *Buf, mclBnG2 *P) noexcept {
  if (mclBnG2_isZero(P)) {
    std::memset(Buf, 0, 128);
    return true;
  }
  mclBnG2_normalize(P, P);
  return bn254SerializeFp(Buf, &P->x.d[1]) &&
         bn254SerializeFp(Buf + 32, &P->x.d[0]) &&
         bn254SerializeFp(Buf + 64, &P->y.d[1]) &&
         bn254SerializeFp(Buf + 96, &P->y.d[0]);
}

inline bool bn254SerializePairingResult(uint8_t *Buf, bool Success) noexcept {
  std::memset(Buf, 0, 32);
  if (Success) {
    Buf[31] = 1;
  }
  return true;
}

inline evmc::Result executeRipemd160(const evmc_message &Msg,
                                     std::vector<uint8_t> &ReturnData) {
  constexpr uint64_t BaseGas = 600;
  constexpr uint64_t GasPerWord = 120;
  const uint64_t InputSize = Msg.input_size;
  const uint64_t WordCount = (InputSize + 31) / 32;
  const uint64_t GasCost = BaseGas + WordCount * GasPerWord;
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint8_t *Input =
      InputSize == 0 ? nullptr : static_cast<const uint8_t *>(Msg.input_data);
  unsigned char Digest[RIPEMD160_DIGEST_LENGTH];
  RIPEMD160(Input, InputSize, Digest);
  ReturnData.assign(32, 0);
  std::memcpy(ReturnData.data() + 12, Digest, RIPEMD160_DIGEST_LENGTH);
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline evmc::Result executeBn256Add(const evmc_message &Msg,
                                    evmc_revision Revision,
                                    std::vector<uint8_t> &ReturnData) {
  const uint64_t GasCost = bn256AddGasCost(Revision);
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas || !ensureBn254Initialized()) {
    ReturnData.clear();
    return evmc::Result(GasCost > MsgGas ? EVMC_OUT_OF_GAS : EVMC_FAILURE, 0, 0,
                        nullptr, 0);
  }

  std::vector<uint8_t> Input;
  copyPaddedInput(Input, Msg, 128);

  mclBnG1 P1, P2, Sum;
  if (!bn254DeserializeG1(&P1, Input.data()) ||
      !bn254DeserializeG1(&P2, Input.data() + 64)) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  mclBnG1_add(&Sum, &P1, &P2);
  ReturnData.assign(64, 0);
  if (!bn254SerializeG1(ReturnData.data(), &Sum)) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline evmc::Result executeBn256Mul(const evmc_message &Msg,
                                    evmc_revision Revision,
                                    std::vector<uint8_t> &ReturnData) {
  const uint64_t GasCost = bn256MulGasCost(Revision);
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas || !ensureBn254Initialized()) {
    ReturnData.clear();
    return evmc::Result(GasCost > MsgGas ? EVMC_OUT_OF_GAS : EVMC_FAILURE, 0, 0,
                        nullptr, 0);
  }

  std::vector<uint8_t> Input;
  copyPaddedInput(Input, Msg, 96);

  mclBnG1 Point, Product;
  mclBnFr Scalar;
  if (!bn254DeserializeG1(&Point, Input.data()) ||
      mclBnFr_setBigEndianMod(&Scalar, Input.data() + 64, 32) != 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  mclBnG1_mul(&Product, &Point, &Scalar);
  ReturnData.assign(64, 0);
  if (!bn254SerializeG1(ReturnData.data(), &Product)) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline evmc::Result executeBn256Pairing(const evmc_message &Msg,
                                        evmc_revision Revision,
                                        std::vector<uint8_t> &ReturnData) {
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (!ensureBn254Initialized()) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  if ((Msg.input_size % 192) != 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  const uint64_t PairCount = Msg.input_size / 192;
  const uint64_t GasCost = bn256PairingBaseGas(Revision) +
                           PairCount * bn256PairingPerPairGas(Revision);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  mclBnGT Acc;
  mclBnGT_setInt32(&Acc, 1);
  const uint8_t *Input = static_cast<const uint8_t *>(Msg.input_data);
  for (uint64_t I = 0; I < PairCount; ++I) {
    const uint8_t *Chunk = Input + I * 192;
    mclBnG1 P;
    mclBnG2 Q;
    if (!bn254DeserializeG1(&P, Chunk) || !bn254DeserializeG2(&Q, Chunk + 64)) {
      ReturnData.clear();
      return evmc::Result(EVMC_FAILURE, 0, 0, nullptr, 0);
    }
    mclBnGT Pairing;
    mclBn_pairing(&Pairing, &P, &Q);
    mclBnGT_mul(&Acc, &Acc, &Pairing);
  }

  ReturnData.assign(32, 0);
  bn254SerializePairingResult(ReturnData.data(), mclBnGT_isOne(&Acc) == 1);
  return evmc::Result(EVMC_SUCCESS, static_cast<int64_t>(MsgGas - GasCost), 0,
                      ReturnData.data(), ReturnData.size());
}

inline intx::uint256 loadUint256Padded(const uint8_t *Data, size_t Size,
                                       size_t Offset) noexcept {
  uint8_t Buffer[32] = {0};
  if (Offset < Size) {
    size_t CopyLen = std::min<size_t>(32, Size - Offset);
    std::memcpy(Buffer, Data + Offset, CopyLen);
  }
  return intx::be::load<intx::uint256>(Buffer);
}

inline uint64_t toUint64Clamped(const intx::uint256 &Value,
                                bool &Overflow) noexcept {
  if (Value > std::numeric_limits<uint64_t>::max()) {
    Overflow = true;
    return std::numeric_limits<uint64_t>::max();
  }
  return static_cast<uint64_t>(Value);
}

inline uint64_t bitLength(const intx::uint256 &Value) noexcept {
  if (Value == 0) {
    return 0;
  }
  uint8_t Bytes[32];
  intx::be::store(Bytes, Value);
  for (size_t I = 0; I < 32; ++I) {
    if (Bytes[I] == 0) {
      continue;
    }
    const unsigned MsBit = 31U - static_cast<unsigned>(__builtin_clz(Bytes[I]));
    return static_cast<uint64_t>((31 - I) * 8 + MsBit + 1);
  }
  return 0;
}

inline uint64_t adjustedExponentLength(uint64_t ExpLen,
                                       const intx::uint256 &ExpHead) noexcept {
  const uint64_t HeadBits = bitLength(ExpHead);
  if (ExpLen <= 32) {
    return HeadBits == 0 ? 0 : (HeadBits - 1);
  }
  const uint64_t HeadIndex = HeadBits == 0 ? 0 : (HeadBits - 1);
  const unsigned __int128 Raw =
      (static_cast<unsigned __int128>(ExpLen) - 32) * 8u;
  const unsigned __int128 Adjusted = Raw + HeadIndex;
  const unsigned __int128 Max = std::numeric_limits<uint64_t>::max();
  return Adjusted > Max ? std::numeric_limits<uint64_t>::max()
                        : static_cast<uint64_t>(Adjusted);
}

inline boost::multiprecision::cpp_int
multComplexityEIP198(uint64_t MaxLen) noexcept {
  using boost::multiprecision::cpp_int;
  const cpp_int X(MaxLen);
  if (MaxLen <= 64) {
    return X * X;
  }
  if (MaxLen <= 1024) {
    return X * X / 4 + cpp_int(96) * MaxLen - 3072;
  }
  return X * X / 16 + cpp_int(480) * MaxLen - 199680;
}

inline boost::multiprecision::cpp_int
multComplexityEIP2565(uint64_t MaxLen) noexcept {
  using boost::multiprecision::cpp_int;
  const uint64_t Words = (MaxLen + 7) / 8;
  const cpp_int W(Words);
  return W * W;
}

inline bool toUint64(const boost::multiprecision::cpp_int &Value,
                     uint64_t &Out) noexcept {
  if (Value < 0 || Value > boost::multiprecision::cpp_int(
                               std::numeric_limits<uint64_t>::max())) {
    return false;
  }
  Out = static_cast<uint64_t>(Value);
  return true;
}

inline std::vector<uint8_t> readSegment(const uint8_t *Data, size_t Size,
                                        uint64_t Offset, uint64_t Length) {
  std::vector<uint8_t> Segment(static_cast<size_t>(Length), 0);
  if (Length == 0) {
    return Segment;
  }
  if (Offset > std::numeric_limits<size_t>::max()) {
    return Segment;
  }
  size_t SafeOffset = static_cast<size_t>(Offset);
  if (SafeOffset >= Size) {
    return Segment;
  }
  size_t CopyLen = std::min<size_t>(Segment.size(), Size - SafeOffset);
  std::memcpy(Segment.data(), Data + SafeOffset, CopyLen);
  return Segment;
}

inline uint32_t loadUint32BE(const uint8_t *Data) noexcept {
  return (static_cast<uint32_t>(Data[0]) << 24) |
         (static_cast<uint32_t>(Data[1]) << 16) |
         (static_cast<uint32_t>(Data[2]) << 8) | static_cast<uint32_t>(Data[3]);
}

inline uint64_t loadUint64LE(const uint8_t *Data) noexcept {
  uint64_t Value = 0;
  for (size_t I = 0; I < 8; ++I) {
    Value |= static_cast<uint64_t>(Data[I]) << (8 * I);
  }
  return Value;
}

inline void storeUint64LE(uint64_t Value, uint8_t *Out) noexcept {
  for (size_t I = 0; I < 8; ++I) {
    Out[I] = static_cast<uint8_t>((Value >> (8 * I)) & 0xff);
  }
}

inline uint64_t rotr64(uint64_t Value, unsigned Shift) noexcept {
  return (Value >> Shift) | (Value << (64 - Shift));
}

inline void blake2bG(uint64_t &A, uint64_t &B, uint64_t &C, uint64_t &D,
                     uint64_t X, uint64_t Y) noexcept {
  A = A + B + X;
  D = rotr64(D ^ A, 32);
  C = C + D;
  B = rotr64(B ^ C, 24);
  A = A + B + Y;
  D = rotr64(D ^ A, 16);
  C = C + D;
  B = rotr64(B ^ C, 63);
}

inline void blake2bCompress(uint64_t H[8], const uint64_t M[16], uint64_t T0,
                            uint64_t T1, bool FinalBlock,
                            uint32_t Rounds) noexcept {
  static constexpr std::array<uint64_t, 8> IV = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
      0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
      0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
  static constexpr uint8_t Sigma[10][16] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
      {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
      {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
      {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
      {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

  uint64_t V[16];
  for (size_t I = 0; I < 8; ++I) {
    V[I] = H[I];
    V[I + 8] = IV[I];
  }
  V[12] ^= T0;
  V[13] ^= T1;
  if (FinalBlock) {
    V[14] = ~V[14];
  }

  for (uint32_t R = 0; R < Rounds; ++R) {
    const uint8_t *S = Sigma[R % 10];
    blake2bG(V[0], V[4], V[8], V[12], M[S[0]], M[S[1]]);
    blake2bG(V[1], V[5], V[9], V[13], M[S[2]], M[S[3]]);
    blake2bG(V[2], V[6], V[10], V[14], M[S[4]], M[S[5]]);
    blake2bG(V[3], V[7], V[11], V[15], M[S[6]], M[S[7]]);
    blake2bG(V[0], V[5], V[10], V[15], M[S[8]], M[S[9]]);
    blake2bG(V[1], V[6], V[11], V[12], M[S[10]], M[S[11]]);
    blake2bG(V[2], V[7], V[8], V[13], M[S[12]], M[S[13]]);
    blake2bG(V[3], V[4], V[9], V[14], M[S[14]], M[S[15]]);
  }

  for (size_t I = 0; I < 8; ++I) {
    H[I] ^= V[I] ^ V[I + 8];
  }
}

inline evmc::Result executeModExp(const evmc_message &Msg,
                                  evmc_revision Revision,
                                  std::vector<uint8_t> &ReturnData) {
  const uint8_t *Input = Msg.input_size == 0
                             ? nullptr
                             : static_cast<const uint8_t *>(Msg.input_data);
  const size_t InputSize = Msg.input_size;

  bool LengthOverflow = false;
  const uint64_t BaseLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 0), LengthOverflow);
  const uint64_t ExpLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 32), LengthOverflow);
  const uint64_t ModLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 64), LengthOverflow);
  if (LengthOverflow) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint64_t MaxLen = std::max(BaseLen, ModLen);
  constexpr uint64_t BaseOffset = 96;
  if (BaseLen > std::numeric_limits<uint64_t>::max() - BaseOffset) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const uint64_t ExpOffset = BaseOffset + BaseLen;
  if (ExpLen > std::numeric_limits<uint64_t>::max() - ExpOffset) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const uint64_t ModOffset = ExpOffset + ExpLen;

  std::array<uint8_t, 32> ExpHeadBytes{};
  if (ExpLen != 0 && Input != nullptr && ExpOffset < InputSize) {
    const uint64_t HeadLen = std::min<uint64_t>(ExpLen, 32);
    auto Head = readSegment(Input, InputSize, ExpOffset, HeadLen);
    if (!Head.empty()) {
      std::memcpy(ExpHeadBytes.data() + (ExpHeadBytes.size() - Head.size()),
                  Head.data(), Head.size());
    }
  }
  intx::uint256 ExpHead = 0;
  for (auto B : ExpHeadBytes) {
    ExpHead = (ExpHead << 8) | static_cast<uint64_t>(B);
  }
  const uint64_t AdjustedExpLen = adjustedExponentLength(ExpLen, ExpHead);
  const uint64_t IterationCount = std::max<uint64_t>(AdjustedExpLen, 1);

  using boost::multiprecision::cpp_int;
  cpp_int GasCost = 0;
  if (Revision >= EVMC_BERLIN) {
    GasCost =
        multComplexityEIP2565(MaxLen) * cpp_int(IterationCount) / cpp_int(3);
    if (GasCost < 200) {
      GasCost = 200;
    }
  } else {
    GasCost =
        multComplexityEIP198(MaxLen) * cpp_int(IterationCount) / cpp_int(20);
    GasCost += cpp_int(LegacyModExpBaseGas);
  }

  uint64_t GasCost64 = 0;
  if (!toUint64(GasCost, GasCost64)) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost64 > MsgGas) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost64);

  if (ModLen == 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_SUCCESS, GasLeft, 0, nullptr, 0);
  }

  auto BaseBytes = readSegment(Input, InputSize, BaseOffset, BaseLen);
  auto ExpBytes = readSegment(Input, InputSize, ExpOffset, ExpLen);
  auto ModBytes = readSegment(Input, InputSize, ModOffset, ModLen);

  cpp_int BaseInt = 0;
  cpp_int ExpInt = 0;
  cpp_int ModInt = 0;

  if (!BaseBytes.empty()) {
    boost::multiprecision::import_bits(BaseInt, BaseBytes.begin(),
                                       BaseBytes.end(), 8);
  }
  if (!ExpBytes.empty()) {
    boost::multiprecision::import_bits(ExpInt, ExpBytes.begin(), ExpBytes.end(),
                                       8);
  }
  if (!ModBytes.empty()) {
    boost::multiprecision::import_bits(ModInt, ModBytes.begin(), ModBytes.end(),
                                       8);
  }

  std::vector<uint8_t> Output(static_cast<size_t>(ModLen), 0);
  if (ModInt != 0) {
    BaseInt %= ModInt;
    cpp_int Result = boost::multiprecision::powm(BaseInt, ExpInt, ModInt);
    std::vector<uint8_t> Tmp;
    boost::multiprecision::export_bits(Result, std::back_inserter(Tmp), 8);
    if (Tmp.size() > Output.size()) {
      std::copy(Tmp.end() - Output.size(), Tmp.end(), Output.begin());
    } else if (!Tmp.empty()) {
      std::copy(Tmp.begin(), Tmp.end(),
                Output.begin() + (Output.size() - Tmp.size()));
    }
  }
  ReturnData = std::move(Output);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0,
                      ReturnData.empty() ? nullptr : ReturnData.data(),
                      ReturnData.size());
}

inline evmc::Result executeBlake2b(const evmc_message &Msg,
                                   std::vector<uint8_t> &ReturnData) {
  constexpr size_t InputSize = 213;
  constexpr uint64_t GasPerRound = 1;
  const uint8_t *Input = Msg.input_size == 0
                             ? nullptr
                             : static_cast<const uint8_t *>(Msg.input_data);

  if (Input == nullptr || Msg.input_size != InputSize) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint8_t FinalFlag = Input[InputSize - 1];
  if (FinalFlag != 0 && FinalFlag != 1) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint32_t Rounds = loadUint32BE(Input);
  const uint64_t GasCost = GasPerRound * static_cast<uint64_t>(Rounds);
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  uint64_t H[8];
  uint64_t M[16];
  constexpr size_t HOffset = 4;
  constexpr size_t MOffset = HOffset + 64;
  constexpr size_t T0Offset = MOffset + 128;
  constexpr size_t T1Offset = T0Offset + 8;
  for (size_t I = 0; I < 8; ++I) {
    H[I] = loadUint64LE(Input + HOffset + I * 8);
  }
  for (size_t I = 0; I < 16; ++I) {
    M[I] = loadUint64LE(Input + MOffset + I * 8);
  }
  const uint64_t T0 = loadUint64LE(Input + T0Offset);
  const uint64_t T1 = loadUint64LE(Input + T1Offset);

  blake2bCompress(H, M, T0, T1, FinalFlag != 0, Rounds);

  ReturnData.assign(64, 0);
  for (size_t I = 0; I < 8; ++I) {
    storeUint64LE(H[I], ReturnData.data() + I * 8);
  }

  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0, ReturnData.data(),
                      ReturnData.size());
}

} // namespace zen::evm::precompile

#endif // ZEN_TESTS_EVM_PRECOMPILES_HPP
