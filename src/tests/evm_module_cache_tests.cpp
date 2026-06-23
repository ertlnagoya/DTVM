// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Regression: L1 EVMC module cache must not treat bytecode as equal from
/// matching head/tail only. Two contracts of length 600 with identical first
/// 256 and last 256 bytes but a differing middle must load separately and
/// produce different results.

#include "vm/dt_evmc_vm.h"
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>

using evmc::operator""_address;
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

namespace {

constexpr size_t kTotalCodeSize = 600;
constexpr size_t kTailStart = 344; // last 256 bytes are [344, 600)

std::vector<uint8_t> buildBytecode(uint8_t PushByte) {
  std::vector<uint8_t> Code(kTotalCodeSize, 0);
  // Prefix: 252x JUMPDEST, PUSH2(257), JUMP — lands at offset 257.
  for (size_t i = 0; i < 252; ++i) {
    Code[i] = 0x5b;
  }
  Code[252] = 0x61; // PUSH2
  Code[253] = 0x01;
  Code[254] = 0x01; // 257 big-endian
  Code[255] = 0x56; // JUMP
  // Byte 256: unreachable padding (middle region)
  Code[256] = 0x00;
  // At 257: JUMPDEST, PUSH1 v, PUSH1 0, MSTORE, PUSH1 1, PUSH1 31, RETURN
  size_t o = 257;
  Code[o++] = 0x5b; // JUMPDEST
  Code[o++] = 0x60; // PUSH1
  Code[o++] = PushByte;
  Code[o++] = 0x60;
  Code[o++] = 0x00;
  Code[o++] = 0x52; // MSTORE
  Code[o++] = 0x60;
  Code[o++] = 0x01;
  Code[o++] = 0x60;
  Code[o++] = 0x1f;
  Code[o++] = 0xf3; // RETURN (1 byte at mem offset 31)
  // Pad middle [268, 344) — must match between variants for this test layout
  while (o < kTailStart) {
    Code[o++] = 0x00;
  }
  // Tail [344, 600) already zero; identical across both contracts
  return Code;
}

void releaseResult(evmc_result &R) {
  if (R.release) {
    R.release(&R);
  }
}

} // namespace

class EVMModuleCacheTest : public ::testing::Test {
protected:
  void SetUp() override {
    Vm = evmc_create_dtvmapi();
    ASSERT_NE(Vm, nullptr);
    if (Vm->set_option) {
      ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
                Vm->set_option(Vm, "mode", "interpreter"));
    }
    Host = std::make_unique<evmc::MockedHost>();
  }

  void TearDown() override {
    if (Vm) {
      Vm->destroy(Vm);
      Vm = nullptr;
    }
  }

  evmc_result executeAtAddress(const std::vector<uint8_t> &Bytecode,
                               const evmc::address &CodeAddr) {
    evmc_message Msg{};
    Msg.kind = EVMC_CALL;
    Msg.depth = 0;
    Msg.gas = 1'000'000;
    Msg.code_address = CodeAddr;
    Msg.recipient = CodeAddr;
    Msg.code = Bytecode.data();
    Msg.code_size = Bytecode.size();

    return Vm->execute(Vm, &evmc::MockedHost::get_interface(),
                       reinterpret_cast<evmc_host_context *>(Host.get()),
                       EVMC_LATEST_STABLE_REVISION, &Msg, Bytecode.data(),
                       Bytecode.size());
  }

  struct evmc_vm *Vm = nullptr;
  std::unique_ptr<evmc::MockedHost> Host;
};

TEST_F(EVMModuleCacheTest, AddrCacheRequiresFullBytecodeMatch) {
  std::vector<uint8_t> A = buildBytecode(0x2a);
  std::vector<uint8_t> B = buildBytecode(0x3b);
  ASSERT_EQ(A.size(), B.size());
  ASSERT_EQ(A.size(), kTotalCodeSize);
  ASSERT_EQ(std::memcmp(A.data(), B.data(), 256), 0);
  ASSERT_EQ(std::memcmp(A.data() + kTailStart, B.data() + kTailStart,
                        kTotalCodeSize - kTailStart),
            0);
  ASSERT_NE(std::memcmp(A.data(), B.data(), A.size()), 0);

  const evmc::address Addr = 0x000000000000000000000000000000000000c001_address;

  evmc_result Ra = executeAtAddress(A, Addr);
  ASSERT_EQ(Ra.status_code, EVMC_SUCCESS);
  ASSERT_EQ(Ra.output_size, 1U);
  ASSERT_NE(Ra.output_data, nullptr);
  EXPECT_EQ(Ra.output_data[0], 0x2a);
  releaseResult(Ra);

  evmc_result Rb = executeAtAddress(B, Addr);
  ASSERT_EQ(Rb.status_code, EVMC_SUCCESS);
  ASSERT_EQ(Rb.output_size, 1U);
  ASSERT_NE(Rb.output_data, nullptr);
  EXPECT_EQ(Rb.output_data[0], 0x3b);
  releaseResult(Rb);
}
