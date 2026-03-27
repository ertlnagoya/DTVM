// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm.h"
#include "evm_test_host.hpp"
#include "host/evm/crypto.h"
#include "utils/evm.h"

#include <gtest/gtest.h>
#include <intx/intx.hpp>
#include <optional>

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using namespace zen::utils;

namespace {

constexpr uint8_t CLEAR_SLOT_RUNTIME[] = {
    0x60, 0x00, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x01, 0x55, 0x00};

intx::uint256 toUint256(const evmc::uint256be &Value) {
  return intx::be::load<intx::uint256>(Value.bytes);
}

evmc::bytes32 toBytes32(const intx::uint256 &Value) {
  return intx::be::store<evmc::bytes32>(Value);
}

struct GasSettlementObservation {
  ZenMockedEVMHost::TransactionExecutionResult Result;
  intx::uint256 SenderBalance;
  intx::uint256 CoinbaseBalance;
};

GasSettlementObservation
runGasSettlementScenario(evmc_revision Revision, const intx::uint256 &GasPrice,
                         const intx::uint256 &BaseFee = intx::uint256(0),
                         const std::optional<intx::uint256> &MaxPriorityFee =
                             std::nullopt,
                         const std::optional<intx::uint256> &BlobBaseFee =
                             std::nullopt,
                         const std::optional<intx::uint256> &MaxFeePerBlobGas =
                             std::nullopt,
                         size_t BlobHashesCount = 0) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  if (!RT) {
    ADD_FAILURE() << "Failed to create EVM runtime";
    return {};
  }
  Host->setRuntime(RT.get());

  const evmc::address Sender =
      evmc::literals::operator""_address(
          "1000000000000000000000000000000000000001");
  const evmc::address Contract =
      evmc::literals::operator""_address(
          "2000000000000000000000000000000000000002");
  const evmc::address Coinbase =
      evmc::literals::operator""_address(
          "3000000000000000000000000000000000000003");
  const evmc::bytes32 SlotKey0 = parseBytes32("0x00");
  const evmc::bytes32 SlotKey1 = parseBytes32("0x01");
  const intx::uint256 InitialSenderBalance = intx::uint256(1000000000);
  const intx::uint256 InitialCoinbaseBalance = intx::uint256(0);

  evmc_tx_context TxContext{};
  TxContext.block_coinbase = Coinbase;
  TxContext.tx_gas_price = toBytes32(GasPrice);
  TxContext.block_base_fee = toBytes32(BaseFee);
  std::vector<evmc::bytes32> BlobHashes;
  if (BlobHashesCount > 0) {
    BlobHashes.resize(BlobHashesCount);
    for (size_t I = 0; I < BlobHashesCount; ++I) {
      BlobHashes[I].bytes[31] = static_cast<uint8_t>(I + 1);
    }
    TxContext.blob_hashes = BlobHashes.data();
    TxContext.blob_hashes_count = BlobHashes.size();
  }
  if (BlobBaseFee.has_value()) {
    TxContext.blob_base_fee = toBytes32(*BlobBaseFee);
  }

  evmc::MockedAccount SenderAccount;
  SenderAccount.balance = toBytes32(InitialSenderBalance);
  SenderAccount.nonce = 0;

  evmc::MockedAccount ContractAccount;
  ContractAccount.balance = toBytes32(0);
  ContractAccount.nonce = 1;
  ContractAccount.code.assign(std::begin(CLEAR_SLOT_RUNTIME),
                              std::end(CLEAR_SLOT_RUNTIME));
  ContractAccount.storage[SlotKey0] =
      evmc::StorageValue{parseBytes32("0x01")};
  ContractAccount.storage[SlotKey1] =
      evmc::StorageValue{parseBytes32("0x01")};
  const std::vector<uint8_t> ContractCodeVec(ContractAccount.code.begin(),
                                             ContractAccount.code.end());
  const std::vector<uint8_t> CodeHash =
      zen::host::evm::crypto::keccak256(ContractCodeVec);
  std::memcpy(ContractAccount.codehash.bytes, CodeHash.data(), 32);

  evmc::MockedAccount CoinbaseAccount;
  CoinbaseAccount.balance = toBytes32(InitialCoinbaseBalance);

  std::vector<ZenMockedEVMHost::AccountInitEntry> Accounts;
  Accounts.push_back({Sender, SenderAccount});
  Accounts.push_back({Contract, ContractAccount});
  Accounts.push_back({Coinbase, CoinbaseAccount});
  Host->loadInitialState(TxContext, Accounts, true);

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 50000;
  Msg.sender = Sender;
  Msg.recipient = Contract;

  ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "refund_cap_host_test";
  ExecConfig.Bytecode = ContractAccount.code.data();
  ExecConfig.BytecodeSize = ContractAccount.code.size();
  ExecConfig.Message = Msg;
  ExecConfig.GasLimit = 50000;
  ExecConfig.IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
  ExecConfig.Revision = Revision;
  if (MaxPriorityFee.has_value()) {
    ExecConfig.MaxPriorityFeePerGas = toBytes32(*MaxPriorityFee);
  }
  if (MaxFeePerBlobGas.has_value()) {
    ExecConfig.MaxFeePerBlobGas = toBytes32(*MaxFeePerBlobGas);
  }

  auto Result = Host->executeTransaction(ExecConfig);
  if (!Result.Success || Result.Status != EVMC_SUCCESS) {
    ADD_FAILURE() << "Host execution failed: success=" << Result.Success
                  << " status=" << evmc::to_string(Result.Status)
                  << " error=" << Result.ErrorMessage;
    return {};
  }

  auto SenderIt = Host->accounts.find(Sender);
  if (SenderIt == Host->accounts.end()) {
    ADD_FAILURE() << "Sender account missing after execution";
    return {};
  }
  auto CoinbaseIt = Host->accounts.find(Coinbase);
  if (CoinbaseIt == Host->accounts.end()) {
    ADD_FAILURE() << "Coinbase account missing after execution";
    return {};
  }
  auto ContractIt = Host->accounts.find(Contract);
  if (ContractIt == Host->accounts.end()) {
    ADD_FAILURE() << "Contract account missing after execution";
    return {};
  }

  auto StorageIt0 = ContractIt->second.storage.find(SlotKey0);
  if (StorageIt0 == ContractIt->second.storage.end()) {
    ADD_FAILURE() << "Contract storage slot 0 missing after execution";
    return {};
  }
  auto StorageIt1 = ContractIt->second.storage.find(SlotKey1);
  if (StorageIt1 == ContractIt->second.storage.end()) {
    ADD_FAILURE() << "Contract storage slot 1 missing after execution";
    return {};
  }
  EXPECT_EQ(StorageIt0->second.current.bytes[31], 0);
  EXPECT_EQ(StorageIt1->second.current.bytes[31], 0);

  return {Result, toUint256(SenderIt->second.balance),
          toUint256(CoinbaseIt->second.balance)};
}

GasSettlementObservation runRefundCapScenario(evmc_revision Revision) {
  return runGasSettlementScenario(Revision, intx::uint256(10));
}

} // namespace

TEST(EVMHostGasSettlement, RefundCapDependsOnRevision) {
  auto Berlin = runRefundCapScenario(EVMC_BERLIN);
  auto London = runRefundCapScenario(EVMC_LONDON);

  EXPECT_EQ(Berlin.Result.GasRefund, Berlin.Result.GasUsed / 2);
  EXPECT_EQ(London.Result.GasRefund, London.Result.GasUsed / 5);
  EXPECT_GT(Berlin.Result.GasRefund, London.Result.GasRefund);
  EXPECT_LT(Berlin.Result.GasCharged, London.Result.GasCharged);
}

TEST(EVMHostGasSettlement, GasSettlementTracksChargedGasInBalances) {
  auto Berlin = runRefundCapScenario(EVMC_BERLIN);
  const intx::uint256 GasPrice = intx::uint256(10);
  const intx::uint256 InitialSenderBalance = intx::uint256(1000000000);

  const intx::uint256 ExpectedSenderBalance =
      InitialSenderBalance - intx::uint256(Berlin.Result.GasCharged) * GasPrice;
  const intx::uint256 ExpectedCoinbaseBalance =
      intx::uint256(Berlin.Result.GasCharged) * GasPrice;

  EXPECT_EQ(Berlin.SenderBalance, ExpectedSenderBalance);
  EXPECT_EQ(Berlin.CoinbaseBalance, ExpectedCoinbaseBalance);
}

TEST(EVMHostGasSettlement, Eip1559SettlementSplitsBaseFeeAndPriorityFee) {
  const intx::uint256 MaxFeePerGas = intx::uint256(15);
  const intx::uint256 BaseFee = intx::uint256(7);
  const intx::uint256 MaxPriorityFeePerGas = intx::uint256(3);
  const intx::uint256 InitialSenderBalance = intx::uint256(1000000000);

  auto London = runGasSettlementScenario(EVMC_LONDON, MaxFeePerGas, BaseFee,
                                         MaxPriorityFeePerGas);

  const intx::uint256 EffectiveGasPrice = BaseFee + MaxPriorityFeePerGas;
  const intx::uint256 ExpectedSenderBalance =
      InitialSenderBalance -
      intx::uint256(London.Result.GasCharged) * EffectiveGasPrice;
  const intx::uint256 ExpectedCoinbaseBalance =
      intx::uint256(London.Result.GasCharged) * MaxPriorityFeePerGas;

  EXPECT_EQ(London.SenderBalance, ExpectedSenderBalance);
  EXPECT_EQ(London.CoinbaseBalance, ExpectedCoinbaseBalance);
}

TEST(EVMHostGasSettlement, CancunBlobFeeIsChargedToSenderOnly) {
  const intx::uint256 MaxFeePerGas = intx::uint256(15);
  const intx::uint256 BaseFee = intx::uint256(7);
  const intx::uint256 MaxPriorityFeePerGas = intx::uint256(3);
  const intx::uint256 BlobBaseFee = intx::uint256(5);
  const intx::uint256 MaxFeePerBlobGas = intx::uint256(9);
  const intx::uint256 InitialSenderBalance = intx::uint256(1000000000);
  constexpr uint64_t BlobGasPerBlob = 131072;
  constexpr size_t BlobCount = 2;

  auto Cancun = runGasSettlementScenario(EVMC_CANCUN, MaxFeePerGas, BaseFee,
                                         MaxPriorityFeePerGas, BlobBaseFee,
                                         MaxFeePerBlobGas, BlobCount);

  const intx::uint256 EffectiveGasPrice = BaseFee + MaxPriorityFeePerGas;
  const intx::uint256 BlobFee =
      intx::uint256(BlobGasPerBlob) * intx::uint256(BlobCount) * BlobBaseFee;
  const intx::uint256 ExpectedSenderBalance =
      InitialSenderBalance -
      intx::uint256(Cancun.Result.GasCharged) * EffectiveGasPrice - BlobFee;
  const intx::uint256 ExpectedCoinbaseBalance =
      intx::uint256(Cancun.Result.GasCharged) * MaxPriorityFeePerGas;

  EXPECT_EQ(Cancun.SenderBalance, ExpectedSenderBalance);
  EXPECT_EQ(Cancun.CoinbaseBalance, ExpectedCoinbaseBalance);
}

TEST(EVMHostGasSettlement, PragueAuthorizationListAppliesDelegationState) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT != nullptr);
  Host->setRuntime(RT.get());

  const evmc::address Sender =
      evmc::literals::operator""_address(
          "1000000000000000000000000000000000000001");
  const evmc::address Contract =
      evmc::literals::operator""_address(
          "2000000000000000000000000000000000000002");
  const evmc::address Signer =
      evmc::literals::operator""_address(
          "3000000000000000000000000000000000000003");
  const evmc::address DelegateTarget =
      evmc::literals::operator""_address(
          "4000000000000000000000000000000000000004");

  evmc_tx_context TxContext{};
  TxContext.chain_id = parseUint256("0x01");
  TxContext.tx_gas_price = parseUint256("0x32");

  evmc::MockedAccount SenderAccount;
  SenderAccount.balance = parseUint256("0x0de0b6b3a7640000");

  evmc::MockedAccount ContractAccount;
  ContractAccount.nonce = 1;
  ContractAccount.code = evmc::bytes(1, '\0');
  const std::vector<uint8_t> ContractCode(ContractAccount.code.begin(),
                                          ContractAccount.code.end());
  const auto ContractCodeHash = zen::host::evm::crypto::keccak256(ContractCode);
  std::memcpy(ContractAccount.codehash.bytes, ContractCodeHash.data(), 32);

  evmc::MockedAccount SignerAccount;
  SignerAccount.balance = parseUint256("0x01");

  Host->loadInitialState(TxContext,
                         {{Sender, SenderAccount},
                          {Contract, ContractAccount},
                          {Signer, SignerAccount}},
                         true);

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 80000;
  Msg.sender = Sender;
  Msg.recipient = Contract;

  ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "prague_authorization_host_test";
  ExecConfig.Bytecode = reinterpret_cast<const uint8_t *>(
      ContractAccount.code.data());
  ExecConfig.BytecodeSize = ContractAccount.code.size();
  ExecConfig.Message = Msg;
  ExecConfig.GasLimit = 80000;
  ExecConfig.IntrinsicGas = 21000 + 25000;
  ExecConfig.Revision = EVMC_PRAGUE;
  ZenMockedEVMHost::AuthorizationListEntry AuthEntry;
  AuthEntry.ChainId = parseUint256("0x01");
  AuthEntry.Address = DelegateTarget;
  AuthEntry.Nonce = 0;
  AuthEntry.Signer = Signer;
  AuthEntry.HasSigner = true;
  ExecConfig.AuthorizationList.push_back(AuthEntry);

  auto Result = Host->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success);
  ASSERT_EQ(Result.Status, EVMC_SUCCESS);
  EXPECT_GT(Result.GasRefund, 0);

  auto SignerIt = Host->accounts.find(Signer);
  ASSERT_NE(SignerIt, Host->accounts.end());
  EXPECT_EQ(SignerIt->second.nonce, 1);
  ASSERT_EQ(SignerIt->second.code.size(), 23U);
  EXPECT_EQ(static_cast<uint8_t>(SignerIt->second.code[0]), 0xef);
  EXPECT_EQ(static_cast<uint8_t>(SignerIt->second.code[1]), 0x01);
  EXPECT_EQ(static_cast<uint8_t>(SignerIt->second.code[2]), 0x00);
  EXPECT_TRUE(std::equal(DelegateTarget.bytes,
                         DelegateTarget.bytes + sizeof(DelegateTarget.bytes),
                         SignerIt->second.code.begin() + 3));
}

TEST(EVMHostGasSettlement, RevertedTransactionKeepsSingleSenderNonceBump) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT != nullptr);
  Host->setRuntime(RT.get());

  const evmc::address Sender =
      evmc::literals::operator""_address(
          "5000000000000000000000000000000000000005");
  const evmc::address Contract =
      evmc::literals::operator""_address(
          "6000000000000000000000000000000000000006");
  constexpr uint8_t REVERT_RUNTIME[] = {0x60, 0x00, 0x60, 0x00, 0xfd};

  evmc_tx_context TxContext{};
  TxContext.tx_gas_price = parseUint256("0x0a");

  evmc::MockedAccount SenderAccount;
  SenderAccount.balance = parseUint256("0x0de0b6b3a7640000");

  evmc::MockedAccount ContractAccount;
  ContractAccount.nonce = 1;
  ContractAccount.code.assign(std::begin(REVERT_RUNTIME),
                              std::end(REVERT_RUNTIME));
  const std::vector<uint8_t> ContractCode(ContractAccount.code.begin(),
                                          ContractAccount.code.end());
  const auto ContractCodeHash = zen::host::evm::crypto::keccak256(ContractCode);
  std::memcpy(ContractAccount.codehash.bytes, ContractCodeHash.data(), 32);

  Host->loadInitialState(TxContext,
                         {{Sender, SenderAccount}, {Contract, ContractAccount}},
                         true);

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 50000;
  Msg.sender = Sender;
  Msg.recipient = Contract;

  ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "revert_nonce_host_test";
  ExecConfig.Bytecode =
      reinterpret_cast<const uint8_t *>(ContractAccount.code.data());
  ExecConfig.BytecodeSize = ContractAccount.code.size();
  ExecConfig.Message = Msg;
  ExecConfig.GasLimit = 50000;
  ExecConfig.IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
  ExecConfig.Revision = EVMC_PRAGUE;

  auto Result = Host->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success);
  ASSERT_EQ(Result.Status, EVMC_REVERT);

  auto SenderIt = Host->accounts.find(Sender);
  ASSERT_NE(SenderIt, Host->accounts.end());
  EXPECT_EQ(SenderIt->second.nonce, 1);
}
