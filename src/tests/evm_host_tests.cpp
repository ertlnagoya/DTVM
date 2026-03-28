// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm.h"
#include "evm_test_host.hpp"
#include "host/evm/crypto.h"
#include "utils/evm.h"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <intx/intx.hpp>
#include <limits>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <optional>

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using namespace zen::utils;

namespace {

constexpr uint8_t CLEAR_SLOT_RUNTIME[] = {0x60, 0x00, 0x60, 0x00, 0x55, 0x60,
                                          0x00, 0x60, 0x01, 0x55, 0x00};

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

using AccountMap = decltype(std::declval<ZenMockedEVMHost>().accounts);

struct RuntimeExecutionObservation {
  evmc::Result Result;
  AccountMap Accounts;
};

evmc::Result runDirectPrecompileCall(const evmc_message &Msg,
                                     evmc_revision Revision);

std::string returnSingleContextOpcode(uint8_t Opcode) {
  return zen::utils::toHex(&Opcode, 1) + "60005260206000f3";
}

bool hexEqualsIgnoreCase(const std::string &Hex1, const std::string &Hex2) {
  auto Normalize = [](std::string Value) {
    for (char &C : Value) {
      C = static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
    }
    return Value;
  };
  return Normalize(Hex1) == Normalize(Hex2);
}

struct EcRecoverFixture {
  std::array<uint8_t, 128> Input = {};
  std::string ExpectedHex;
  bool Valid = false;
};

EcRecoverFixture buildEcRecoverFixture() {
  EcRecoverFixture Fixture;

  using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
  using ECKeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
  using ECPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
  using ECDSASigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

  ECKeyPtr Key(EC_KEY_new_by_curve_name(NID_secp256k1), &EC_KEY_free);
  if (!Key) {
    return Fixture;
  }
  const EC_GROUP *Group = EC_KEY_get0_group(Key.get());
  if (!Group) {
    return Fixture;
  }

  BNPtr PrivKey(BN_new(), &BN_free);
  ECPointPtr PubKey(EC_POINT_new(Group), &EC_POINT_free);
  if (!PrivKey || !PubKey || BN_set_word(PrivKey.get(), 1) != 1 ||
      EC_POINT_mul(Group, PubKey.get(), PrivKey.get(), nullptr, nullptr,
                   nullptr) != 1 ||
      EC_KEY_set_private_key(Key.get(), PrivKey.get()) != 1 ||
      EC_KEY_set_public_key(Key.get(), PubKey.get()) != 1) {
    return Fixture;
  }

  std::array<uint8_t, 32> MsgHash = {};
  for (size_t I = 0; I < MsgHash.size(); ++I) {
    MsgHash[I] = static_cast<uint8_t>(I + 1);
  }

  ECDSASigPtr Sig(ECDSA_do_sign(MsgHash.data(), MsgHash.size(), Key.get()),
                  &ECDSA_SIG_free);
  if (!Sig) {
    return Fixture;
  }
  const BIGNUM *R = nullptr;
  const BIGNUM *S = nullptr;
  ECDSA_SIG_get0(Sig.get(), &R, &S);
  if (!R || !S || BN_bn2binpad(R, Fixture.Input.data() + 64, 32) != 32 ||
      BN_bn2binpad(S, Fixture.Input.data() + 96, 32) != 32) {
    return Fixture;
  }
  std::memcpy(Fixture.Input.data(), MsgHash.data(), MsgHash.size());

  std::array<uint8_t, 65> EncodedPubKey = {};
  if (EC_POINT_point2oct(Group, PubKey.get(), POINT_CONVERSION_UNCOMPRESSED,
                         EncodedPubKey.data(), EncodedPubKey.size(),
                         nullptr) != EncodedPubKey.size()) {
    return Fixture;
  }
  std::vector<uint8_t> PubKeyBytes(EncodedPubKey.begin() + 1,
                                   EncodedPubKey.end());
  const auto AddressHash = zen::host::evm::crypto::keccak256(PubKeyBytes);
  std::array<uint8_t, 32> ExpectedOutput = {};
  std::memcpy(ExpectedOutput.data() + 12, AddressHash.data() + 12, 20);
  Fixture.ExpectedHex =
      "0x" + zen::utils::toHex(ExpectedOutput.data(), ExpectedOutput.size());

  const evmc::address EcRecoverAddr = evmc::literals::operator""_address(
      "0000000000000000000000000000000000000001");
  for (uint8_t V : {uint8_t(27), uint8_t(28)}) {
    Fixture.Input[63] = V;
    evmc_message Msg{};
    Msg.kind = EVMC_CALL;
    Msg.gas = 5000;
    Msg.recipient = EcRecoverAddr;
    Msg.code_address = EcRecoverAddr;
    Msg.input_data = Fixture.Input.data();
    Msg.input_size = Fixture.Input.size();

    auto Result = runDirectPrecompileCall(Msg, EVMC_CANCUN);
    if (Result.status_code == EVMC_SUCCESS && Result.output_size == 32 &&
        hexEqualsIgnoreCase(
            "0x" + zen::utils::toHex(
                       static_cast<const uint8_t *>(Result.output_data),
                       Result.output_size),
            Fixture.ExpectedHex)) {
      Fixture.Valid = true;
      return Fixture;
    }
  }

  return Fixture;
}

evmc::Result runDirectPrecompileCall(const evmc_message &Msg,
                                     evmc_revision Revision) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  EXPECT_TRUE(RT != nullptr);
  if (!RT) {
    return {};
  }
  Host->setRuntime(RT.get());
  Host->setRevision(Revision);

  evmc_tx_context TxContext{};
  Host->loadInitialState(TxContext, {}, true);
  return Host->call(Msg);
}

evmc::Result runContextOpcodeScenario(
    const std::string &RuntimeHex, const evmc_message &Msg,
    const evmc_tx_context &TxContext, evmc_revision Revision,
    const intx::uint256 &ContractBalance = intx::uint256(0)) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  EXPECT_TRUE(RT != nullptr);
  if (!RT) {
    return {};
  }
  Host->setRuntime(RT.get());

  auto Bytecode = zen::utils::fromHex(RuntimeHex);
  EXPECT_TRUE(Bytecode.has_value());
  if (!Bytecode.has_value()) {
    return evmc::Result{};
  }

  auto ModRet = RT->loadEVMModule("context_opcode_test", Bytecode->data(),
                                  Bytecode->size());
  EXPECT_TRUE(ModRet);
  if (!ModRet) {
    return evmc::Result{};
  }
  EVMModule *Mod = *ModRet;

  auto InstIso = RT->createManagedIsolation();
  EXPECT_TRUE(InstIso != nullptr);
  if (!InstIso) {
    return evmc::Result{};
  }
  auto InstRet = InstIso->createEVMInstance(*Mod, 1000000);
  EXPECT_TRUE(InstRet);
  if (!InstRet) {
    return evmc::Result{};
  }
  EVMInstance *Inst = *InstRet;

  evmc::MockedAccount SenderAccount;
  SenderAccount.balance = toBytes32(intx::uint256(1000000000));

  evmc::MockedAccount ContractAccount;
  ContractAccount.nonce = 1;
  ContractAccount.balance = toBytes32(ContractBalance);
  ContractAccount.code.assign(Bytecode->begin(), Bytecode->end());
  const auto CodeHash = zen::host::evm::crypto::keccak256(*Bytecode);
  std::memcpy(ContractAccount.codehash.bytes, CodeHash.data(), 32);

  Host->loadInitialState(TxContext,
                         {{Msg.sender, SenderAccount},
                          {Msg.recipient, ContractAccount},
                          {TxContext.block_coinbase, evmc::MockedAccount{}}},
                         true);

  Host->setRevision(Revision);
  evmc_message CallMsg = Msg;
  evmc::Result Result;
  RT->callEVMMain(*Inst, CallMsg, Result);
  return Result;
}

RuntimeExecutionObservation runRuntimeExecutionScenario(
    const std::string &RuntimeHex, const evmc_message &Msg,
    const evmc_tx_context &TxContext, evmc_revision Revision,
    const std::vector<ZenMockedEVMHost::AccountInitEntry> &AdditionalAccounts =
        {},
    const intx::uint256 &ContractBalance = intx::uint256(0)) {
  RuntimeExecutionObservation Observation{};

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  EXPECT_TRUE(RT != nullptr);
  if (!RT) {
    return Observation;
  }
  Host->setRuntime(RT.get());

  auto Bytecode = zen::utils::fromHex(RuntimeHex);
  EXPECT_TRUE(Bytecode.has_value());
  if (!Bytecode.has_value()) {
    return Observation;
  }

  auto ModRet =
      RT->loadEVMModule("nested_call_test", Bytecode->data(), Bytecode->size());
  EXPECT_TRUE(ModRet);
  if (!ModRet) {
    return Observation;
  }
  EVMModule *Mod = *ModRet;

  auto InstIso = RT->createManagedIsolation();
  EXPECT_TRUE(InstIso != nullptr);
  if (!InstIso) {
    return Observation;
  }
  auto InstRet = InstIso->createEVMInstance(*Mod, 1000000);
  EXPECT_TRUE(InstRet);
  if (!InstRet) {
    return Observation;
  }
  EVMInstance *Inst = *InstRet;

  evmc::MockedAccount SenderAccount;
  SenderAccount.balance = toBytes32(intx::uint256(1000000000));

  evmc::MockedAccount ContractAccount;
  ContractAccount.nonce = 1;
  ContractAccount.balance = toBytes32(ContractBalance);
  ContractAccount.code.assign(Bytecode->begin(), Bytecode->end());
  const auto CodeHash = zen::host::evm::crypto::keccak256(*Bytecode);
  std::memcpy(ContractAccount.codehash.bytes, CodeHash.data(), 32);

  std::vector<ZenMockedEVMHost::AccountInitEntry> Accounts;
  Accounts.push_back({Msg.sender, SenderAccount});
  Accounts.push_back({Msg.recipient, ContractAccount});
  if (std::memcmp(TxContext.block_coinbase.bytes, evmc::address{}.bytes,
                  sizeof(TxContext.block_coinbase.bytes)) != 0) {
    Accounts.push_back({TxContext.block_coinbase, evmc::MockedAccount{}});
  }
  Accounts.insert(Accounts.end(), AdditionalAccounts.begin(),
                  AdditionalAccounts.end());

  Host->loadInitialState(TxContext, Accounts, true);
  Host->setRevision(Revision);

  evmc_message CallMsg = Msg;
  RT->callEVMMain(*Inst, CallMsg, Observation.Result);
  Observation.Accounts = Host->accounts;
  return Observation;
}

GasSettlementObservation runGasSettlementScenario(
    evmc_revision Revision, const intx::uint256 &GasPrice,
    const intx::uint256 &BaseFee = intx::uint256(0),
    const std::optional<intx::uint256> &MaxPriorityFee = std::nullopt,
    const std::optional<intx::uint256> &BlobBaseFee = std::nullopt,
    const std::optional<intx::uint256> &MaxFeePerBlobGas = std::nullopt,
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

  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Contract = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Coinbase = evmc::literals::operator""_address(
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
  ContractAccount.storage[SlotKey0] = evmc::StorageValue{parseBytes32("0x01")};
  ContractAccount.storage[SlotKey1] = evmc::StorageValue{parseBytes32("0x01")};
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

  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Contract = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Signer = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");
  const evmc::address DelegateTarget = evmc::literals::operator""_address(
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
  ExecConfig.Bytecode =
      reinterpret_cast<const uint8_t *>(ContractAccount.code.data());
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

  const evmc::address Sender = evmc::literals::operator""_address(
      "5000000000000000000000000000000000000005");
  const evmc::address Contract = evmc::literals::operator""_address(
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

  Host->loadInitialState(
      TxContext, {{Sender, SenderAccount}, {Contract, ContractAccount}}, true);

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

TEST(EVMRunnerDefaults, DefaultGasLimitIsSafeForInt64BackedExecution) {
  EXPECT_EQ(zen::utils::defaultEvmGasLimit(),
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
}

TEST(EVMTransactionContext,
     AddressCallerOriginAndValueOpcodesUseMessageContext) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Recipient = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address TxOrigin = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");
  const evmc::uint256be CallValue = parseUint256("0x2a");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Recipient;
  Msg.code_address = Recipient;
  Msg.value = CallValue;

  evmc_tx_context TxContext{};
  TxContext.tx_origin = TxOrigin;

  auto AddressResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_ADDRESS), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(AddressResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(
      zen::utils::toHex(AddressResult.output_data, AddressResult.output_size),
      "0000000000000000000000002000000000000000000000000000000000000002");

  auto CallerResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_CALLER), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(CallerResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(
      zen::utils::toHex(CallerResult.output_data, CallerResult.output_size),
      "0000000000000000000000001000000000000000000000000000000000000001");

  auto OriginResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_ORIGIN), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(OriginResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(
      zen::utils::toHex(OriginResult.output_data, OriginResult.output_size),
      "0000000000000000000000003000000000000000000000000000000000000003");

  auto ValueResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_CALLVALUE), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(ValueResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(ValueResult.output_data, ValueResult.output_size),
      "000000000000000000000000000000000000000000000000000000000000002a"));
}

TEST(EVMTransactionContext, BlockContextOpcodesUseTxContextFields) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Recipient = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Coinbase = evmc::literals::operator""_address(
      "4000000000000000000000000000000000000004");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Recipient;
  Msg.code_address = Recipient;

  evmc_tx_context TxContext{};
  TxContext.block_coinbase = Coinbase;
  TxContext.block_timestamp = 0x1234;
  TxContext.block_number = 0x5678;
  TxContext.tx_gas_price = parseUint256("0x77");
  TxContext.block_base_fee = parseUint256("0x9a");
  TxContext.block_prev_randao = parseBytes32("0xabcdef");
  TxContext.chain_id = parseUint256("0x42");

  auto CoinbaseResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_COINBASE), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(CoinbaseResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(CoinbaseResult.output_data, CoinbaseResult.output_size),
      "0000000000000000000000004000000000000000000000000000000000000004"));

  auto TimestampResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_TIMESTAMP), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(TimestampResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(TimestampResult.output_data,
                        TimestampResult.output_size),
      "0000000000000000000000000000000000000000000000000000000000001234"));

  auto NumberResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_NUMBER), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(NumberResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(NumberResult.output_data, NumberResult.output_size),
      "0000000000000000000000000000000000000000000000000000000000005678"));

  auto ChainIdResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_CHAINID), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(ChainIdResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(ChainIdResult.output_data, ChainIdResult.output_size),
      "0000000000000000000000000000000000000000000000000000000000000042"));

  auto GasPriceResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_GASPRICE), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(GasPriceResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(GasPriceResult.output_data, GasPriceResult.output_size),
      "0000000000000000000000000000000000000000000000000000000000000077"));

  auto BaseFeeResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_BASEFEE), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(BaseFeeResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(BaseFeeResult.output_data, BaseFeeResult.output_size),
      "000000000000000000000000000000000000000000000000000000000000009a"));

  auto PrevRandaoResult = runContextOpcodeScenario(
      returnSingleContextOpcode(evmc_opcode::OP_PREVRANDAO), Msg, TxContext,
      EVMC_CANCUN);
  ASSERT_EQ(PrevRandaoResult.status_code, EVMC_SUCCESS);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(PrevRandaoResult.output_data,
                        PrevRandaoResult.output_size),
      "0000000000000000000000000000000000000000000000000000000000abcdef"));
}

TEST(EVMStatePersistence, SaveLoadRoundTripPreservesExtendedTxContext) {
  evmc::MockedHost Host;
  Host.tx_context.tx_origin =
      parseAddress("0x3000000000000000000000000000000000000003");
  Host.tx_context.tx_gas_price = parseUint256("0x77");
  Host.tx_context.chain_id = parseUint256("0x42");
  Host.tx_context.block_number = 0x5678;
  Host.tx_context.block_timestamp = 0x1234;
  Host.tx_context.block_coinbase =
      parseAddress("0x4000000000000000000000000000000000000004");
  Host.tx_context.block_prev_randao = parseBytes32("0xabcdef");
  Host.tx_context.block_base_fee = parseUint256("0x9a");
  Host.tx_context.blob_base_fee = parseUint256("0x55");

  const auto StatePath = std::filesystem::temp_directory_path() /
                         "dtvm_extended_tx_context_state_test.json";
  ASSERT_TRUE(saveState(Host, StatePath.string()));

  evmc::MockedHost ReloadedHost;
  ASSERT_TRUE(loadState(ReloadedHost, StatePath.string()));
  std::filesystem::remove(StatePath);

  EXPECT_EQ(addressToHex(ReloadedHost.tx_context.tx_origin),
            addressToHex(Host.tx_context.tx_origin));
  EXPECT_EQ(bytes32ToHex(ReloadedHost.tx_context.tx_gas_price),
            bytes32ToHex(Host.tx_context.tx_gas_price));
  EXPECT_EQ(bytes32ToHex(ReloadedHost.tx_context.chain_id),
            bytes32ToHex(Host.tx_context.chain_id));
  EXPECT_EQ(ReloadedHost.tx_context.block_number, Host.tx_context.block_number);
  EXPECT_EQ(ReloadedHost.tx_context.block_timestamp,
            Host.tx_context.block_timestamp);
  EXPECT_EQ(addressToHex(ReloadedHost.tx_context.block_coinbase),
            addressToHex(Host.tx_context.block_coinbase));
  EXPECT_EQ(bytes32ToHex(ReloadedHost.tx_context.block_prev_randao),
            bytes32ToHex(Host.tx_context.block_prev_randao));
  EXPECT_EQ(bytes32ToHex(ReloadedHost.tx_context.block_base_fee),
            bytes32ToHex(Host.tx_context.block_base_fee));
  EXPECT_EQ(bytes32ToHex(ReloadedHost.tx_context.blob_base_fee),
            bytes32ToHex(Host.tx_context.blob_base_fee));
}

TEST(EVMCallSemantics, StaticCallRejectsStateWrites) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Parent = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Child = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Parent;
  Msg.code_address = Parent;

  evmc_tx_context TxContext{};

  evmc::MockedAccount ChildAccount;
  ChildAccount.nonce = 1;
  auto ChildBytecode = fromHex("600160005500");
  ASSERT_TRUE(ChildBytecode.has_value());
  ChildAccount.code.assign(ChildBytecode->begin(), ChildBytecode->end());
  const auto ChildCodeHash = zen::host::evm::crypto::keccak256(*ChildBytecode);
  std::memcpy(ChildAccount.codehash.bytes, ChildCodeHash.data(), 32);

  const std::string ParentRuntimeHex =
      "60006000600060007330000000000000000000000000000000000000036300100000"
      "fa60005260206000f3";
  auto Observation = runRuntimeExecutionScenario(
      ParentRuntimeHex, Msg, TxContext, EVMC_CANCUN, {{Child, ChildAccount}});

  ASSERT_EQ(Observation.Result.status_code, EVMC_SUCCESS);
  ASSERT_EQ(Observation.Result.output_size, 32U);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Observation.Result.output_data,
                        Observation.Result.output_size),
      "0000000000000000000000000000000000000000000000000000000000000000"));

  auto ChildIt = Observation.Accounts.find(Child);
  ASSERT_NE(ChildIt, Observation.Accounts.end());
  auto StorageIt = ChildIt->second.storage.find(parseBytes32("0x00"));
  EXPECT_TRUE(StorageIt == ChildIt->second.storage.end() ||
              StorageIt->second.current == parseBytes32("0x00"));
}

TEST(EVMCallSemantics, DelegateCallPreservesSenderValueAndReturndata) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Parent = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Child = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Parent;
  Msg.code_address = Parent;
  Msg.value = parseUint256("0x2a");

  evmc_tx_context TxContext{};
  TxContext.tx_origin = Sender;

  evmc::MockedAccount ChildAccount;
  ChildAccount.nonce = 1;
  auto ChildBytecode = fromHex("336000523460205260406000f3");
  ASSERT_TRUE(ChildBytecode.has_value());
  ChildAccount.code.assign(ChildBytecode->begin(), ChildBytecode->end());
  const auto ChildCodeHash = zen::host::evm::crypto::keccak256(*ChildBytecode);
  std::memcpy(ChildAccount.codehash.bytes, ChildCodeHash.data(), 32);

  const std::string ParentRuntimeHex =
      "60006000600060007330000000000000000000000000000000000000036300100000"
      "f4503d80600060003e6000f3";
  auto Observation = runRuntimeExecutionScenario(
      ParentRuntimeHex, Msg, TxContext, EVMC_CANCUN, {{Child, ChildAccount}});

  ASSERT_EQ(Observation.Result.status_code, EVMC_SUCCESS);
  ASSERT_EQ(Observation.Result.output_size, 64U);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Observation.Result.output_data, 32),
      "0000000000000000000000001000000000000000000000000000000000000001"));
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Observation.Result.output_data + 32, 32),
      "000000000000000000000000000000000000000000000000000000000000002a"));
}

TEST(EVMCallSemantics, CallCanBubbleChildRevertData) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Parent = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Child = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Parent;
  Msg.code_address = Parent;

  evmc_tx_context TxContext{};

  evmc::MockedAccount ChildAccount;
  ChildAccount.nonce = 1;
  auto ChildBytecode = fromHex("602a60005260206000fd");
  ASSERT_TRUE(ChildBytecode.has_value());
  ChildAccount.code.assign(ChildBytecode->begin(), ChildBytecode->end());
  const auto ChildCodeHash = zen::host::evm::crypto::keccak256(*ChildBytecode);
  std::memcpy(ChildAccount.codehash.bytes, ChildCodeHash.data(), 32);

  const std::string ParentRuntimeHex =
      "60006000600060006000733000000000000000000000000000000000000003630010"
      "0000f1503d80600060003e6000fd";
  auto Observation = runRuntimeExecutionScenario(
      ParentRuntimeHex, Msg, TxContext, EVMC_CANCUN, {{Child, ChildAccount}});

  ASSERT_EQ(Observation.Result.status_code, EVMC_REVERT);
  ASSERT_EQ(Observation.Result.output_size, 32U);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Observation.Result.output_data,
                        Observation.Result.output_size),
      "000000000000000000000000000000000000000000000000000000000000002a"));
}

TEST(EVMCallSemantics, CallForwardsUsableGasAndReturnsReturndata) {
  const evmc::address Sender = evmc::literals::operator""_address(
      "1000000000000000000000000000000000000001");
  const evmc::address Parent = evmc::literals::operator""_address(
      "2000000000000000000000000000000000000002");
  const evmc::address Child = evmc::literals::operator""_address(
      "3000000000000000000000000000000000000003");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000;
  Msg.sender = Sender;
  Msg.recipient = Parent;
  Msg.code_address = Parent;

  evmc_tx_context TxContext{};

  evmc::MockedAccount ChildAccount;
  ChildAccount.nonce = 1;
  auto ChildBytecode = fromHex("5a60005260206000f3");
  ASSERT_TRUE(ChildBytecode.has_value());
  ChildAccount.code.assign(ChildBytecode->begin(), ChildBytecode->end());
  const auto ChildCodeHash = zen::host::evm::crypto::keccak256(*ChildBytecode);
  std::memcpy(ChildAccount.codehash.bytes, ChildCodeHash.data(), 32);

  const std::string ParentRuntimeHex =
      "60206000600060006000733000000000000000000000000000000000000003630100"
      "00f160005260206000f3";
  auto Observation = runRuntimeExecutionScenario(
      ParentRuntimeHex, Msg, TxContext, EVMC_CANCUN, {{Child, ChildAccount}});

  ASSERT_EQ(Observation.Result.status_code, EVMC_SUCCESS);
  ASSERT_EQ(Observation.Result.output_size, 32U);
  EXPECT_FALSE(hexEqualsIgnoreCase(
      zen::utils::toHex(Observation.Result.output_data,
                        Observation.Result.output_size),
      "0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST(EVMPrecompiles, IdentityReturnsInputAndChargesWordGas) {
  const evmc::address Identity =
      parseAddress("0x0000000000000000000000000000000000000004");
  const std::array<uint8_t, 40> Input = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
      0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100;
  Msg.recipient = Identity;
  Msg.code_address = Identity;
  Msg.input_data = Input.data();
  Msg.input_size = Input.size();

  auto Result = runDirectPrecompileCall(Msg, EVMC_FRONTIER);
  ASSERT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.gas_left, 79);
  EXPECT_EQ(Result.output_size, Input.size());
  EXPECT_EQ(zen::utils::toHex(Result.output_data, Result.output_size),
            zen::utils::toHex(Input.data(), Input.size()));
}

TEST(EVMPrecompiles, EcRecoverReturnsRecoveredAddressAndChargesFixedGas) {
  const auto Fixture = buildEcRecoverFixture();
  ASSERT_TRUE(Fixture.Valid);

  const evmc::address EcRecoverAddr = evmc::literals::operator""_address(
      "0000000000000000000000000000000000000001");

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 5000;
  Msg.recipient = EcRecoverAddr;
  Msg.code_address = EcRecoverAddr;
  Msg.input_data = Fixture.Input.data();
  Msg.input_size = Fixture.Input.size();

  auto Result = runDirectPrecompileCall(Msg, EVMC_CANCUN);
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.gas_left, 2000);
  ASSERT_EQ(Result.output_size, 32);

  const auto Output =
      "0x" + zen::utils::toHex(static_cast<const uint8_t *>(Result.output_data),
                               Result.output_size);
  EXPECT_TRUE(hexEqualsIgnoreCase(Output, Fixture.ExpectedHex));
}

TEST(EVMPrecompiles, EcRecoverRejectsInvalidRecoveryId) {
  const auto Fixture = buildEcRecoverFixture();
  ASSERT_TRUE(Fixture.Valid);

  const evmc::address EcRecoverAddr = evmc::literals::operator""_address(
      "0000000000000000000000000000000000000001");

  auto InvalidInput = Fixture.Input;
  InvalidInput[63] = 29;

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 5000;
  Msg.recipient = EcRecoverAddr;
  Msg.code_address = EcRecoverAddr;
  Msg.input_data = InvalidInput.data();
  Msg.input_size = InvalidInput.size();

  auto Result = runDirectPrecompileCall(Msg, EVMC_CANCUN);
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.gas_left, 2000);
  EXPECT_EQ(Result.output_size, 0);
}

TEST(EVMPrecompiles, Sha256ReturnsDigestAndChargesWordGas) {
  const evmc::address Sha256 =
      parseAddress("0x0000000000000000000000000000000000000002");
  const std::array<uint8_t, 3> Input = {'a', 'b', 'c'};

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100;
  Msg.recipient = Sha256;
  Msg.code_address = Sha256;
  Msg.input_data = Input.data();
  Msg.input_size = Input.size();

  auto Result = runDirectPrecompileCall(Msg, EVMC_FRONTIER);
  ASSERT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.gas_left, 28);
  EXPECT_EQ(Result.output_size, 32U);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Result.output_data, Result.output_size),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

TEST(EVMPrecompiles, Ripemd160ReturnsDigestAndChargesWordGas) {
  const evmc::address Ripemd160 =
      parseAddress("0x0000000000000000000000000000000000000003");
  const std::array<uint8_t, 3> Input = {'a', 'b', 'c'};

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000;
  Msg.recipient = Ripemd160;
  Msg.code_address = Ripemd160;
  Msg.input_data = Input.data();
  Msg.input_size = Input.size();

  auto Result = runDirectPrecompileCall(Msg, EVMC_FRONTIER);
  ASSERT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.gas_left, 280);
  EXPECT_EQ(Result.output_size, 32U);
  EXPECT_TRUE(hexEqualsIgnoreCase(
      zen::utils::toHex(Result.output_data, Result.output_size),
      "0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
}

TEST(EVMPrecompiles, ModExpAvailabilityDependsOnFork) {
  const evmc::address ModExp =
      parseAddress("0x0000000000000000000000000000000000000005");
  const std::array<uint8_t, 96> ZeroInput = {};

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000;
  Msg.recipient = ModExp;
  Msg.code_address = ModExp;
  Msg.input_data = ZeroInput.data();
  Msg.input_size = ZeroInput.size();

  auto HomesteadResult = runDirectPrecompileCall(Msg, EVMC_HOMESTEAD);
  ASSERT_EQ(HomesteadResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(HomesteadResult.output_size, 0U);
  EXPECT_EQ(HomesteadResult.gas_left, Msg.gas);

  auto ByzantiumResult = runDirectPrecompileCall(Msg, EVMC_BYZANTIUM);
  ASSERT_EQ(ByzantiumResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(ByzantiumResult.output_size, 0U);
  EXPECT_EQ(ByzantiumResult.gas_left, 400);
}

TEST(EVMPrecompiles, Blake2AvailabilityDependsOnFork) {
  const evmc::address Blake2f =
      parseAddress("0x0000000000000000000000000000000000000009");
  std::array<uint8_t, 213> Input = {};
  Input[3] = 0x0c;
  Input[212] = 1;

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100;
  Msg.recipient = Blake2f;
  Msg.code_address = Blake2f;
  Msg.input_data = Input.data();
  Msg.input_size = Input.size();

  auto ByzantiumResult = runDirectPrecompileCall(Msg, EVMC_BYZANTIUM);
  ASSERT_EQ(ByzantiumResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(ByzantiumResult.output_size, 0U);
  EXPECT_EQ(ByzantiumResult.gas_left, Msg.gas);

  auto IstanbulResult = runDirectPrecompileCall(Msg, EVMC_ISTANBUL);
  ASSERT_EQ(IstanbulResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(IstanbulResult.output_size, 64U);
  EXPECT_EQ(IstanbulResult.gas_left, 88);
}
