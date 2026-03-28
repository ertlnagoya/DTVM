// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm.h"
#include "evm_test_fixtures.h"
#include "evm_test_helpers.h"
#include "evm_test_host.hpp"

#include <algorithm>
#include <gtest/gtest.h>

using namespace zen::evm;
using namespace zen::utils;
using namespace zen::evm_test_utils;

namespace {

constexpr bool DEBUG = true;
constexpr bool PRINT_FAILURE_DETAILS = true;
// TODO: RunMode selection logic will be refactored in the future.
constexpr auto STATE_TEST_RUN_MODE = common::RunMode::InterpMode;

struct TxIntrinsicCost {
  int64_t Intrinsic = 0;
  int64_t Min = 0;
};

int64_t countTxDataTokens(const evmc_revision Revision,
                          const std::vector<uint8_t> &Data) {
  const size_t ZeroBytes =
      static_cast<size_t>(std::count(Data.begin(), Data.end(), 0));
  const size_t NonZeroBytes = Data.size() - ZeroBytes;
  const int64_t NonZeroMultiplier = Revision >= EVMC_ISTANBUL ? 4 : 17;
  return static_cast<int64_t>(NonZeroBytes) * NonZeroMultiplier +
         static_cast<int64_t>(ZeroBytes);
}

TxIntrinsicCost computeTxIntrinsicCost(const evmc_revision Revision,
                                       const ParsedTransaction &PT) {
  static constexpr int64_t TxCreateCost = 32000;
  static constexpr int64_t DataTokenCost = 4;
  static constexpr int64_t AccessListAddressCost = 2400;
  static constexpr int64_t AccessListStorageKeyCost = 1900;
  static constexpr int64_t AuthorizationEmptyAccountCost = 25000;
  static constexpr int64_t InitcodeWordCost = 2;
  static constexpr int64_t TotalCostFloorPerToken = 10;

  const bool IsCreateTx =
      PT.Message->kind == EVMC_CREATE || PT.Message->kind == EVMC_CREATE2;
  const int64_t CreateCost =
      IsCreateTx && Revision >= EVMC_HOMESTEAD ? TxCreateCost : 0;

  const int64_t DataTokens = countTxDataTokens(Revision, PT.CallData);
  const int64_t DataCost = DataTokens * DataTokenCost;

  int64_t AccessListCost = 0;
  if (Revision >= EVMC_BERLIN) {
    for (const auto &Entry : PT.AccessList) {
      AccessListCost += AccessListAddressCost;
      AccessListCost += AccessListStorageKeyCost *
                        static_cast<int64_t>(Entry.StorageKeys.size());
    }
  }

  const int64_t AuthListCost =
      static_cast<int64_t>(PT.AuthorizationList.size()) *
      AuthorizationEmptyAccountCost;

  int64_t InitcodeCost = 0;
  if (IsCreateTx && Revision >= EVMC_SHANGHAI) {
    const int64_t InitcodeWords =
        static_cast<int64_t>((PT.CallData.size() + 31) / 32);
    InitcodeCost = InitcodeWords * InitcodeWordCost;
  }

  const int64_t IntrinsicCost = zen::evm::BASIC_EXECUTION_COST + CreateCost +
                                DataCost + AccessListCost + AuthListCost +
                                InitcodeCost;

  const int64_t MinCost =
      Revision >= EVMC_PRAGUE
          ? zen::evm::BASIC_EXECUTION_COST + DataTokens * TotalCostFloorPerToken
          : 0;

  return {IntrinsicCost, MinCost};
}

// Revision filter configuration
// Set to EVMC_MAX_REVISION to run all tests, or a specific revision to filter
evmc_revision getTargetRevision() {
  static const std::unordered_map<std::string, evmc_revision> RevisionMap = {
      {"ALL", EVMC_MAX_REVISION},
      {"Frontier", EVMC_FRONTIER},
      {"Homestead", EVMC_HOMESTEAD},
      {"TangerineWhistle", EVMC_TANGERINE_WHISTLE},
      {"SpuriousDragon", EVMC_SPURIOUS_DRAGON},
      {"Byzantium", EVMC_BYZANTIUM},
      {"Constantinople", EVMC_CONSTANTINOPLE},
      {"Petersburg", EVMC_PETERSBURG},
      {"Istanbul", EVMC_ISTANBUL},
      {"Berlin", EVMC_BERLIN},
      {"London", EVMC_LONDON},
      {"Paris", EVMC_PARIS},
      {"Shanghai", EVMC_SHANGHAI},
      {"Cancun", EVMC_CANCUN},
      {"Prague", EVMC_PRAGUE},
  };

  const char *EnvRevision = std::getenv("DTVM_TEST_REVISION");
  if (EnvRevision != nullptr) {
    std::string RevisionStr = EnvRevision;
    auto It = RevisionMap.find(RevisionStr);
    if (It != RevisionMap.end()) {
      return It->second;
    }
  }
  // Default: only test Cancun revision
  return EVMC_CANCUN;
}

RuntimeConfig buildRuntimeConfig() {
  RuntimeConfig Config;

  const bool MultipassSupported =
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      true;
#else
      false;
#endif

  if (STATE_TEST_RUN_MODE == common::RunMode::MultipassMode &&
      !MultipassSupported) {
    std::cerr << "Multipass requested but not built, falling back to "
                 "interpreter"
              << std::endl;
    Config.Mode = common::RunMode::InterpMode;
  } else {
    Config.Mode = STATE_TEST_RUN_MODE;
    if (Config.Mode == common::RunMode::UnknownMode) {
      Config.Mode = MultipassSupported ? common::RunMode::MultipassMode
                                       : common::RunMode::InterpMode;
    }
  }

  Config.EnableEvmGasMetering = true;
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Config.DisableMultipassGreedyRA = true;
#endif

  return Config;
}

std::string getDefaultTestDir() {
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_spec_test/state_tests");
  return DirPath.string();
}

const std::string DEFAULT_TEST_DIR = getDefaultTestDir();

struct ExecutionResult {
  bool Passed = false;
  std::vector<std::string> ErrorMessages;
};

ExecutionResult executeStateTest(const StateTestFixture &Fixture,
                                 const std::string &Fork,
                                 const ForkPostResult &ExpectedResult) {
  auto MakeFailure = [&](const std::string &Msg) {
    ExecutionResult Result;
    Result.Passed = false;
    Result.ErrorMessages.push_back(Msg);
    return Result;
  };

  try {
    ParsedTransaction PT =
        createTransactionFromIndex(*Fixture.Transaction, ExpectedResult);
    const evmc_revision Revision = mapForkToRevision(Fork);
    const TxIntrinsicCost IntrinsicCost = computeTxIntrinsicCost(Revision, PT);

    const bool IsCreateTx =
        PT.Message->kind == EVMC_CREATE || PT.Message->kind == EVMC_CREATE2;
    if (IsCreateTx && Revision >= EVMC_SHANGHAI &&
        PT.CallData.size() > zen::evm::MAX_SIZE_OF_INITCODE) {
      if (!ExpectedResult.ExpectedException.empty()) {
        return {true, {}};
      }
      return MakeFailure("Initcode size limit exceeded for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    const int64_t TxGasLimit = PT.Message->gas;
    const int64_t RequiredGasLimit =
        std::max(IntrinsicCost.Intrinsic, IntrinsicCost.Min);
    if (TxGasLimit < RequiredGasLimit) {
      if (!ExpectedResult.ExpectedException.empty()) {
        return {true, {}};
      }
      return MakeFailure("Intrinsic gas too low for " + Fixture.TestName +
                         " (" + Fork + ")");
    }

    const int64_t MinimumChargedGas = IntrinsicCost.Min;
    const int64_t ExecutionGasLimit = TxGasLimit - IntrinsicCost.Intrinsic;
    PT.Message->gas = ExecutionGasLimit;

    // Find the target account (contract to call)
    const ParsedAccount *TargetAccount = nullptr;
    for (const auto &PA : Fixture.PreState) {
      if (std::memcmp(PA.Address.bytes, PT.Message->recipient.bytes, 20) == 0) {
        TargetAccount = &PA;
        break;
      }
    }

    if (!TargetAccount && !IsCreateTx) {
      if (!ExpectedResult.ExpectedException.empty()) {
        return {true, {}};
      }
      if (DEBUG) {
        std::cout << "No target account found for test: " << Fixture.TestName
                  << std::endl;
      }
      return MakeFailure(
          "Target account " +
          evmc::hex(evmc::bytes_view(PT.Message->recipient.bytes, 20)) +
          " not present in pre-state for " + Fixture.TestName + " (" + Fork +
          ")");
    }

    // Skip if no code to execute
    if (!IsCreateTx && TargetAccount->Account.code.empty()) {
      if (DEBUG) {
        std::cout << "No code to execute for test: " << Fixture.TestName
                  << std::endl;
      }
      return {true, {}};
    }

    RuntimeConfig Config = buildRuntimeConfig();

    auto HostPtr = std::make_unique<ZenMockedEVMHost>();

    std::vector<ZenMockedEVMHost::AccountInitEntry> InitialAccounts;
    InitialAccounts.reserve(Fixture.PreState.size());
    for (const auto &PA : Fixture.PreState) {
      ZenMockedEVMHost::AccountInitEntry Entry;
      Entry.Address = PA.Address;
      Entry.Account = PA.Account;
      InitialAccounts.push_back(Entry);
    }
    evmc_tx_context TxContext = Fixture.Environment;
    if (!PT.BlobHashes.empty()) {
      TxContext.blob_hashes = PT.BlobHashes.data();
      TxContext.blob_hashes_count = PT.BlobHashes.size();
    }
    HostPtr->loadInitialState(TxContext, InitialAccounts, true);

    // Warm sender and recipient (required by EIP-2929)
    HostPtr->access_account(PT.Message->sender);
    HostPtr->access_account(PT.Message->recipient);

    auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
    if (!RT) {
      return MakeFailure("Failed to create EVM runtime for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    HostPtr->setRuntime(RT.get());
    ZenMockedEVMHost *MockedHost = HostPtr.get();

    ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
    ExecConfig.ModuleName = Fixture.TestName;
    if (IsCreateTx) {
      ExecConfig.Bytecode = PT.CallData.data();
      ExecConfig.BytecodeSize = PT.CallData.size();
    } else {
      ExecConfig.Bytecode = TargetAccount->Account.code.data();
      ExecConfig.BytecodeSize = TargetAccount->Account.code.size();
    }
    ExecConfig.Message = *PT.Message;
    ExecConfig.Revision = Revision;
    ExecConfig.IntrinsicGas = static_cast<uint64_t>(IntrinsicCost.Intrinsic);
    ExecConfig.MinimumChargedGas = static_cast<uint64_t>(MinimumChargedGas);

    // Convert AccessList from ParsedTransaction to TransactionExecutionConfig
    for (const auto &Entry : PT.AccessList) {
      ZenMockedEVMHost::AccessListEntry ALE;
      ALE.Address = Entry.Address;
      ALE.StorageKeys = Entry.StorageKeys;
      ExecConfig.AccessList.push_back(std::move(ALE));
    }

    for (const auto &Entry : PT.AuthorizationList) {
      ZenMockedEVMHost::AuthorizationListEntry ALE;
      ALE.ChainId = Entry.ChainId;
      ALE.Address = Entry.Address;
      ALE.Nonce = Entry.Nonce;
      ALE.Signer = Entry.Signer;
      ALE.HasSigner = Entry.HasSigner;
      ExecConfig.AuthorizationList.push_back(std::move(ALE));
    }

    ExecConfig.GasLimit = static_cast<uint64_t>(PT.Message->gas);

    if (Fixture.Transaction &&
        Fixture.Transaction->HasMember("maxPriorityFeePerGas") &&
        (*Fixture.Transaction)["maxPriorityFeePerGas"].IsString()) {
      ExecConfig.MaxPriorityFeePerGas = parseUint256(
          (*Fixture.Transaction)["maxPriorityFeePerGas"].GetString());
    }
    ExecConfig.MaxFeePerBlobGas = PT.MaxFeePerBlobGas;

    auto ExecResult = MockedHost->executeTransaction(ExecConfig);

    if (DEBUG) {
      std::cout << "ExecutionSucceeded: " << ExecResult.Success << std::endl;
      std::cout << "ExecutionGasUsed: " << ExecResult.GasUsed << std::endl;
      std::cout << "ExecutionGasCharged: " << ExecResult.GasCharged
                << std::endl;
      std::cout << "ExecutionStatus: " << ExecResult.Status << std::endl;
      if (!ExecResult.ErrorMessage.empty()) {
        std::cout << "ExecutionError: " << ExecResult.ErrorMessage << std::endl;
      }
    }

    if (!ExpectedResult.ExpectedException.empty()) {
      if (ExecResult.Status == EVMC_SUCCESS) {
        return MakeFailure("Expected exception '" +
                           ExpectedResult.ExpectedException + "' for " +
                           Fixture.TestName + " (" + Fork +
                           ") but execution succeeded");
      }
      return {true, {}};
    }

    if (!ExecResult.Success) {
      std::string ErrorMsg = "Execution infrastructure failure for " +
                             Fixture.TestName + " (" + Fork + ")";
      if (!ExecResult.ErrorMessage.empty()) {
        ErrorMsg += ": " + ExecResult.ErrorMessage;
      }
      return MakeFailure(ErrorMsg);
    }

    std::vector<std::string> AllErrors;

    std::string ActualStateRoot = calculateStateRootHash(*MockedHost);
    if (ActualStateRoot != ExpectedResult.ExpectedHash) {
      AllErrors.push_back("State root mismatch" +
                          std::string("\n  Expected: ") +
                          ExpectedResult.ExpectedHash +
                          std::string("\n  Actual:   ") + ActualStateRoot);
    }

    std::string ActualLogsHash =
        "0x" + calculateLogsHash(MockedHost->recorded_logs);
    if (ActualLogsHash != ExpectedResult.ExpectedLogs) {
      AllErrors.push_back("Logs hash mismatch" + std::string("\n  Expected: ") +
                          ExpectedResult.ExpectedLogs +
                          std::string("\n  Actual:   ") + ActualLogsHash);
    }

    if (ExpectedResult.ExpectedState &&
        ExpectedResult.ExpectedState->IsObject()) {
      auto StateErrors = verifyPostState(
          *MockedHost, *ExpectedResult.ExpectedState, Fixture.TestName, Fork);
      AllErrors.insert(AllErrors.end(), StateErrors.begin(), StateErrors.end());
    }

    if (!AllErrors.empty()) {
      ExecutionResult Result;
      Result.Passed = false;
      Result.ErrorMessages = std::move(AllErrors);
      return Result;
    }

    return {true, {}};

  } catch (const std::exception &E) {
    return MakeFailure("Exception in executeStateTest for " + Fixture.TestName +
                       " (" + Fork + "): " + E.what());
  }
}

struct StateTestCaseParam {
  const StateTestFixture *Fixture = nullptr;
  std::string ForkName;
  ForkPostResult Expected;
  bool Valid = false;
  std::string LoadError;
  std::string CaseName;
};

const std::vector<StateTestFixture> &getStateFixtures() {
  static std::vector<StateTestFixture> Fixtures = [] {
    std::vector<StateTestFixture> Loaded;
    auto JsonFiles = findJsonFiles(DEFAULT_TEST_DIR);
    if (DEBUG) {
      std::cout << "Found " << JsonFiles.size() << " JSON test files in "
                << DEFAULT_TEST_DIR << std::endl;
    }

    for (const auto &FilePath : JsonFiles) {
      auto FixturesFromFile = parseStateTestFile(FilePath);
      for (auto &Fixture : FixturesFromFile) {
        if (DEBUG) {
          std::cout << "Loaded fixture: " << Fixture.TestName << std::endl;
        }
        Loaded.push_back(std::move(Fixture));
      }
    }

    if (DEBUG) {
      std::cout << "Total fixtures loaded: " << Loaded.size() << std::endl;
    }

    return Loaded;
  }();

  return Fixtures;
}

const std::vector<StateTestCaseParam> &getStateTestParams() {
  static std::vector<StateTestCaseParam> Params = [] {
    std::vector<StateTestCaseParam> Cases;
    const auto &Fixtures = getStateFixtures();

    size_t CaseCounter = 0;
    evmc_revision TargetRevision = getTargetRevision();

    for (const auto &Fixture : Fixtures) {
      if (!Fixture.Post || !Fixture.Post->IsObject()) {
        StateTestCaseParam Param;
        Param.Fixture = &Fixture;
        Param.Valid = false;
        Param.LoadError = "Invalid test fixture: " + Fixture.TestName +
                          " - Post section missing or invalid";
        Param.CaseName =
            Fixture.TestName + "_InvalidPost_" + std::to_string(CaseCounter++);
        Cases.push_back(std::move(Param));
        continue;
      }

      for (const auto &Fork : Fixture.Post->GetObject()) {
        std::string ForkName = Fork.name.GetString();

        // Filter by revision if not running all tests
        if (TargetRevision != EVMC_MAX_REVISION) {
          evmc_revision ForkRevision = mapForkToRevision(ForkName);
          if (ForkRevision != TargetRevision) {
            continue;
          }
        }

        const rapidjson::Value &ForkResults = Fork.value;
        if (!ForkResults.IsArray()) {
          StateTestCaseParam Param;
          Param.Fixture = &Fixture;
          Param.Valid = false;
          Param.LoadError = "Invalid fork results format for: " + ForkName +
                            " in test: " + Fixture.TestName;
          Param.CaseName = Fixture.TestName + "_" + ForkName +
                           "_InvalidResults_" + std::to_string(CaseCounter++);
          Cases.push_back(std::move(Param));
          continue;
        }

        for (rapidjson::SizeType I = 0; I < ForkResults.Size(); ++I) {
          try {
            ForkPostResult ExpectedResult = parseForkPostResult(ForkResults[I]);

            StateTestCaseParam Param;
            Param.Fixture = &Fixture;
            Param.ForkName = ForkName;
            Param.Expected = std::move(ExpectedResult);
            Param.Valid = true;
            Param.CaseName =
                Fixture.TestName + "_" + ForkName + "_" + std::to_string(I);
            Cases.push_back(std::move(Param));
          } catch (const std::exception &E) {
            StateTestCaseParam Param;
            Param.Fixture = &Fixture;
            Param.Valid = false;
            Param.LoadError = "Failed to parse post result " +
                              std::to_string(I) + " for fork " + ForkName +
                              " in test " + Fixture.TestName + ": " + E.what();
            Param.CaseName = Fixture.TestName + "_" + ForkName +
                             "_ParseError_" + std::to_string(CaseCounter++);
            Cases.push_back(std::move(Param));
          }
        }
      }
    }

    if (DEBUG) {
      std::cout << "Generated " << Cases.size() << " state test cases"
                << std::endl;
    }

    return Cases;
  }();

  return Params;
}

std::string sanitizeTestName(const std::string &Name) {
  std::string Result;
  Result.reserve(Name.size());
  for (char C : Name) {
    if (std::isalnum(static_cast<unsigned char>(C))) {
      Result.push_back(C);
    } else {
      Result.push_back('_');
    }
  }
  if (Result.empty()) {
    Result = "Case";
  }
  if (std::isdigit(static_cast<unsigned char>(Result.front()))) {
    Result.insert(Result.begin(), '_');
  }
  return Result;
}

class EVMStateTest : public testing::TestWithParam<StateTestCaseParam> {};

void assertFocusedFixturePasses(const std::string &FixturePath,
                                const std::string &FixtureName,
                                const std::string &ForkName,
                                const std::string &FailureLabel) {
  auto Fixtures = parseStateTestFile(FixturePath);
  auto FixtureIt = std::find_if(Fixtures.begin(), Fixtures.end(),
                                [&](const StateTestFixture &Fixture) {
                                  return Fixture.TestName == FixtureName;
                                });

  ASSERT_NE(FixtureIt, Fixtures.end())
      << "Focused fixture not found in " << FixturePath;
  ASSERT_NE(FixtureIt->Post, nullptr)
      << "Focused fixture is missing post state";

  const auto ForkIt = FixtureIt->Post->FindMember(ForkName.c_str());
  ASSERT_NE(ForkIt, FixtureIt->Post->MemberEnd())
      << "Fork " << ForkName << " not found in focused fixture";
  ASSERT_TRUE(ForkIt->value.IsArray())
      << "Fork " << ForkName << " does not contain a result array";
  ASSERT_GT(ForkIt->value.Size(), 0u)
      << "Fork " << ForkName << " result array is empty";

  ForkPostResult ExpectedResult = parseForkPostResult(ForkIt->value[0]);
  ExecutionResult Result =
      executeStateTest(*FixtureIt, ForkName, ExpectedResult);

  if (!Result.Passed) {
    std::string CombinedErrors = "\n";
    CombinedErrors += "=================================================\n";
    CombinedErrors +=
        FailureLabel + " failed with " +
        std::to_string(Result.ErrorMessages.size()) +
        (Result.ErrorMessages.size() == 1 ? " error:" : " errors:") + "\n";
    CombinedErrors += "=================================================\n";
    for (size_t I = 0; I < Result.ErrorMessages.size(); ++I) {
      CombinedErrors += "\n[Error " + std::to_string(I + 1) + "]\n";
      CombinedErrors += Result.ErrorMessages[I];
      CombinedErrors += "\n";
    }
    CombinedErrors += "=================================================\n";
    FAIL() << CombinedErrors;
  }
}

TEST(EVMStateFocused, Blake2PrecompileDelegatecallBerlin) {
  const evmc_revision TargetRevision = getTargetRevision();
  if (TargetRevision != EVMC_MAX_REVISION && TargetRevision != EVMC_BERLIN) {
    GTEST_SKIP() << "Focused Berlin regression skipped for requested revision";
  }

  const std::string FixturePath =
      DEFAULT_TEST_DIR +
      "/istanbul/eip152_blake2/test_blake2_precompile_delegatecall.json";
  const std::string FixtureName =
      "tests/istanbul/eip152_blake2/test_blake2_delegatecall.py::"
      "test_blake2_precompile_delegatecall[fork_Berlin-state_test]";
  const std::string ForkName = "Berlin";

  assertFocusedFixturePasses(FixturePath, FixtureName, ForkName,
                             "Focused Berlin blake2 delegatecall regression");
}

TEST(EVMStateFocused, ChainIdTypedTransaction4Prague) {
  const evmc_revision TargetRevision = getTargetRevision();
  if (TargetRevision != EVMC_MAX_REVISION && TargetRevision != EVMC_PRAGUE) {
    GTEST_SKIP() << "Focused Prague regression skipped for requested revision";
  }

  const std::string FixturePath =
      DEFAULT_TEST_DIR + "/istanbul/eip1344_chainid/test_chainid.json";
  const std::string FixtureName =
      "tests/istanbul/eip1344_chainid/test_chainid.py::"
      "test_chainid[fork_Prague-typed_transaction_4-state_test]";
  const std::string ForkName = "Prague";

  assertFocusedFixturePasses(
      FixturePath, FixtureName, ForkName,
      "Focused Prague CHAINID typed_transaction_4 regression");
}

TEST(EVMStateFocused, ContractCreatingTxMaxSizeOnesPrague) {
  const evmc_revision TargetRevision = getTargetRevision();
  if (TargetRevision != EVMC_MAX_REVISION && TargetRevision != EVMC_PRAGUE) {
    GTEST_SKIP() << "Focused Prague regression skipped for requested revision";
  }

  const std::string FixturePath =
      DEFAULT_TEST_DIR +
      "/shanghai/eip3860_initcode/test_contract_creating_tx.json";
  const std::string FixtureName =
      "tests/shanghai/eip3860_initcode/test_initcode.py::"
      "test_contract_creating_tx[fork_Prague-state_test-max_size_ones]";
  const std::string ForkName = "Prague";

  assertFocusedFixturePasses(
      FixturePath, FixtureName, ForkName,
      "Focused Prague max_size_ones contract-creation regression");
}

TEST(EVMStateFocused, ReentrancySelfdestructRevertCallCancun) {
  const evmc_revision TargetRevision = getTargetRevision();
  if (TargetRevision != EVMC_MAX_REVISION && TargetRevision != EVMC_CANCUN) {
    GTEST_SKIP() << "Focused Cancun regression skipped for requested revision";
  }

  const std::string FixturePath =
      DEFAULT_TEST_DIR +
      "/cancun/eip6780_selfdestruct/test_reentrancy_selfdestruct_revert.json";
  const std::string FixtureName =
      "tests/cancun/eip6780_selfdestruct/test_reentrancy_selfdestruct_revert."
      "py::test_reentrancy_selfdestruct_revert[fork_Cancun-state_test-"
      "second_suicide_CALL-first_suicide_CALL]";
  const std::string ForkName = "Cancun";

  assertFocusedFixturePasses(
      FixturePath, FixtureName, ForkName,
      "Focused Cancun reentrancy selfdestruct revert CALL regression");
}

TEST(EVMStateFocused, ReentrancySelfdestructRevertDelegatecallCancun) {
  const evmc_revision TargetRevision = getTargetRevision();
  if (TargetRevision != EVMC_MAX_REVISION && TargetRevision != EVMC_CANCUN) {
    GTEST_SKIP() << "Focused Cancun regression skipped for requested revision";
  }

  const std::string FixturePath =
      DEFAULT_TEST_DIR +
      "/cancun/eip6780_selfdestruct/test_reentrancy_selfdestruct_revert.json";
  const std::string FixtureName =
      "tests/cancun/eip6780_selfdestruct/test_reentrancy_selfdestruct_revert."
      "py::test_reentrancy_selfdestruct_revert[fork_Cancun-state_test-"
      "second_suicide_DELEGATECALL-first_suicide_DELEGATECALL]";
  const std::string ForkName = "Cancun";

  assertFocusedFixturePasses(
      FixturePath, FixtureName, ForkName,
      "Focused Cancun reentrancy selfdestruct revert DELEGATECALL regression");
}

TEST_P(EVMStateTest, ExecutesStateTest) {
  const auto &Param = GetParam();

  if (!Param.Valid) {
    FAIL() << Param.LoadError;
    return;
  }

  ASSERT_NE(Param.Fixture, nullptr);

  ExecutionResult Result =
      executeStateTest(*Param.Fixture, Param.ForkName, Param.Expected);

  if (!Result.Passed) {
    if (!PRINT_FAILURE_DETAILS) {
      EXPECT_TRUE(Result.Passed);
      return;
    }

    std::string CombinedErrors = "\n";
    CombinedErrors += "=================================================\n";
    CombinedErrors +=
        "Post-execution state verification failed with " +
        std::to_string(Result.ErrorMessages.size()) +
        (Result.ErrorMessages.size() == 1 ? " error:" : " errors:") + "\n";
    CombinedErrors += "=================================================\n";
    for (size_t I = 0; I < Result.ErrorMessages.size(); ++I) {
      CombinedErrors += "\n[Error " + std::to_string(I + 1) + "]\n";
      CombinedErrors += Result.ErrorMessages[I];
      CombinedErrors += "\n";
    }
    CombinedErrors += "=================================================\n";
    EXPECT_TRUE(Result.Passed) << CombinedErrors;
  }
}

INSTANTIATE_TEST_SUITE_P(ExecuteAllStateTests, EVMStateTest,
                         ::testing::ValuesIn(getStateTestParams()),
                         [](const auto &Info) {
                           return sanitizeTestName(Info.param.CaseName);
                         });

} // anonymous namespace
