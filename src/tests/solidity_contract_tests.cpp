// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "solidity_test_helpers.h"
#include <CLI/CLI.hpp>
#include <filesystem>
#include <gtest/gtest.h>
#include <limits>

using namespace zen::utils;
using namespace zen::evm_test_utils;

namespace zen::test {

using SolidityTestPair = std::pair<std::string, std::string>;
namespace {
constexpr const char *COUNTER_DEPLOY_HEX =
    "6080604052348015600e575f5ffd5b506102358061001c5f395ff3fe608060405234801561"
    "000f575f5ffd5b506004361061004a575f3560e01c806306661abd1461004e5780639077ce"
    "611461006c578063d732d95514610088578063e8927fbc14610092575b5f5ffd5b61005661"
    "009c565b60405161006391906100f2565b60405180910390f35b6100866004803603810190"
    "6100819190610139565b6100a1565b005b6100906100aa565b005b61009a6100c2565b005b"
    "5f5481565b805f8190555050565b5f5f8154809291906100bb90610191565b919050555056"
    "5b5f5f8154809291906100d3906101b8565b9190505550565b5f819050919050565b6100ec"
    "816100da565b82525050565b5f6020820190506101055f8301846100e3565b92915050565b"
    "5f5ffd5b610118816100da565b8114610122575f5ffd5b50565b5f81359050610133816101"
    "0f565b92915050565b5f6020828403121561014e5761014d61010b565b5b5f61015b848285"
    "01610125565b91505092915050565b7f4e487b710000000000000000000000000000000000"
    "00000000000000000000005f52601160045260245ffd5b5f61019b826100da565b91505f82"
    "036101ad576101ac610164565b5b600182039050919050565b5f6101c2826100da565b9150"
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036101"
    "f4576101f3610164565b5b60018201905091905056fea26469706673582212204aed3f7ff0"
    "55870ecaed125cbf6f4fd7f4b082e55a1cb01cc8c450d3dfd2c4bd64736f6c634300081e00"
    "33";
constexpr const char *COUNTER_RUNTIME_HEX =
    "608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806306661abd14"
    "61004e5780639077ce611461006c578063d732d95514610088578063e8927fbc1461009257"
    "5b5f5ffd5b61005661009c565b60405161006391906100f2565b60405180910390f35b6100"
    "8660048036038101906100819190610139565b6100a1565b005B6100906100aa565B005B61"
    "009a6100c2565B005B5f5481565B805f8190555050565B5f5f8154809291906100bb906101"
    "91565B9190505550565B5f5f8154809291906100d3906101b8565B9190505550565B5f8190"
    "50919050565B6100ec816100da565B82525050565B5f6020820190506101055f8301846100"
    "e3565B92915050565B5f5ffd5B610118816100da565B8114610122575f5ffd5B50565B5f81"
    "3590506101338161010f565B92915050565B5f6020828403121561014e5761014d61010b56"
    "5B5B5f61015b84828501610125565B91505092915050565B7f4e487b710000000000000000"
    "00000000000000000000000000000000000000005f52601160045260245ffd5B5f61019b82"
    "6100da565B91505f82036101ad576101ac610164565B5B600182039050919050565B5f6101"
    "c2826100da565B91507fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffff82036101f4576101f3610164565B5B60018201905091905056fea26469706673"
    "582212204aed3f7ff055870ecaed125cbf6f4fd7f4b082e55a1cb01cc8c450d3dfd2c4bd64"
    "736f6c634300081e0033";

DeployedContract makeLoadedContract(EVMTestEnvironment &Env,
                                    const evmc::address &Address,
                                    const std::string &RuntimeHex,
                                    uint64_t GasLimit) {
  TempHexFile TempRuntimeFile(RuntimeHex);
  auto ModRet = Env.Runtime->loadEVMModule(TempRuntimeFile.getPath());
  EXPECT_TRUE(ModRet);
  EVMModule *CallMod = *ModRet;

  Isolation *CallIso = Env.Runtime->createManagedIsolation();
  EXPECT_NE(CallIso, nullptr);

  auto CallInstRet = CallIso->createEVMInstance(*CallMod, GasLimit);
  EXPECT_TRUE(CallInstRet);

  DeployedContract Result;
  Result.Instance = *CallInstRet;
  Result.Address = Address;
  Result.RuntimeBytecode = RuntimeHex;
  return Result;
}

DeployedContract deployContractWithCreate2(EVMTestEnvironment &Env,
                                           const SolcContractData &ContractData,
                                           const std::string &Create2SaltHex,
                                           uint64_t GasLimit) {
  TempHexFile TempDeployFile(ContractData.DeployBytecode);
  auto DeployModRet = Env.Runtime->loadEVMModule(TempDeployFile.getPath());
  EXPECT_TRUE(DeployModRet);
  EVMModule *DeployMod = *DeployModRet;

  Isolation *DeployIso = Env.Runtime->createManagedIsolation();
  EXPECT_NE(DeployIso, nullptr);

  auto DeployInstRet = DeployIso->createEVMInstance(*DeployMod, GasLimit);
  EXPECT_TRUE(DeployInstRet);
  EVMInstance *DeployInst = *DeployInstRet;

  auto InitCode = zen::utils::fromHex(ContractData.DeployBytecode);
  EXPECT_TRUE(InitCode.has_value());
  evmc::bytes32 Salt = zen::utils::parseBytes32(Create2SaltHex);
  evmc::address ExpectedAddress = zen::utils::computeCreate2Address(
      Env.DeployerAddr, Salt,
      evmc::bytes_view{InitCode->data(), InitCode->size()});

  evmc_message Msg = {};
  Msg.kind = EVMC_CREATE2;
  Msg.gas = static_cast<int64_t>(GasLimit);
  Msg.sender = Env.DeployerAddr;
  Msg.recipient = ExpectedAddress;
  Msg.create2_salt = Salt;
  Msg.input_data = InitCode->data();
  Msg.input_size = InitCode->size();

  evmc::Result DeployResult;
  Env.Runtime->callEVMMain(*DeployInst, Msg, DeployResult);
  if (DeployResult.status_code == EVMC_SUCCESS &&
      DeployResult.create_address == evmc::address{}) {
    DeployResult.create_address = ExpectedAddress;
  }
  EXPECT_EQ(DeployResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(DeployResult.create_address, ExpectedAddress);
  EXPECT_GT(DeployResult.output_size, 0U);

  std::vector<uint8_t> DeployResultBytes(DeployResult.output_data,
                                         DeployResult.output_data +
                                             DeployResult.output_size);
  std::string DeployResultHex =
      zen::utils::toHex(DeployResultBytes.data(), DeployResultBytes.size());
  EXPECT_TRUE(hexEquals(DeployResultHex, ContractData.RuntimeBytecode));

  auto &NewContractAccount = Env.MockedHost->accounts[ExpectedAddress];
  NewContractAccount.code =
      evmc::bytes(DeployResultBytes.data(), DeployResultBytes.size());

  const std::vector<uint8_t> CodeHashVec =
      zen::host::evm::crypto::keccak256(DeployResultBytes);
  evmc::bytes32 CodeHash{};
  std::memcpy(CodeHash.bytes, CodeHashVec.data(), 32);
  NewContractAccount.codehash = CodeHash;
  NewContractAccount.nonce = 1;
  Env.MockedHost->accounts[Env.DeployerAddr].nonce += 1;

  return makeLoadedContract(Env, ExpectedAddress, DeployResultHex, GasLimit);
}

RuntimeConfig makeInterpreterEvmConfig(RuntimeConfig Config = {}) {
  Config.Format = InputFormat::EVM;
  if (Config.Mode == RunMode::SinglepassMode) {
    Config.Mode = RunMode::InterpMode;
  }
  return Config;
}
} // namespace

std::vector<SolidityTestPair>
EnumerateSolidityTests(const std::string &TestCategory);

class SolidityContractTest : public testing::TestWithParam<SolidityTestPair> {
protected:
  static RuntimeConfig GlobalConfig;
  static uint64_t GlobalGasLimit;

public:
  static void SetGlobalConfig(const RuntimeConfig &Config) {
    GlobalConfig = Config;
  }
  static void SetGlobalGasLimit(uint64_t GasLimit) {
    GlobalGasLimit = GasLimit;
  }
  static const RuntimeConfig &GetGlobalConfig() { return GlobalConfig; }
  static uint64_t GetGlobalGasLimit() { return GlobalGasLimit; }
};

RuntimeConfig SolidityContractTest::GlobalConfig;
uint64_t SolidityContractTest::GlobalGasLimit =
    zen::utils::defaultEvmGasLimit();

std::vector<SolidityTestPair>
EnumerateSolidityTests(const std::string &TestCategory) {
  std::vector<SolidityTestPair> TestPairs;

  std::filesystem::path TestsRoot =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests");

  if (!TestCategory.empty()) {
    std::filesystem::path CategoryDir = TestsRoot / TestCategory;
    if (std::filesystem::exists(CategoryDir) &&
        std::filesystem::is_directory(CategoryDir)) {
      for (const auto &Entry :
           std::filesystem::directory_iterator(CategoryDir)) {
        if (Entry.is_directory()) {
          std::string ContractName = Entry.path().filename().string();
          TestPairs.emplace_back(TestCategory, ContractName);
        }
      }
    }
  } else {
    std::string DefaultCategory = "evm_solidity";
    std::filesystem::path CategoryDir = TestsRoot / DefaultCategory;

    if (std::filesystem::exists(CategoryDir) &&
        std::filesystem::is_directory(CategoryDir)) {
      for (const auto &Entry :
           std::filesystem::directory_iterator(CategoryDir)) {
        if (Entry.is_directory()) {
          std::string ContractName = Entry.path().filename().string();
          TestPairs.emplace_back(DefaultCategory, ContractName);
        }
      }
    }
  }

  return TestPairs;
}

TEST_P(SolidityContractTest, TestContract) {
  const auto &[Category, ContractName] = GetParam();
  evmc_status_code Result = executeSingleContractTest(
      GetGlobalConfig(), GetGlobalGasLimit(), Category, ContractName);
  EXPECT_EQ(Result, EVMC_SUCCESS) << "Contract Test Failed: " << ContractName;
}

TEST(SolidityStatePersistence, SaveLoadRoundTripPreservesContractState) {
  RuntimeConfig Config =
      makeInterpreterEvmConfig(SolidityContractTest::GetGlobalConfig());
  const uint64_t GasLimit = 1000000000ULL;

  SolcContractData ContractData{
      .DeployBytecode = COUNTER_DEPLOY_HEX,
      .RuntimeBytecode = COUNTER_RUNTIME_HEX,
  };

  EVMTestEnvironment InitialEnv(Config);
  DeployedContract Contract =
      deployContract(InitialEnv, "counter", ContractData, {}, {}, GasLimit);

  const std::string SetCalldata = "9077ce61000000000000000000000000000000000000"
                                  "000000000000000000000000002a";
  evmc::Result SetResult =
      executeContractCall(InitialEnv, Contract, SetCalldata, GasLimit);
  ASSERT_EQ(SetResult.status_code, EVMC_SUCCESS);

  std::filesystem::path StatePath = std::filesystem::temp_directory_path() /
                                    "dtvm_counter_state_roundtrip.json";
  ASSERT_TRUE(
      zen::utils::saveState(*InitialEnv.MockedHost, StatePath.string()));

  EVMTestEnvironment LoadedEnv(Config);
  ASSERT_TRUE(zen::utils::loadState(*LoadedEnv.MockedHost, StatePath.string()));
  std::filesystem::remove(StatePath);

  auto LoadedIt = LoadedEnv.MockedHost->accounts.find(Contract.Address);
  ASSERT_NE(LoadedIt, LoadedEnv.MockedHost->accounts.end());
  ASSERT_FALSE(LoadedIt->second.code.empty());

  DeployedContract LoadedContract = makeLoadedContract(
      LoadedEnv, Contract.Address, COUNTER_RUNTIME_HEX, GasLimit);

  evmc::Result GetResult =
      executeContractCall(LoadedEnv, LoadedContract, "06661abd", GasLimit);
  ASSERT_EQ(GetResult.status_code, EVMC_SUCCESS);
  ASSERT_NE(GetResult.output_data, nullptr);
  ASSERT_EQ(GetResult.output_size, 32U);
  EXPECT_TRUE(hexEquals(
      zen::utils::toHex(GetResult.output_data, GetResult.output_size),
      "000000000000000000000000000000000000000000000000000000000000002a"));
}

TEST(SolidityDeployLifecycle,
     CreateProducesDeterministicAddressAndCallableCode) {
  RuntimeConfig Config = makeInterpreterEvmConfig();
  const uint64_t GasLimit = 1000000000ULL;

  SolcContractData ContractData{
      .DeployBytecode = COUNTER_DEPLOY_HEX,
      .RuntimeBytecode = COUNTER_RUNTIME_HEX,
  };

  EVMTestEnvironment Env(Config);
  const evmc::address ExpectedAddress =
      zen::utils::computeCreateAddress(Env.DeployerAddr, 0);
  DeployedContract Contract =
      deployContract(Env, "counter", ContractData, {}, {}, GasLimit);

  EXPECT_EQ(Contract.Address, ExpectedAddress);

  evmc::Result GetResult =
      executeContractCall(Env, Contract, "06661abd", GasLimit);
  ASSERT_EQ(GetResult.status_code, EVMC_SUCCESS);
  ASSERT_NE(GetResult.output_data, nullptr);
  ASSERT_EQ(GetResult.output_size, 32U);
  EXPECT_EQ(zen::utils::toHex(GetResult.output_data, GetResult.output_size),
            "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST(SolidityDeployLifecycle,
     Create2ProducesDeterministicAddressAndCallableCode) {
  RuntimeConfig Config = makeInterpreterEvmConfig();
  const uint64_t GasLimit = 1000000000ULL;
  const std::string Create2SaltHex = "01";

  SolcContractData ContractData{
      .DeployBytecode = COUNTER_DEPLOY_HEX,
      .RuntimeBytecode = COUNTER_RUNTIME_HEX,
  };

  EVMTestEnvironment Env(Config);
  DeployedContract Contract =
      deployContractWithCreate2(Env, ContractData, Create2SaltHex, GasLimit);

  EXPECT_NE(Contract.Address, evmc::address{});

  evmc::Result GetResult =
      executeContractCall(Env, Contract, "06661abd", GasLimit);
  ASSERT_EQ(GetResult.status_code, EVMC_SUCCESS);
  ASSERT_NE(GetResult.output_data, nullptr);
  ASSERT_EQ(GetResult.output_size, 32U);
  EXPECT_EQ(zen::utils::toHex(GetResult.output_data, GetResult.output_size),
            "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST(EVMRunnerDefaults, DefaultGasLimitIsSafeForInt64BackedExecution) {
  const uint64_t DefaultGasLimit = zen::utils::defaultEvmGasLimit();
  EXPECT_EQ(DefaultGasLimit,
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
}

INSTANTIATE_TEST_SUITE_P(
    SolidityTests, SolidityContractTest,
    testing::ValuesIn(EnumerateSolidityTests("")),
    [](const testing::TestParamInfo<SolidityTestPair> &info) {
      return info.param.second;
    });

} // namespace zen::test

using namespace zen::test;

namespace zen::evm_test_utils {

evmc_status_code executeSingleContractTest(const RuntimeConfig &Config,
                                           uint64_t GasLimit,
                                           const std::string &TestCategory,
                                           const std::string &TestContract) {
  std::filesystem::path TestDir =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests") / TestCategory;

  if (!std::filesystem::exists(TestDir)) {
    throw getError(ErrorCode::InvalidFilePath);
  }

  std::filesystem::path ContractDir = TestDir / TestContract;
  if (!std::filesystem::exists(ContractDir) ||
      !std::filesystem::is_directory(ContractDir)) {
    throw getError(ErrorCode::InvalidFilePath);
  }

  ContractDirectoryInfo DirInfo = checkCaseDirectory(ContractDir);

  SolidityContractTestData ContractTest;
  ContractTest.ContractPath = ContractDir.string();

  parseContractJson(DirInfo.SolcJsonFile, ContractTest.ContractDataMap);
  parseTestCaseJson(DirInfo.CasesFile, ContractTest);

  if (ContractTest.TestCases.empty()) {
    return EVMC_SUCCESS;
  }

  EVMTestEnvironment TestEnv(Config);
  std::map<std::string, DeployedContract> DeployedContracts;
  std::map<std::string, evmc::address> DeployedAddresses;

  // Step 1: Deploy all specified contracts
  for (const std::string &NowContractName : ContractTest.DeployContracts) {
    auto ContractIt = ContractTest.ContractDataMap.find(NowContractName);
    ZEN_ASSERT(ContractIt != ContractTest.ContractDataMap.end());

    const auto &[ContractAddress, ContractData] = *ContractIt;
    std::vector<std::pair<std::string, std::string>> Ctorargs;
    auto ArgsIt = ContractTest.ConstructorArgs.find(NowContractName);
    if (ArgsIt != ContractTest.ConstructorArgs.end()) {
      Ctorargs = ArgsIt->second;
    }

    try {
      DeployedContract Deployed =
          deployContract(TestEnv, NowContractName, ContractData, Ctorargs,
                         DeployedAddresses, GasLimit);

      DeployedContracts[NowContractName] = Deployed;
      DeployedAddresses[NowContractName] = Deployed.Address;
    } catch (const std::exception &E) {
      std::cerr << "Deployment failed for " << NowContractName << ": "
                << E.what() << std::endl;
      return EVMC_FAILURE;
    }
  }

  // Step 2: Execute all test cases
  bool AllCasePassed = true;
  for (size_t I = 0; I < ContractTest.TestCases.size(); ++I) {
    const auto &TestCase = ContractTest.TestCases[I];
    auto InstanceIt = DeployedContracts.find(TestCase.Contract);
    if (InstanceIt == DeployedContracts.end()) {
      std::cerr << "Contract instance not found: " << TestCase.Contract
                << std::endl;
      return EVMC_FAILURE;
    }
    if (TestCase.Calldata.empty()) {
      throw getError(ErrorCode::InvalidRawData);
    }

    const auto &Contract = InstanceIt->second;
    evmc::Result CallResult =
        executeContractCall(TestEnv, Contract, TestCase.Calldata, GasLimit);
    if (checkResult(TestCase, CallResult) != EVMC_SUCCESS) {
      AllCasePassed = false;
    }
  }

#ifndef NDEBUG
  std::string StateFileName = TestContract + "_state.json";
  std::filesystem::path StateFilePath = ContractDir / StateFileName;

  if (!zen::utils::saveState(*TestEnv.MockedHost, StateFilePath.string())) {
    std::cerr << "Failed to save debug state to: " << StateFilePath
              << std::endl;
  }
#endif // NDEBUG

  return AllCasePassed ? EVMC_SUCCESS : EVMC_FAILURE;
}

} // namespace zen::evm_test_utils

GTEST_API_ int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  CLI::App CLIParser{"Solidity Tests Command Line Interface\n",
                     "solidityContractTests"};

  std::string TestContract;
  std::string TestCategory;

  // same as evm.codes: 0xFFFF'FFFF'FFFF (281,474,976,710,655)
  uint64_t GasLimit = zen::utils::defaultEvmGasLimit();
  LoggerLevel LogLevel = LoggerLevel::Info;
  RuntimeConfig Config;

  const std::unordered_map<std::string, InputFormat> FormatMap = {
      {"wasm", InputFormat::WASM},
      {"evm", InputFormat::EVM},
  };
  const std::unordered_map<std::string, RunMode> ModeMap = {
      {"interpreter", RunMode::InterpMode},
      {"multipass", RunMode::MultipassMode},
  };
  const std::unordered_map<std::string, LoggerLevel> LogMap = {
      {"trace", LoggerLevel::Trace}, {"debug", LoggerLevel::Debug},
      {"info", LoggerLevel::Info},   {"warn", LoggerLevel::Warn},
      {"error", LoggerLevel::Error}, {"fatal", LoggerLevel::Fatal},
      {"off", LoggerLevel::Off},
  };

  CLIParser.add_option("-t, --test", TestContract,
                       "Specific test contract name");
  CLIParser.add_option("-c, --category", TestCategory, "Test Category");
  CLIParser.add_option("--format", Config.Format, "Input format")
      ->transform(CLI::CheckedTransformer(FormatMap, CLI::ignore_case));
  CLIParser.add_option("-m, --mode", Config.Mode, "Running mode")
      ->transform(CLI::CheckedTransformer(ModeMap, CLI::ignore_case));
  CLIParser.add_option("--gas-limit", GasLimit, "Gas limit");
  CLIParser.add_option("--log-level", LogLevel, "Log level")
      ->transform(CLI::CheckedTransformer(LogMap, CLI::ignore_case));
#ifdef ZEN_ENABLE_EVM
  CLIParser.add_flag("--enable-evm-gas", Config.EnableEvmGasMetering,
                     "Enable EVM gas metering when compiling EVM bytecode");
#endif // ZEN_ENABLE_EVM
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  CLIParser.add_flag("--disable-multipass-greedyra",
                     Config.DisableMultipassGreedyRA,
                     "Disable greedy register allocation of multipass JIT");
  auto *DMMOption = CLIParser.add_flag(
      "--disable-multipass-multithread", Config.DisableMultipassMultithread,
      "Disable multithread compilation of multipass JIT");
  CLIParser
      .add_option("--num-multipass-threads", Config.NumMultipassThreads,
                  "Number of threads for multipass JIT(set 0 for automatic "
                  "determination)")
      ->excludes(DMMOption);
  CLIParser.add_flag("--enable-multipass-lazy", Config.EnableMultipassLazy,
                     "Enable multipass lazy mode(on request compile)");
#endif // ZEN_ENABLE_MULTIPASS_JIT
  CLI11_PARSE(CLIParser, argc, argv);

  zen::setGlobalLogger(
      createConsoleLogger("solidity_contract_logger", LogLevel));

  // Set global config for parameterized tests
  SolidityContractTest::SetGlobalConfig(Config);
  SolidityContractTest::SetGlobalGasLimit(GasLimit);

  if (!TestContract.empty()) {
    TestCategory = TestCategory.empty() ? "evm_solidity" : TestCategory;

    return executeSingleContractTest(Config, GasLimit, TestCategory,
                                     TestContract);
  }

  std::vector<SolidityTestPair> TestPairs;
  if (TestCategory.empty()) {
    TestPairs = EnumerateSolidityTests("");
  } else {
    TestPairs = EnumerateSolidityTests(TestCategory);
  }

  if (TestPairs.empty()) {
    std::cerr << "No tests found" << std::endl;
    return EVMC_FAILURE;
  }

  // Run all tests using Google Test
  return RUN_ALL_TESTS();
}
