// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/codeholder.h"
#include "utils/logging.h"
#include "utils/others.h"
#include "utils/statistics.h"
#include "zetaengine.h"
#include <CLI/CLI.hpp>
#ifdef ZEN_ENABLE_EVM
#include "host/evm/crypto.h"
#include "tests/evm_test_host.hpp"
#include "utils/evm.h"
#endif // ZEN_ENABLE_EVM
#include <fstream>
#include <limits>
#include <unistd.h>

#ifdef ZEN_ENABLE_BUILTIN_WASI
#include "host/wasi/wasi.h"
#endif

#ifdef ZEN_ENABLE_BUILTIN_ENV
#include "host/env/env.h"
#endif

#ifdef ZEN_ENABLE_EVMABI_TEST
#include "host/evmabimock/evmabimock.h"
#endif

#ifdef ZEN_ENABLE_PROFILER
#include <gperftools/profiler.h>
#endif

using namespace zen::common;
using namespace zen::runtime;
using namespace zen::utils;

int exitMain(int ExitCode, Runtime *RT = nullptr) {
  if (RT) {
    RT->getStatistics().report();
  }

#ifdef ZEN_ENABLE_PROFILER
  ProfilerStop();
#endif

  return ExitCode;
}

// when evmabi test enabled, we need fuzz test by cli, so we need all output
// fixed
#ifdef ZEN_ENABLE_EVMABI_TEST
#define SIMPLE_LOG_ERROR(...)                                                  \
  printf(__VA_ARGS__);                                                         \
  printf("\n");
#else
#define SIMPLE_LOG_ERROR(...) ZEN_LOG_ERROR(__VA_ARGS__)
#endif // ZEN_ENABLE_EVMABI_TEST

#ifdef ZEN_ENABLE_EVM
struct EVMMessageConfig {
  evmc_call_kind Kind;
  uint64_t GasLimit;
  std::vector<uint8_t> Calldata;
  std::string SenderAddress;
  std::string ContractAddress;
  std::string Create2Salt;
  evmc::uint256be Value;
};

static evmc_message createEvmMessage(evmc::MockedHost &Host,
                                     const EVMMessageConfig &Config,
                                     const std::vector<uint8_t> &Bytecode) {
  evmc_message Msg{
      .kind = Config.Kind,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(Config.GasLimit),
      .recipient = {},
      .sender = {},
      .input_data = nullptr,
      .input_size = 0,
      .value = {},
      .create2_salt = {},
      .code_address = {},
      .code = {}, // code will load in callEVMMain
      .code_size = 0,
  };

  if (!Config.Calldata.empty()) {
    Msg.input_data = Config.Calldata.data();
    Msg.input_size = Config.Calldata.size();
  }

  if (EVMC_CREATE == Config.Kind) {
    Msg.input_data = Bytecode.data();
    Msg.input_size = Bytecode.size();

    evmc::address DeployerAddr = zen::utils::parseAddress(Config.SenderAddress);
    auto &DeployerAccount = Host.accounts[DeployerAddr];
    DeployerAccount.nonce = 0;
    DeployerAccount.set_balance(100000000UL);
    Msg.recipient = computeCreateAddress(DeployerAddr, DeployerAccount.nonce);
    Msg.sender = DeployerAddr;
  } else if (EVMC_CREATE2 == Config.Kind) {
    Msg.input_data = Bytecode.data();
    Msg.input_size = Bytecode.size();

    evmc::address DeployerAddr = zen::utils::parseAddress(Config.SenderAddress);
    auto &DeployerAccount = Host.accounts[DeployerAddr];
    DeployerAccount.nonce = 0;
    DeployerAccount.set_balance(100000000UL);
    Msg.sender = DeployerAddr;
    Msg.create2_salt = zen::utils::parseBytes32(Config.Create2Salt);
    Msg.recipient = computeCreate2Address(
        DeployerAddr, Msg.create2_salt,
        evmc::bytes_view{Bytecode.data(), Bytecode.size()});
  } else {
    evmc::address ContractAddr =
        zen::utils::parseAddress(Config.ContractAddress);
    Msg.recipient = ContractAddr;
    Msg.sender = zen::utils::parseAddress(Config.SenderAddress);
    Msg.code_address = ContractAddr;
  }
  Msg.value = Config.Value;

  return Msg;
}

static bool loadEVMHexFileBytes(const std::string &Filename,
                                std::vector<uint8_t> &Bytecode) {
  if (Filename.empty()) {
    return false;
  }

  std::ifstream File(Filename);
  if (!File.is_open()) {
    return false;
  }

  std::string HexContent((std::istreambuf_iterator<char>(File)),
                         std::istreambuf_iterator<char>());
  utils::trimString(HexContent);

  auto DecodedBytes = utils::fromHex(std::string_view(HexContent));
  if (!DecodedBytes.has_value()) {
    return false;
  }

  Bytecode = std::move(*DecodedBytes);
  return true;
}

static bool runEVMBenchmark(const std::string &Filename,
                            uint32_t NumExtraCompilations,
                            uint32_t NumExtraExecutions, Runtime *RT,
                            EVMModule *Mod, const EVMMessageConfig &MsgConfig,
                            evmc::MockedHost &Host) {
  if (NumExtraCompilations + NumExtraExecutions == 0) {
    return true;
  }

  std::vector<uint8_t> Bytecode;
  if (!zen::utils::readBinaryFile(Filename, Bytecode)) {
    SIMPLE_LOG_ERROR("failed to read EVM bytecode file %s", Filename.c_str());
    return false;
  }

  for (uint32_t I = 0; I < NumExtraCompilations; ++I) {
    std::string NewEvmName = Filename + std::to_string(I);
    MayBe<EVMModule *> TestModRet =
        RT->loadEVMModule(NewEvmName, Bytecode.data(), Bytecode.size());
    ZEN_ASSERT(TestModRet);
    RT->unloadEVMModule(*TestModRet);
  }

  for (uint32_t I = 0; I < NumExtraExecutions; ++I) {
    IsolationUniquePtr TestIso = RT->createUnmanagedIsolation();
    ZEN_ASSERT(TestIso);
    MayBe<EVMInstance *> TestInstRet =
        TestIso->createEVMInstance(*Mod, MsgConfig.GasLimit);
    ZEN_ASSERT(TestInstRet);
    EVMInstance *TestInst = *TestInstRet;
    evmc_message TestMsg = createEvmMessage(Host, MsgConfig, Bytecode);
    evmc::Result TestExeResult;
    RT->callEVMMain(*TestInst, TestMsg, TestExeResult);
  }

  return true;
}
#endif // ZEN_ENABLE_EVM

int main(int argc, char *argv[]) {
#ifdef ZEN_ENABLE_PROFILER
  ProfilerStart("dtvm.prof");
#endif

  std::unique_ptr<CLI::App> CLIParser;
  try {
    CLIParser = std::make_unique<CLI::App>(
        "ZetaEngine Command Line Interface\n", "dtvm");
  } catch (const std::exception &E) {
    printf("failed to create CLI parser: %s\n", E.what());
    return exitMain(EXIT_FAILURE);
  }

  std::string Filename;
  std::string FuncName;
  std::string EntryHint;
  std::string Calldata;
  std::vector<std::string> Args;
  std::vector<std::string> Envs;
  std::vector<std::string> Dirs;
  std::string SaveStateFile;
  std::string LoadStateFile;
#ifdef ZEN_ENABLE_EVM
  uint64_t GasLimit = zen::utils::defaultEvmGasLimit();
#else
  uint64_t GasLimit = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
#endif
  LoggerLevel LogLevel = LoggerLevel::Info;
  uint32_t NumExtraCompilations = 0;
  uint32_t NumExtraExecutions = 0;
  RuntimeConfig Config;
  bool EnableBenchmark = false;
  bool DeployMode = false;
  std::string ContractAddress;
  std::string ContractAddressOutFile;
  std::string EVMBytecodeKind = "auto";
  std::string Create2Salt;
  std::string SenderAddress = "1000000000000000000000000000000000000000";
  std::string TxOriginAddress;
  std::string TxGasPriceHex = "0x0";
  std::string ValueHex = "0x0";
  std::string ChainIdHex = "0x1";
  std::string CoinbaseAddress = "0000000000000000000000000000000000000000";
  std::string PrevRandaoHex = "0x0";
  std::string BaseFeeHex = "0x0";
  std::string BlobBaseFeeHex = "0x0";
  int64_t BlockNumber = 0;
  int64_t BlockTimestamp = 0;
  int64_t BlockGasLimit = 0;

  const std::unordered_map<std::string, InputFormat> FormatMap = {
      {"wasm", InputFormat::WASM},
      {"evm", InputFormat::EVM},
  };
  const std::unordered_map<std::string, RunMode> ModeMap = {
      {"interpreter", RunMode::InterpMode},
#ifndef ZEN_ENABLE_EVM
      {"singlepass", RunMode::SinglepassMode},
#endif // ZEN_ENABLE_EVM
      {"multipass", RunMode::MultipassMode},
  };
  const std::unordered_map<std::string, LoggerLevel> LogMap = {
      {"trace", LoggerLevel::Trace}, {"debug", LoggerLevel::Debug},
      {"info", LoggerLevel::Info},   {"warn", LoggerLevel::Warn},
      {"error", LoggerLevel::Error}, {"fatal", LoggerLevel::Fatal},
      {"off", LoggerLevel::Off},
  };
  const std::unordered_map<std::string, std::string> EVMBytecodeKindMap = {
      {"auto", "auto"},
      {"deploy", "deploy"},
      {"runtime", "runtime"},
  };

  try {
    CLIParser->add_option("INPUT_FILE", Filename, "input filename")->required();
    CLIParser->add_option("--format", Config.Format, "Input format")
        ->transform(CLI::CheckedTransformer(FormatMap, CLI::ignore_case));
    CLIParser->add_option("-m,--mode", Config.Mode, "Running mode")
        ->transform(CLI::CheckedTransformer(ModeMap, CLI::ignore_case));
    CLIParser->add_option("-f,--function", FuncName, "Entry function name");
    CLIParser->add_option("--args", Args, "Entry function args");
    CLIParser->add_option("--env", Envs, "Environment variables");
    CLIParser->add_option("--dir", Dirs, "Work directories");
    CLIParser->add_option("--gas-limit", GasLimit, "Gas limit");
    CLIParser->add_option("--log-level", LogLevel, "Log level")
        ->transform(CLI::CheckedTransformer(LogMap, CLI::ignore_case));
    CLIParser->add_option("--save-state", SaveStateFile,
                          "Save EVM state to file");
    CLIParser->add_option("--load-state", LoadStateFile,
                          "Load EVM state from file");
    CLIParser->add_flag("--deploy", DeployMode, "Deploy contract mode");
    CLIParser->add_option("--contract-address", ContractAddress,
                          "Contract address for call mode");
    CLIParser->add_option("--contract-address-out", ContractAddressOutFile,
                          "Write deployed contract address to file");
    CLIParser
        ->add_option("--evm-bytecode-kind", EVMBytecodeKind,
                     "Interpret INPUT_FILE as deploy or runtime bytecode")
        ->transform(
            CLI::CheckedTransformer(EVMBytecodeKindMap, CLI::ignore_case));
    CLIParser->add_option("--create2-salt", Create2Salt,
                          "CREATE2 salt for deploy mode");
    CLIParser->add_option("--sender", SenderAddress,
                          "Sender address for transactions");
    CLIParser->add_option("--tx-origin", TxOriginAddress,
                          "Transaction origin address for EVM context");
    CLIParser->add_option(
        "--tx-gas-price", TxGasPriceHex,
        "Transaction gas price as uint256 hex for EVM context");
    CLIParser->add_option("--value", ValueHex,
                          "Call value as uint256 hex for EVM execution");
    CLIParser->add_option("--chain-id", ChainIdHex,
                          "Chain ID as uint256 hex for EVM context");
    CLIParser->add_option("--coinbase", CoinbaseAddress,
                          "Coinbase address for EVM block context");
    CLIParser->add_option("--block-number", BlockNumber,
                          "Block number for EVM block context");
    CLIParser->add_option("--block-timestamp", BlockTimestamp,
                          "Block timestamp for EVM block context");
    CLIParser->add_option("--block-gas-limit", BlockGasLimit,
                          "Block gas limit for EVM block context");
    CLIParser->add_option("--base-fee", BaseFeeHex,
                          "Base fee as uint256 hex for EVM block context");
    CLIParser->add_option("--prev-randao", PrevRandaoHex,
                          "PrevRandao as bytes32 hex for EVM block context");
    CLIParser->add_option("--blob-base-fee", BlobBaseFeeHex,
                          "Blob base fee as uint256 hex for EVM block context");
    CLIParser->add_option("--num-extra-compilations", NumExtraCompilations,
                          "The number of extra compilations");
    CLIParser->add_option("--num-extra-executions", NumExtraExecutions,
                          "The number of extra executions");
    CLIParser->add_flag("--enable-statistics", Config.EnableStatistics,
                        "Enable statistics");
    CLIParser->add_flag("--disable-wasm-memory-map",
                        Config.DisableWasmMemoryMap, "Disable wasm memory map");
    CLIParser->add_flag("--benchmark", EnableBenchmark, "Enable benchmark");
    // If you want to trace the cpu instructions of wasm func,
    // you can qemu-x86_64 -cpu qemu64,+ssse3,+sse4.1,+sse4.2,+x2apic
    // -singlestep -d in_asm -strace dtvm $ARGS_OF_DTVM 2>&1 | tee trace.log
    // then grep the lines in trace.log between ""
    CLIParser->add_flag(
        "--enable-gdb-tracing-hook", Config.EnableGdbTracingHook,
        "Enable gdb cpu instruction tracing hook(then can trace cpu "
        "instructions when executing wasm in gdb)");
#ifdef ZEN_ENABLE_MULTIPASS_JIT
    CLIParser->add_flag("--disable-multipass-greedyra",
                        Config.DisableMultipassGreedyRA,
                        "Disable greedy register allocation of multipass JIT");
    auto *DMMOption = CLIParser->add_flag(
        "--disable-multipass-multithread", Config.DisableMultipassMultithread,
        "Disable multithread compilation of multipass JIT");
    CLIParser
        ->add_option("--num-multipass-threads", Config.NumMultipassThreads,
                     "Number of threads for multipass JIT(set 0 for automatic "
                     "determination)")
        ->excludes(DMMOption);
    CLIParser->add_flag("--enable-multipass-lazy", Config.EnableMultipassLazy,
                        "Enable multipass lazy mode(on request compile)");
    CLIParser->add_option("--entry-hint", EntryHint, "Entry function hint");
#ifdef ZEN_ENABLE_EVM
    CLIParser->add_flag("--enable-evm-gas", Config.EnableEvmGasMetering,
                        "Enable EVM gas metering when compiling EVM bytecode");
    CLIParser->add_option("--calldata", Calldata, "Calldata hex pass to EVM");
#endif // ZEN_ENABLE_EVM
#endif // ZEN_ENABLE_MULTIPASS_JIT

    CLI11_PARSE(*CLIParser, argc, argv);
  } catch (const std::exception &E) {
    printf("failed to parse command line arguments: %s\n", E.what());
    return exitMain(EXIT_FAILURE);
  }

  try {
    zen::setGlobalLogger(createConsoleLogger("dtvm_cli_logger", LogLevel));
  } catch (const std::exception &E) {
    ZEN_LOG_ERROR("failed to create logger: %s", E.what());
    return exitMain(EXIT_FAILURE);
  }

  /// ================ EVM mode ================
#ifdef ZEN_ENABLE_EVM
  if (Config.Format == InputFormat::EVM) {
    if (GasLimit > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      ZEN_LOG_ERROR("gas limit out of range for EVM execution: %llu",
                    static_cast<unsigned long long>(GasLimit));
      return exitMain(EXIT_FAILURE);
    }
    if (!Create2Salt.empty() && !DeployMode) {
      ZEN_LOG_ERROR("--create2-salt requires --deploy");
      return exitMain(EXIT_FAILURE);
    }
    if (!ContractAddressOutFile.empty() && !DeployMode) {
      ZEN_LOG_ERROR("--contract-address-out requires --deploy");
      return exitMain(EXIT_FAILURE);
    }
    if (DeployMode && EVMBytecodeKind == "runtime") {
      ZEN_LOG_ERROR(
          "--deploy requires deploy bytecode; got --evm-bytecode-kind=runtime");
      return exitMain(EXIT_FAILURE);
    }
    if (!DeployMode && EVMBytecodeKind == "deploy") {
      ZEN_LOG_ERROR("EVM call mode requires runtime bytecode; got "
                    "--evm-bytecode-kind=deploy");
      return exitMain(EXIT_FAILURE);
    }
    if (!DeployMode && ContractAddress.empty() && !Calldata.empty()) {
      ZEN_LOG_ERROR("--contract-address is required for calldata-driven EVM "
                    "call mode");
      return exitMain(EXIT_FAILURE);
    }
    auto MockedEVMHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
    if (!TxOriginAddress.empty()) {
      MockedEVMHost->tx_context.tx_origin =
          zen::utils::parseAddress(TxOriginAddress);
    }
    MockedEVMHost->tx_context.tx_gas_price =
        zen::utils::parseUint256(TxGasPriceHex);
    MockedEVMHost->tx_context.chain_id = zen::utils::parseUint256(ChainIdHex);
    MockedEVMHost->tx_context.block_coinbase =
        zen::utils::parseAddress(CoinbaseAddress);
    MockedEVMHost->tx_context.block_number = BlockNumber;
    MockedEVMHost->tx_context.block_timestamp = BlockTimestamp;
    MockedEVMHost->tx_context.block_gas_limit = BlockGasLimit;
    MockedEVMHost->tx_context.block_prev_randao =
        zen::utils::parseBytes32(PrevRandaoHex);
    MockedEVMHost->tx_context.block_base_fee =
        zen::utils::parseUint256(BaseFeeHex);
    MockedEVMHost->tx_context.blob_base_fee =
        zen::utils::parseUint256(BlobBaseFeeHex);
    // Load state if specified
    if (!LoadStateFile.empty() &&
        !zen::utils::loadState(*MockedEVMHost, LoadStateFile)) {
      ZEN_LOG_ERROR("failed to load state from file: %s",
                    LoadStateFile.c_str());
      return exitMain(EXIT_FAILURE);
    }

    // std::unique_ptr<evmc::Host> Host = std::move(MockedEVMHost);
    auto &MockedHost = *MockedEVMHost;
    std::unique_ptr<evmc::Host> Host = std::move(MockedEVMHost);
    std::unique_ptr<Runtime> RT = Runtime::newEVMRuntime(Config, Host.get());
    if (!RT) {
      ZEN_LOG_ERROR("failed to create runtime");
      return exitMain(EXIT_FAILURE);
    }

    // Set runtime for ZenMockedEVMHost
    MockedHost.setRuntime(RT.get());

    MayBe<EVMModule *> ModRet = RT->loadEVMModule(Filename);
    if (!ModRet) {
      const Error &Err = ModRet.getError();
      ZEN_ASSERT(!Err.isEmpty());
      const auto &ErrMsg = Err.getFormattedMessage(false);
      SIMPLE_LOG_ERROR("failed to load module: %s, %s", ErrMsg.c_str(),
                       Filename.c_str());
      return exitMain(EXIT_FAILURE, RT.get());
    }
    EVMModule *Mod = *ModRet;

    Isolation *Iso = RT->createManagedIsolation();
    if (!Iso) {
      ZEN_LOG_ERROR("failed to create EVM isolation");
      return exitMain(EXIT_FAILURE, RT.get());
    }

    MayBe<EVMInstance *> InstRet = Iso->createEVMInstance(*Mod, GasLimit);
    if (!InstRet) {
      const Error &Err = InstRet.getError();
      ZEN_ASSERT(!Err.isEmpty());
      const auto &ErrMsg = Err.getFormattedMessage(false);
      SIMPLE_LOG_ERROR("failed to create EVM instance: %s", ErrMsg.c_str());
      return exitMain(EXIT_FAILURE, RT.get());
    }
    EVMInstance *Inst = *InstRet;
    evmc_call_kind MsgKind = EVMC_CALL;
    if (DeployMode) {
      MsgKind = Create2Salt.empty() ? EVMC_CREATE : EVMC_CREATE2;
    }
    evmc::Result ExeResult;
    std::vector<uint8_t> Bytecode;
    if (EVMC_CREATE == MsgKind) {
      if (!loadEVMHexFileBytes(Filename, Bytecode)) {
        SIMPLE_LOG_ERROR("failed to read deploy bytecode from hex file: %s",
                         Filename.c_str());
        return exitMain(EXIT_FAILURE, RT.get());
      }
    }

    static thread_local std::vector<uint8_t> CalldataBytes;
    CalldataBytes.clear();
    if (!Calldata.empty()) {
      auto Bytes = zen::utils::fromHex(Calldata);
      if (Bytes.has_value()) {
        CalldataBytes = std::move(*Bytes);
      }
    }

    EVMMessageConfig MsgConfig{.Kind = MsgKind,
                               .GasLimit = GasLimit,
                               .Calldata = CalldataBytes,
                               .SenderAddress = SenderAddress,
                               .ContractAddress = ContractAddress,
                               .Create2Salt = Create2Salt,
                               .Value = zen::utils::parseUint256(ValueHex)};
    evmc_message Msg = createEvmMessage(MockedHost, MsgConfig, Bytecode);
    RT->callEVMMain(*Inst, Msg, ExeResult);

    if (EVMC_CREATE == MsgKind || EVMC_CREATE2 == MsgKind) {
      ExeResult.create_address = Msg.recipient;
      if (ExeResult.status_code == EVMC_SUCCESS) {
        auto &NewContractAccount = MockedHost.accounts[Msg.recipient];
        if (ExeResult.output_data && ExeResult.output_size > 0) {
          std::vector<uint8_t> DeployResultBytes(ExeResult.output_data,
                                                 ExeResult.output_data +
                                                     ExeResult.output_size);
          NewContractAccount.code =
              evmc::bytes(DeployResultBytes.data(), DeployResultBytes.size());
          const std::vector<uint8_t> CodeHashVec =
              zen::host::evm::crypto::keccak256(DeployResultBytes);
          evmc::bytes32 CodeHash{};
          std::memcpy(CodeHash.bytes, CodeHashVec.data(),
                      sizeof(CodeHash.bytes));
          NewContractAccount.codehash = CodeHash;
        } else {
          NewContractAccount.code.clear();
          NewContractAccount.codehash = evmc::bytes32{};
        }
        NewContractAccount.nonce = 1;
      }

      evmc::address DeployerAddr = zen::utils::parseAddress(SenderAddress);
      auto &DeployerAccount = MockedHost.accounts[DeployerAddr];
      DeployerAccount.nonce++;
    }

    // Use EVM status code directly as process exit code
    int ExitCode = static_cast<int>(ExeResult.status_code);
    printf("status code: %d\n", ExitCode);
    printf("status: %s\n", evmc::to_string(ExeResult.status_code));
    printf("gas left: %lld\n", static_cast<long long>(ExeResult.gas_left));
    if (EVMC_CREATE == MsgKind || EVMC_CREATE2 == MsgKind) {
      printf("contract address: %s\n",
             zen::utils::addressToHex(ExeResult.create_address).c_str());
      if (ExeResult.status_code == EVMC_SUCCESS &&
          !ContractAddressOutFile.empty()) {
        std::ofstream OutFile(ContractAddressOutFile);
        if (!OutFile.is_open()) {
          ZEN_LOG_ERROR("failed to open contract address output file: %s",
                        ContractAddressOutFile.c_str());
          return exitMain(EXIT_FAILURE, RT.get());
        }
        OutFile << zen::utils::addressToHex(ExeResult.create_address) << '\n';
      }
    }
    if (ExeResult.output_data && ExeResult.output_size > 0) {
      std::string output =
          zen::utils::toHex(ExeResult.output_data, ExeResult.output_size);
      if (ExeResult.status_code == EVMC_REVERT) {
        printf("revert data: 0x%s\n", output.c_str());
      } else {
        printf("output: 0x%s\n", output.c_str());
      }
    }

    if (!SaveStateFile.empty()) {
      auto *MockedHostPtr = static_cast<evmc::MockedHost *>(Host.get());
      if (MockedHostPtr) {
        if (!zen::utils::saveState(*MockedHostPtr, SaveStateFile)) {
          ZEN_LOG_ERROR("failed to save state to file: %s",
                        SaveStateFile.c_str());
          return exitMain(EXIT_FAILURE, RT.get());
        }
      }
    }

    /// ======= EVM Extra compilations and executions for benchmarking =======
    if (!runEVMBenchmark(Filename, NumExtraCompilations, NumExtraExecutions,
                         RT.get(), Mod, MsgConfig,
                         *static_cast<evmc::MockedHost *>(Host.get()))) {
      return exitMain(EXIT_FAILURE, RT.get());
    }

#ifdef NDEBUG
    if (EnableBenchmark) {
      _exit(ExitCode);
    }
#endif

    if (!RT->unloadEVMModule(Mod)) {
      ZEN_LOG_ERROR("failed to unload EVM module");
      return exitMain(EXIT_FAILURE, RT.get());
    }

    if (!Iso->deleteEVMInstance(Inst)) {
      ZEN_LOG_ERROR("failed to delete instance");
      return exitMain(EXIT_FAILURE, RT.get());
    }

    return exitMain(ExitCode, RT.get());
  }
#endif // ZEN_ENABLE_EVM

  /// ================ Create ZetaEngine runtime ================

  std::unique_ptr<Runtime> RT = Runtime::newRuntime(Config);
  if (!RT) {
    ZEN_LOG_ERROR("failed to create runtime");
    return exitMain(EXIT_FAILURE);
  }

  /// ================ Load WASI module ================

#ifdef ZEN_ENABLE_BUILTIN_WASI
  RT->setWASIArgs(Filename, Args);
  RT->setWASIEnvs(Envs);
  RT->setWASIDirs(Dirs);
  HostModule *WASIMod = LOAD_HOST_MODULE(RT, zen::host, wasi_snapshot_preview1);
  if (!WASIMod) {
    ZEN_LOG_ERROR("failed to load WASI module");
    return exitMain(EXIT_FAILURE, RT.get());
  }
#endif

  /// ================ Load env module ================

#ifdef ZEN_ENABLE_BUILTIN_ENV
  HostModule *EnvMod = LOAD_HOST_MODULE(RT, zen::host, env);
  if (!EnvMod) {
    ZEN_LOG_ERROR("failed to load env module");
    return exitMain(EXIT_FAILURE, RT.get());
  }
#endif

  /// =============== Load evmabi mock module ================

#ifdef ZEN_ENABLE_EVMABI_TEST
  HostModule *EvmAbiMockMod = LOAD_HOST_MODULE(RT, zen::host, env);
  if (!EvmAbiMockMod) {
    ZEN_LOG_ERROR("failed to load evmabi mock module");
    return exitMain(EXIT_FAILURE, RT.get());
  }
#endif

  /// ================ Load user's module ================

  const auto &ActualEntryHint = !EntryHint.empty() ? EntryHint : FuncName;
  MayBe<Module *> ModRet = RT->loadModule(Filename, ActualEntryHint);
  if (!ModRet) {
    const Error &Err = ModRet.getError();
    ZEN_ASSERT(!Err.isEmpty());
    const auto &ErrMsg = Err.getFormattedMessage(false);
    SIMPLE_LOG_ERROR("failed to load module: %s", ErrMsg.c_str());
    return exitMain(EXIT_FAILURE, RT.get());
  }
  Module *Mod = *ModRet;

  /// ================ Create isolation ================

  Isolation *Iso = RT->createManagedIsolation();
  if (!Iso) {
    ZEN_LOG_ERROR("failed to create managed isolation");
    return exitMain(EXIT_FAILURE, RT.get());
  }

  /// ================ Create instance ================

  MayBe<Instance *> InstRet = Iso->createInstance(*Mod, GasLimit);
  if (!InstRet) {
    const Error &Err = InstRet.getError();
    ZEN_ASSERT(!Err.isEmpty());
    const auto &ErrMsg = Err.getFormattedMessage(false);
    SIMPLE_LOG_ERROR("failed to create instance: %s", ErrMsg.c_str());
    return exitMain(EXIT_FAILURE, RT.get());
  }
  Instance *Inst = *InstRet;

#ifdef ZEN_ENABLE_EVMABI_TEST
  std::vector<uint8_t> WasmFileBytecode;
  if (!zen::utils::readBinaryFile(Filename, WasmFileBytecode)) {
    SIMPLE_LOG_ERROR("failed to read wasm file %s", Filename.c_str());
    return exitMain(EXIT_FAILURE, RT.get());
  }
  auto EVMAbiMockCtx = zen::host::EVMAbiMockContext::create(WasmFileBytecode);
  Inst->setCustomData((void *)EVMAbiMockCtx.get());
#endif // ZEN_ENABLE_EVMABI_TEST

  /// ================ Call function ================

  std::vector<TypedValue> Results;
  if (!FuncName.empty()) {
    /// Call the specified function
    bool CallRet = RT->callWasmFunction(*Inst, FuncName, Args, Results);
    if (!CallRet) {
      const Error &Err = Inst->getError();
      ZEN_ASSERT(!Err.isEmpty());
      const auto &ErrMsg = Err.getFormattedMessage(false);
      SIMPLE_LOG_ERROR("failed to call function '%s': %s", FuncName.c_str(),
                       ErrMsg.c_str());
      return exitMain(EXIT_FAILURE, RT.get());
    }
    printTypedValueArray(Results);
  } else {
    /// Call the main function
    bool CallRet = RT->callWasmMain(*Inst, Results);
    if (!CallRet) {
      const Error &Err = Inst->getError();
      ZEN_ASSERT(!Err.isEmpty());
      const auto &ErrMsg = Err.getFormattedMessage(false);
      SIMPLE_LOG_ERROR("failed to call main function: %s", ErrMsg.c_str());
      return exitMain(EXIT_FAILURE, RT.get());
    }
  }

  /// ========== Extra compilations and executions for benchmarking ==========

  if (NumExtraCompilations + NumExtraExecutions > 0) {
    CodeHolderUniquePtr Code;
    try {
      Code = CodeHolder::newFileCodeHolder(*RT, Filename);
    } catch (const std::exception &E) {
      SIMPLE_LOG_ERROR("failed to load module: %s", E.what());
      return exitMain(EXIT_FAILURE, RT.get());
    }
    for (uint32_t I = 0; I < NumExtraCompilations; ++I) {
      // Use new filename to avoid cache based on filename
      std::string NewWasmName = Filename + std::to_string(I);
      MayBe<Module *> TestModRet =
          RT->loadModule(NewWasmName, Code->getData(), Code->getSize());
      ZEN_ASSERT(TestModRet);
      RT->unloadModule(*TestModRet);
    }
    for (uint32_t I = 0; I < NumExtraExecutions; ++I) {
      Results.clear();
      IsolationUniquePtr TestIso = RT->createUnmanagedIsolation();
      ZEN_ASSERT(TestIso);
      MayBe<Instance *> TestInstRet = TestIso->createInstance(*Mod, GasLimit);
      ZEN_ASSERT(TestInstRet);
      Instance *TestInst = *TestInstRet;
      if (!FuncName.empty()) {
        RT->callWasmFunction(*TestInst, FuncName, Args, Results);
      } else {
        RT->callWasmMain(*TestInst, Results);
      }
    }
  }

#ifdef ZEN_ENABLE_BUILTIN_WASI
  int ExitCode = Inst->getExitCode();
#else
  int ExitCode = EXIT_SUCCESS;

#endif

  if (EnableBenchmark) {
    _exit(ExitCode);
  }

  /// ================ Delete instance ================

  if (!Iso->deleteInstance(Inst)) {
    ZEN_LOG_ERROR("failed to delete instance");
    return exitMain(EXIT_FAILURE, RT.get());
  }

  /// ================ Delete isolation ================

  if (!RT->deleteManagedIsolation(Iso)) {
    ZEN_LOG_ERROR("failed to delete isolation");
    return exitMain(EXIT_FAILURE, RT.get());
  }

#ifdef NDEBUG
  Mod->releaseMemoryAllocatorCache();
  if (EnableBenchmark) {
    // zen cli no need to free resources(or async tasks) when run success.
    // OS will do that
    ::exit(exitMain(ExitCode, RT.get()));
  }
#endif // NDEBUG

  /// ================ Unload user's module ================

  if (!RT->unloadModule(Mod)) {
    ZEN_LOG_ERROR("failed to unload module");
    return exitMain(EXIT_FAILURE, RT.get());
  }

  /// ================ Unload env module ================

#ifdef ZEN_ENABLE_BUILTIN_ENV
  if (!RT->unloadHostModule(EnvMod)) {
    ZEN_LOG_ERROR("failed to unload env module");
    return exitMain(EXIT_FAILURE, RT.get());
  }

#endif

  /// ================ Unload WASI module ================

#ifdef ZEN_ENABLE_BUILTIN_WASI
  if (!RT->unloadHostModule(WASIMod)) {
    ZEN_LOG_ERROR("failed to unload WASI module");
    return exitMain(EXIT_FAILURE, RT.get());
  }
#endif

  return exitMain(ExitCode, RT.get());
}
