// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "dt_evmc_vm.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/config.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "evm/storage_diff.h"
#include "runtime/runtime.h"
#include "storage_persistence.h"
#include "wrapped_host.h"

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/helpers.h>

#include <cstring>
#include <memory>
#include <vector>

namespace {

using namespace zen::runtime;
using namespace zen::common;

// JIT compilation limits (95% < 10KB)
const size_t MAX_JIT_BYTECODE_SIZE = 0x6000;

namespace {

static dtvm_storage_diff_t to_c_storage_diff(const evm::StorageDiff &Diff) {
  dtvm_storage_diff_t Result{};
  std::memcpy(&Result.address, &Diff.address, sizeof(Result.address));
  std::memcpy(&Result.key, &Diff.key, sizeof(Result.key));
  Result.has_old_value = Diff.old_value.has_value() ? 1 : 0;
  if (Diff.old_value) {
    std::memcpy(&Result.old_value, &*Diff.old_value, sizeof(Result.old_value));
  } else {
    std::memset(&Result.old_value, 0, sizeof(Result.old_value));
  }
  std::memcpy(&Result.new_value, &Diff.new_value, sizeof(Result.new_value));
  return Result;
}

class CallbackStorageDiffSink final : public zen::evm::StorageDiffSink {
public:
  CallbackStorageDiffSink(void *Context,
                          dtvm_storage_diff_sink_on_sstore_fn OnSstore,
                          dtvm_storage_diff_sink_on_finish_fn OnFinish)
      : Ctx(Context), OnSstore(OnSstore), OnFinish(OnFinish) {}

  void on_sstore(const StorageDiff &Diff) override {
    if (!OnSstore) {
      return;
    }
    const auto DiffData = to_c_storage_diff(Diff);
    OnSstore(Ctx, &DiffData);
  }

  void on_finish(const ExecutionDiffLog &Diffs) override {
    if (!OnFinish) {
      return;
    }
    if (Diffs.empty()) {
      OnFinish(Ctx, nullptr, 0);
      return;
    }
    Buffer.clear();
    Buffer.reserve(Diffs.size());
    for (const auto &Diff : Diffs) {
      Buffer.push_back(to_c_storage_diff(Diff));
    }
    OnFinish(Ctx, Buffer.data(), Buffer.size());
  }

private:
  void *Ctx = nullptr;
  dtvm_storage_diff_sink_on_sstore_fn OnSstore = nullptr;
  dtvm_storage_diff_sink_on_finish_fn OnFinish = nullptr;
  std::vector<dtvm_storage_diff_t> Buffer;
};

class CallbackStorageProvider final : public zen::evm::StorageProvider {
public:
  CallbackStorageProvider(void *Context,
                          dtvm_storage_provider_sload_fn OnSload,
                          dtvm_storage_provider_sstore_fn OnEphemeralStore)
      : Ctx(Context), OnSload(OnSload),
        OnEphemeralStore(OnEphemeralStore) {}

  evmc::bytes32 sload(const evmc::address &Address,
                      const evmc::bytes32 &Key) override {
    if (!OnSload) {
      return {};
    }
    struct evmc_address AddressC;
    struct evmc_bytes32 KeyC;
    std::memcpy(&AddressC, &Address, sizeof(AddressC));
    std::memcpy(&KeyC, &Key, sizeof(KeyC));
    return OnSload(Ctx, &AddressC, &KeyC);
  }

  void sstore_ephemeral(const evmc::address &Address,
                        const evmc::bytes32 &Key,
                        const evmc::bytes32 &Value) override {
    if (!OnEphemeralStore) {
      return;
    }
    struct evmc_address AddressC;
    struct evmc_bytes32 KeyC;
    struct evmc_bytes32 ValueC;
    std::memcpy(&AddressC, &Address, sizeof(AddressC));
    std::memcpy(&KeyC, &Key, sizeof(KeyC));
    std::memcpy(&ValueC, &Value, sizeof(ValueC));
    OnEphemeralStore(Ctx, &AddressC, &KeyC, &ValueC);
  }

private:
  void *Ctx = nullptr;
  dtvm_storage_provider_sload_fn OnSload = nullptr;
  dtvm_storage_provider_sstore_fn OnEphemeralStore = nullptr;
};

} // namespace

// RAII helper for temporarily changing runtime configuration
class ScopedConfig {
public:
  ScopedConfig(Runtime *Runtime, const RuntimeConfig &NewConfig)
      : RT(Runtime), PreviousConfig(Runtime->getConfig()) {
    RT->setConfig(NewConfig);
  }

  ~ScopedConfig() { RT->setConfig(PreviousConfig); }

private:
  Runtime *RT;
  RuntimeConfig PreviousConfig;
};

// CRC32 checksum
uint32_t crc32(const uint8_t *Data, size_t Size) {
  static uint32_t Table[256];
  static bool TableInitialized = false;
  if (!TableInitialized) {
    for (uint32_t I = 0; I < 256; ++I) {
      uint32_t C = I;
      for (int J = 0; J < 8; ++J)
        C = (C & 1) ? (0xEDB88320u ^ (C >> 1)) : (C >> 1);
      Table[I] = C;
    }
    TableInitialized = true;
  }
  uint32_t Crc = 0xFFFFFFFFu;
  for (size_t I = 0; I < Size; ++I)
    Crc = Table[(Crc ^ Data[I]) & 0xFFu] ^ (Crc >> 8);
  return Crc ^ 0xFFFFFFFFu;
}

// VM interface for DTVM
struct DTVM : evmc_vm {
  DTVM();
  ~DTVM() {
    for (auto &P : LoadedMods) {
      EVMModule *Mod = P.second;
      if (!RT->unloadEVMModule(Mod)) {
        ZEN_LOG_ERROR("failed to unload EVM module");
      }
    }
    if (Iso) {
      RT->deleteManagedIsolation(Iso);
    }
  }
  RuntimeConfig Config = {.Format = InputFormat::EVM,
                          .Mode = RunMode::MultipassMode,
                          .EnableEvmGasMetering = true};
  std::unique_ptr<Runtime> RT;
  std::unique_ptr<WrappedHost> ExecHost;
  std::unique_ptr<evm::StorageDiffSink> StorageDiffSinkImpl;
  std::unique_ptr<evm::StorageProvider> StorageProviderImpl;
  std::unordered_map<uint64_t, EVMModule *> LoadedMods;
  Isolation *Iso = nullptr;

  void configureStoragePersistence(
      void *Context, dtvm_storage_diff_sink_on_sstore_fn OnSstore,
      dtvm_storage_diff_sink_on_finish_fn OnFinish,
      dtvm_storage_provider_sload_fn OnSload,
      dtvm_storage_provider_sstore_fn OnEphemeralStore);
};

/// The implementation of the evmc_vm::destroy() method.
void destroy(evmc_vm *VMInstance) { delete static_cast<DTVM *>(VMInstance); }

/// The implementation of the evmc_vm::get_capabilities() method.
evmc_capabilities_flagset get_capabilities(evmc_vm * /*instance*/) {
  return EVMC_CAPABILITY_EVM1;
}

/// VM options.
///
/// The implementation of the evmc_vm::set_option() method.
/// VMs are allowed to omit this method implementation.
enum evmc_set_option_result set_option(evmc_vm *VMInstance, const char *Name,
                                       const char *Value) {
  auto *VM = static_cast<DTVM *>(VMInstance);
  if (std::strcmp(Name, "mode") == 0) {
    if (std::strcmp(Value, "interpreter") == 0) {
      VM->Config.Mode = RunMode::InterpMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "multipass") == 0) {
      VM->Config.Mode = RunMode::MultipassMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  } else if (std::strcmp(Name, "enable_gas_metering") == 0) {
    if (std::strcmp(Value, "true") == 0) {
      VM->Config.EnableEvmGasMetering = true;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "false") == 0) {
      VM->Config.EnableEvmGasMetering = false;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  }
  return EVMC_SET_OPTION_INVALID_NAME;
}

/// The implementation of the evmc_vm::execute() method.
evmc_result execute(evmc_vm *EVMInstance, const evmc_host_interface *Host,
                    evmc_host_context *Context, enum evmc_revision Rev,
                    const evmc_message *Msg, const uint8_t *Code,
                    size_t CodeSize) {
  auto *VM = static_cast<DTVM *>(EVMInstance);
  struct HostContextScope {
    WrappedHost *ExecHost;
    const evmc_host_interface *PrevInterface;
    evmc_host_context *PrevContext;
    HostContextScope(WrappedHost *Host, const evmc_host_interface *Interface,
                     evmc_host_context *Context)
        : ExecHost(Host), PrevInterface(Host->getInterface()),
          PrevContext(Host->getContext()) {
      ExecHost->reinitialize(Interface, Context);
    }
    ~HostContextScope() { ExecHost->reinitialize(PrevInterface, PrevContext); }
  };

  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  if (!VM->RT) {
    VM->RT = Runtime::newEVMRuntime(VM->Config, VM->ExecHost.get());
  }
  // Use interpreter mode for large bytecode
  std::unique_ptr<ScopedConfig> TempConfig;
  if (VM->Config.Mode == RunMode::MultipassMode &&
      CodeSize > MAX_JIT_BYTECODE_SIZE) {
    RuntimeConfig NewConfig = VM->Config;
    NewConfig.Mode = RunMode::InterpMode;
    TempConfig = std::make_unique<ScopedConfig>(VM->RT.get(), NewConfig);
  }

  uint32_t CheckSum = crc32(Code, CodeSize);
  uint64_t ModKey = (static_cast<uint64_t>(Rev) << 32) | CheckSum;
  std::string ModName =
      std::to_string(CheckSum) + "_" + std::to_string(static_cast<int>(Rev));
  auto ModRet = VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev);
  if (!ModRet) {
    const Error &Err = ModRet.getError();
    ZEN_ASSERT(!Err.isEmpty());
    const auto &ErrMsg = Err.getFormattedMessage(false);
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  EVMModule *Mod = *ModRet;
  VM->LoadedMods[ModKey] = Mod;
  if (!VM->Iso) {
    VM->Iso = VM->RT->createManagedIsolation();
  }
  if (!VM->Iso) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  auto InstRet = VM->Iso->createEVMInstance(*Mod, 1000000000);
  if (!InstRet) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  auto *TheInst = *InstRet;
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  TheInst->setRevision(Rev);
  TheInst->setStorageDiffSink(VM->StorageDiffSinkImpl.get());
  TheInst->setStorageProvider(VM->StorageProviderImpl.get());

  evmc_message Message = *Msg;
  evmc::Result Result;
  VM->RT->callEVMMain(*TheInst, Message, Result);
  VM->Iso->deleteEVMInstance(TheInst);

  return Result.release_raw();
}

/// @cond internal
#if !defined(PROJECT_VERSION)
/// The dummy project version if not provided by the build system.
#define PROJECT_VERSION "0.0.0"
#endif
/// @endcond

void DTVM::configureStoragePersistence(
    void *Context, dtvm_storage_diff_sink_on_sstore_fn OnSstore,
    dtvm_storage_diff_sink_on_finish_fn OnFinish,
    dtvm_storage_provider_sload_fn OnSload,
    dtvm_storage_provider_sstore_fn OnEphemeralStore) {
  if (OnSstore || OnFinish) {
    StorageDiffSinkImpl =
        std::make_unique<CallbackStorageDiffSink>(Context, OnSstore, OnFinish);
  } else {
    StorageDiffSinkImpl.reset();
  }
  if (OnSload || OnEphemeralStore) {
    StorageProviderImpl = std::make_unique<CallbackStorageProvider>(
        Context, OnSload, OnEphemeralStore);
  } else {
    StorageProviderImpl.reset();
  }
}

DTVM::DTVM()
    : evmc_vm{EVMC_ABI_VERSION, "dtvm",    PROJECT_VERSION,
              ::destroy,        ::execute, ::get_capabilities,
              ::set_option},
      ExecHost(new WrappedHost) {}
} // namespace

extern "C" evmc_vm *evmc_create_dtvmapi() { return new DTVM; }

extern "C" void dtvm_set_storage_persistence_callbacks(
    evmc_vm *VMInstance, void *Context,
    dtvm_storage_diff_sink_on_sstore_fn OnSstore,
    dtvm_storage_diff_sink_on_finish_fn OnFinish,
    dtvm_storage_provider_sload_fn OnSload,
    dtvm_storage_provider_sstore_fn OnEphemeralStore) {
  auto *VM = static_cast<DTVM *>(VMInstance);
  VM->configureStoragePersistence(Context, OnSstore, OnFinish, OnSload,
                                  OnEphemeralStore);
}
