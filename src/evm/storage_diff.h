#ifndef ZEN_EVM_STORAGE_DIFF_H
#define ZEN_EVM_STORAGE_DIFF_H

#include <evmc/evmc.hpp>
#include <optional>
#include <vector>

namespace zen {
namespace evm {

struct StorageDiff {
  evmc::address address;
  evmc::bytes32 key;
  std::optional<evmc::bytes32> old_value;
  evmc::bytes32 new_value;
};

using ExecutionDiffLog = std::vector<StorageDiff>;

class StorageDiffSink {
public:
  virtual ~StorageDiffSink() = default;
  virtual void on_sstore(const StorageDiff &Diff) = 0;
  virtual void on_finish(const ExecutionDiffLog &Diffs) {}
};

class StorageProvider {
public:
  virtual ~StorageProvider() = default;
  virtual evmc::bytes32 sload(const evmc::address &Address,
                              const evmc::bytes32 &Key) = 0;
  virtual void sstore_ephemeral(const evmc::address &Address,
                                const evmc::bytes32 &Key,
                                const evmc::bytes32 &Value) {}
};

} // namespace evm
} // namespace zen

#endif // ZEN_EVM_STORAGE_DIFF_H
