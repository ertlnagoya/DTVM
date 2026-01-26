#ifndef ZEN_VM_STORAGE_PERSISTENCE_H
#define ZEN_VM_STORAGE_PERSISTENCE_H

#include <evmc/evmc.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dtvm_storage_diff_t {
  struct evmc_address address;
  struct evmc_bytes32 key;
  struct evmc_bytes32 old_value;
  unsigned char has_old_value;
  struct evmc_bytes32 new_value;
} dtvm_storage_diff_t;

typedef void (*dtvm_storage_diff_sink_on_sstore_fn)(
    void *context, const dtvm_storage_diff_t *diff);
typedef void (*dtvm_storage_diff_sink_on_finish_fn)(
    void *context, const dtvm_storage_diff_t *diffs, size_t count);
typedef struct evmc_bytes32 (*dtvm_storage_provider_sload_fn)(
    void *context, const struct evmc_address *address,
    const struct evmc_bytes32 *key);
typedef void (*dtvm_storage_provider_sstore_fn)(
    void *context, const struct evmc_address *address,
    const struct evmc_bytes32 *key, const struct evmc_bytes32 *value);

void dtvm_set_storage_persistence_callbacks(
    evmc_vm *vm, void *context,
    dtvm_storage_diff_sink_on_sstore_fn on_sstore,
    dtvm_storage_diff_sink_on_finish_fn on_finish,
    dtvm_storage_provider_sload_fn on_sload,
    dtvm_storage_provider_sstore_fn on_ephemeral_store);

#ifdef __cplusplus
}
#endif

#endif // ZEN_VM_STORAGE_PERSISTENCE_H
