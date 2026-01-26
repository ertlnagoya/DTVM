# Change: Add storage state persistence

## Why
- Smart contract deployments must survive host restarts and new invocations, so storage writes need to linger across dtvm runs rather than resetting in-memory maps.
- The runtime already exposes EVMC host callbacks, so we can capture storage diffs at SSTORE time, hand them to the host, and let dtvm_solsdk persist the data where appropriate.
- Capturing diffs in a structured way also enables future auditing and rollback guarantees tied to execution success.

## What Changes
- Extend the interpreter execution context with an explicit storage diff log, add new traits (`StorageDiffSink`, `StorageProvider`), and surface them through the existing execution entry points so dtvm can emit diffs and consult persisted storage values on demand.
- Update the EVMC host bridge to carry the new persistence traits so dtvm_solsdk can receive diffs and service SLOAD queries, while ensuring only successful runs trigger commits.
- Build a sled-backed (with JSON fallback) key-value store in dtvm_solsdk, implement the diff sink/provider that writes to sled, and add CLI flags/tests that exercise persistence across sequential executions.

## Impact
- Affected specs: `evm-execution`, `evmc-vm-interface`
- Affected code: `src/` (execution context, interpreter, host bridge), `rust_crate/`, `dtvm_solsdk/` (KVS implementation, CLI, tests)
