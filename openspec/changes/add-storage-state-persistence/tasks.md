## 1. Implementation
- [ ] Wire up `StorageDiff`/`ExecutionDiffLog` inside dtvm, update SSTORE to record diffs, and add the `StorageDiffSink`/`StorageProvider` traits.
- [ ] Extend dtvm execution hosts (EVMC `execute` entry points, runtime context) to accept optional diff sinks/providers and only call `on_finish` when status is success.
- [ ] Build a sled-based key-value store in dtvm_solsdk plus the diff sink/provider implementations to persist diffs and answer SLOAD queries through the host bridge.
- [ ] Enhance the CLI/tests in dtvm_solsdk to configure the persistence backend, run sequential set/get flows, and verify state is preserved/restored.

## 2. Validation
- [ ] Run the relevant regression/e2e tests (`cargo test` under dtvm_solsdk or provided scripts) to confirm persistence works and REVERT paths do not commit.
