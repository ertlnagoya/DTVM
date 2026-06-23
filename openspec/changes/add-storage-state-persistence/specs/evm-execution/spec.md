## ADDED Requirements
### Requirement: Collect storage diffs during EVM execution
The system SHALL track every successful `SSTORE` operation as a `StorageDiff { address, key, old?, new }` entry, append it to the execution diff log, and pass it to the host via a pluggable `StorageDiffSink` interface.

#### Scenario: Successful execution commits diffs
- **WHEN** an execution call performs one or more `SSTORE` opcodes and finishes with status `EVMC_SUCCESS` or `EVMC_STOP`
- **THEN** the system SHALL invoke `StorageDiffSink::on_finish` with the accumulated diffs
- **AND** diffs representing only the successful SSTOREs SHALL be delivered to the host for persistence
- **AND** the system SHALL NOT commit diffs when the status indicates failure (e.g., REVERT)

#### Scenario: REVERT or failure suppresses commit
- **WHEN** execution terminates with a failure status such as `EVMC_REVERT`
- **THEN** the system SHALL skip calling `on_finish` and the host SHALL not persist the diffs
- **AND** the in-memory diff log SHALL be discarded to avoid leaking reverted writes

### Requirement: Host-backed storage provider for SLOAD
The system SHALL consult a host-provided `StorageProvider` every time `SLOAD` is executed, letting the host return persisted storage values while optionally falling back to an in-memory map when the provider is absent.

#### Scenario: Persistent storage available
- **WHEN** `SLOAD` executes and a `StorageProvider` is registered
- **THEN** the system SHALL call `StorageProvider::sload(address, key)` and use its return value
- **AND** the returned value SHALL reflect the last committed diff persisted by the host

#### Scenario: No provider registered
- **WHEN** `SLOAD` executes and no storage provider is registered
- **THEN** the system SHALL read from the existing in-memory storage map so behavior remains compatible with legacy runs
