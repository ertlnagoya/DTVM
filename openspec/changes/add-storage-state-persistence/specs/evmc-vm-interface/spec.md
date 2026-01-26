## ADDED Requirements
### Requirement: Host callbacks for storage diff persistence
The system SHALL extend the EVMC host binding so the host can supply implementations of `StorageDiffSink` and `StorageProvider` when a runtime execute call is prepared, enabling dtvm to report diffs and query persisted storage.

#### Scenario: Host supplies persistence callbacks
- **WHEN** the host implements `StorageDiffSink`/`StorageProvider` and passes them through the EVMC execute context
- **THEN** the system SHALL associate them with the runtime so `SSTORE` reports diffs via `StorageDiffSink::on_sstore`
- **AND** the runtime SHALL only call `StorageDiffSink::on_finish` after a successful execution
- **AND** `SLOAD` operations SHALL forward through `StorageProvider::sload` to read the persisted state

#### Scenario: Host omits persistence callbacks
- **WHEN** no storage persistence callbacks are provided
- **THEN** the system SHALL execute using its existing in-memory storage map without invoking new host methods
