# Change: EVMC L1 module cache validation and interpreter TLS cleanup

- **Status**: Implemented
- **Date**: 2026-04-10
- **Tier**: Light

## Overview

Harden the address-based EVM module LRU used by `libdtvmapi` so cached modules match the incoming bytecode exactly, and clear interpreter thread-local resource pointers after each run when reusing `InterpreterExecContext`.

## Motivation

Head-and-tail-only bytecode checks could false-match different contracts of the same length, causing wrong execution and state divergences (e.g. invalid block on real replay). Thread-local `EVMResource` pointers were not cleared after `interpret()`, risking cross-call leakage when contexts are reused.

## Impact

- `src/vm/dt_evmc_vm.cpp`: cache validation is configurable — strict full-bytecode `memcmp` remains the default for correctness; trusted immutable-code hosts can opt into relaxed head/tail window validation via `DTVM_EVM_STRICT_ADDR_CACHE_VALIDATION=false`.
- `src/evm/opcode_handlers.h`: TLS cleanup is centralized in `BaseInterpreter::interpret()` via `EVMResource::ClearGuard`, so all interpreter invocations are covered automatically.
- `src/vm/dt_evmc_vm.cpp`, `src/runtime/runtime.cpp`: clear TLS after interpreter runs (RAII guard).
- `src/tests/evm_module_cache_tests.cpp`: regression for same head/tail, different middle.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [ ] Build and tests pass
