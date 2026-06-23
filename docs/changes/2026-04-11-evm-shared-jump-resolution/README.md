# Change: extract shared jump target resolution pass into bytecode cache

- **Status**: Implemented
- **Date**: 2026-04-11
- **Tier**: Light
- **PR**: #462

## Overview

Extract a shared abstract-stack-based jump target resolution pass into the bytecode cache (`EVMBytecodeCache`), so that both the SPP gas optimizer and the SSA liftability analyzer consume the same pre-resolved jump targets instead of each running independent (and divergent) resolution logic.

## Motivation

Prior to this change, jump target resolution was performed independently in two places:

1. **SPP gas optimizer** (`buildGasChunksSPP`) — used a simple pattern-match (`resolveConstantJumpTarget`) that only recognized adjacent `PUSHn + JUMP/JUMPI` sequences.
2. **SSA liftability analyzer** (`EVMAnalyzer`) — ran its own per-block abstract stack simulation, which could track values through DUP/SWAP but operated in isolation.

This duplication had two problems:

- **Inconsistency**: the two passes could disagree on whether a jump was resolved, leading to the SPP optimizer falling back to per-block metering while the SSA analyzer considered the same jump constant. This mismatch could leave optimization opportunities on the table.
- **Missed resolutions**: patterns like `PUSHn ... SWAPn ... JUMP` (where the push and jump are separated by stack manipulation) were invisible to the simple pattern-matcher in SPP, even though the abstract stack simulation could resolve them.

By running a single abstract stack simulation once during cache construction, both consumers get a strictly larger set of resolved targets from a single source of truth.

## Impact

### Affected Modules

- `src/evm/evm_cache.{h,cpp}` — new `ResolvedJumpTargets` field and `resolveJumpTargetsByAbstractStack` pass
- `src/compiler/evm_frontend/evm_analyzer.h` — fallback lookup into shared map via `tryResolveFromSharedMap`
- `src/compiler/evm_frontend/evm_mir_compiler.h` — wires `setResolvedJumpTargets` on the analyzer
- `src/compiler/evm_compiler.cpp` — passes cache to MIR compiler
- `src/action/evm_bytecode_visitor.h` — passes `evmc_revision` to cache builder

### Key Design Decisions

- **Raw PCs in shared map**: `ResolvedJumpTargets` stores the raw (non-canonicalized) JUMPDEST PCs from the PUSH immediate value, not the canonical PC after consecutive JUMPDESTs. This is necessary because the SPP gas optimizer needs the original PC to correctly account for intermediate JUMPDEST instructions in gas block boundaries. The SSA analyzer canonicalizes in its own consumer (`tryResolveFromSharedMap` calls `getCanonicalJumpDestPC`).
- **Caller-provided revision**: the shared pass receives the caller's `evmc_revision` metrics table rather than hardcoding `DEFAULT_REVISION`, so opcodes like PUSH0 (introduced in Shanghai) get correct stack effects under their respective revisions.
- **Graceful fallback**: the SSA analyzer first attempts its own local abstract stack simulation; only when that fails does it consult the shared map. This preserves the existing resolution quality while strictly extending coverage.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
