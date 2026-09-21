# Agent State ABI Specification

**Status**: Draft  
**Version**: 1.0.0  
**License**: Community Specification License 1.0  

## Abstract

The Agent State ABI defines a portable, transport-neutral specification for serializing, restoring, branching, and verifying autonomous agent lifecycle state.

## Core Concepts

1. **State Snapshot (`AgentState`)**: The authoritative logical snapshot encompassing identity, session metadata, context lineage, authority grants, resource budgets, and execution status.
2. **Transition Events (`AgentStateEvent`)**: An append-only sequence of typed state transitions. Given an initial state and an ordered sequence of events, any conforming runtime reconstructs an identical logical agent state.
3. **Subsystem Boundary**: Agent state strictly references semantic memory (`MemoryRef`), physical GPU KV cache (`InferenceContextRef`), and content-addressed artifacts (`ArtifactRef`). Subsystems remain independent and do not leak internal structures into the ABI.
