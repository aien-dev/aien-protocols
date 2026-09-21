# Inference Protocol Specification

**Status**: Draft  
**Version**: 1.0.0  
**License**: Community Specification License 1.0  

## Abstract

The Inference Protocol defines the contract between autonomous agent orchestrators (AEGIS) and model execution backends (Sovereign Core).

## Core Concepts

1. **Inference Context Reference (`InferenceContextRef`)**: A durable logical handle referencing reproducible inference context. It contains model and tokenizer fingerprints, logical state digests, lineage metadata, and cache isolation keys. It never contains physical GPU pointers or raw block IDs.
2. **Copy-on-Write Branching**: Sequential sequence branches share immutable prefix KV blocks with reference counting. Physical page copies occur exclusively upon divergence.
3. **Leased KV Pinning**: Blocks are held via time-bounded leases renewed during active runs.
