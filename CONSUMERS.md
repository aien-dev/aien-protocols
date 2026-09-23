# Protocol Consumers

Each consumer below pins the protocol version it targets. Until this repo
carries a newer tag with migration notes, all consumers target `v0.1.0`.

| Consumer | Uses | Pinned version |
| :--- | :--- | :---: |
| `aegis-runtime` | protocol-types, action-protocol, probe, agent-state-abi, inference-protocol, inference-client | v0.1.0 |
| `aien-local-stack` | protocol-types, agent-state-abi, inference-protocol, inference-client, provenance | v0.1.0 |
| `spark-inquisitor` | protocol-types, evaluation-protocol, probe | v0.1.0 |
| `spark-rsi` | protocol-types, evaluation-protocol, probe | v0.1.0 |
| `aien-sovereign-core` (`spark-harvester`, `spark-mail-rs`) | protocol-types, provenance, probe | v0.1.0 |

Consumption is by path dependency today. A consumer moves to a newer tag by
recording the new version in this table in the same change that adopts it.
