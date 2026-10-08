# OSC unit artifact container v1: conformance vectors

Contract: [`../OSC_UNIT_ARTIFACT.md`](../OSC_UNIT_ARTIFACT.md) (v1 DRAFT, not frozen).
Each `.unit` file is a complete container. `expected.txt` lists, per vector, the loader mode, supported capability domains, trust anchors present, and the required verdict. Public keys are in [`../keys/`](../keys/): both are THROWAWAY TEST keys derived from fixed labels in [`../tools/make-vectors.sh`](../tools/make-vectors.sh). They are not any AIEN key and must never enter a real anchor set.

Regenerate and check everything: `bash specs/osc-unit-artifact/tools/check-vectors.sh`.
The valid unit is `../src/min.osc` as compiled by omega `oscc` at `d64ccb3` (`ir_sha256=084803c2...1a1d`). Vector verdicts were produced by the shell generator and judged by the shell reference checker only; no kernel or adapter loader has run them.

| sha256 | vector |
|---|---|
| `ae6a921881b62fe8cb1d9cb27f92db6ecc32186cb39e3ff6b5b96250d2749a89` | `a01_valid_min.unit` |
| `17d7d99e8eecbef75dac0a726e1b881e8d4dbb50a40784e831a58bafd68336aa` | `a02_valid_caps_kernel_domain.unit` |
| `563c7635f5a5fe5340c0e39c84065d2dfea893014f3df1be2be550aa232dd6eb` | `a03_valid_hosted_domain.unit` |
| `475ae4b511179276d49d576ecee4bc17b3487294c6350805d42b96b5435d8d16` | `a04_valid_owner_class.unit` |
| `be228ca3d267a9fc8c2fc60a5215cebd164c56f30d338cade6eaed44c896b148` | `r01_bad_magic.unit` |
| `b86c49a7f7ce74d21e56dee2fc8f7ee5abc40cfae3e37c4e578e342e9f30ae54` | `r02_container_version_2.unit` |
| `a68a2a79cea336e3bd017b3f64aa0db0e6f7d339dae446d64704879e589d89d9` | `r03_unit_format_6.unit` |
| `fecb015de9af99ee98f372573fde6917f10c8a651aca45d3e09affd0c1053bba` | `r04_abi_version_2.unit` |
| `2456e5012d7cb21c6fab57047f2ccc490259824262b9cfaf108f817b7abb3b40` | `r05_unknown_flags.unit` |
| `10045a51b691b9cc64d1e6c90318ff8a261df863738336660f2e1ff848051c72` | `r06_header_field_reserved.unit` |
| `8481f2348e72ae8bce9fde745a25f0536007d1651f717ca8de494798584200e4` | `r07_truncated_file.unit` |
| `a1851d5a7a12c4225d08ed80faa9e38b3afff0b5c926e2df35a1db070f36368e` | `r08_section_bounds.unit` |
| `4732d8171fd757a0a0119fb2c4737fb2abf05df19b5a894fdd3f9544b7cd68b0` | `r09_section_overlap.unit` |
| `f5cba7f5eeaeec1089938c7b0522c0009788c1771e3f75127433a99af8b50b5d` | `r10_section_layout_offset.unit` |
| `420050c717377ed2dd2d1baf3238a316b9bebe1c475579b960769688d988c01c` | `r11_too_many_functions.unit` |
| `8960f4b3279e7f898f0f9d4b95df0c4f8d395ea14bfad016b12db15e9e3fa875` | `r12_code_hash_mismatch.unit` |
| `c3080ca18396413cefe4f0a4a586a042ad94759407231e7b0c5114848f5faeee` | `r13_ir_hash_mismatch.unit` |
| `5cabda267a1896954183650a1a566ac8186ce31b5e3a4dbc56d7b0a8e750a9f2` | `r14_bad_signature.unit` |
| `80fa4dfe21c8b584f7b5cd31ccfa3ecac8c2c4d1735cf2d6cafbb06074c541bc` | `r15_ir_version_mismatch.unit` |
| `7f2b19843d6b19821f4045fdbc18964e2a8a66369f03964037823c28d66d732a` | `r16_entry_table_unaligned.unit` |
| `5d8be3ae496517afa41c4b5bfd7bd856ad143271939fb94558605c89667562a7` | `r17_too_many_functions.unit` |
| `42c20250e970bbedf2ea044af71e01939f607dd0aa95da7167a2ee8a1c52f5fb` | `r18_gen_not_representable.unit` |
| `ae6a921881b62fe8cb1d9cb27f92db6ecc32186cb39e3ff6b5b96250d2749a89` | `r19_test_signer_release.unit` |
| `563c7635f5a5fe5340c0e39c84065d2dfea893014f3df1be2be550aa232dd6eb` | `r20_domain_unsupported.unit` |
| `475ae4b511179276d49d576ecee4bc17b3487294c6350805d42b96b5435d8d16` | `r21_untrusted_owner_signer.unit` |
| `07e1b6d823f5dfd40dce550c98a15436f3c53afe6aaa98d37b1de8cbb9044831` | `r22_trailing_byte.unit` |
