# OSC unit artifact container v1: conformance vectors

Contract: [`../OSC_UNIT_ARTIFACT.md`](../OSC_UNIT_ARTIFACT.md) (v1 DRAFT, not frozen).
Each `.unit` file is a complete container. `expected.txt` lists, per vector, the loader mode, supported capability domains, trust anchors present, and the required verdict. Public keys are in [`../keys/`](../keys/): both are THROWAWAY TEST keys derived from fixed labels in [`../tools/make-vectors.sh`](../tools/make-vectors.sh). They are not any AIEN key and must never enter a real anchor set.

Regenerate and check everything: `bash specs/osc-unit-artifact/tools/check-vectors.sh` (32 container vectors plus 6 name lookups, 38 checks).
The valid unit is `../src/min.osc` as compiled by omega `oscc` at `d64ccb3` (`ir_sha256=084803c2...1a1d`). Verdicts were produced by the shell generator and judged by the shell reference checker only; no kernel or adapter loader has run them.

| sha256 | file |
|---|---|
| `5711ca0a71062f7df709bde41ed80c8e724f4826b886ecc9b0ceb55f80682da4` | `a01_valid_min.unit` |
| `617ccd94e08502b6d99995dfe13af7c0a3c166411b3e15ea605669dc5f216833` | `a02_valid_caps_kernel_domain.unit` |
| `aad288697f7527d40e1ee38f6b46eacac5e109eaa2fa541886381e3992117d88` | `a03_valid_hosted_domain.unit` |
| `f837ad840f1f97c5e3b802bfcae02f7f45c6e71db64adcca30eca9c53d1e473c` | `a04_valid_owner_class.unit` |
| `fab5256cf6a05f57e72f64c24f92e8e4bd7cf3f18156f139f32ac028ed2a4362` | `r01_bad_magic.unit` |
| `5b1b89a87b3246aaef583d0b96acc9fe15a76b7552466fc0932bd6380c67e12b` | `r02_container_version_2.unit` |
| `819bda98999a593091a9df83ef6f66bc4698a29ab55abc430dd0924028380543` | `r03_unit_format_6.unit` |
| `98363de25611c12cb7a2a9075f3c581693c97a2c8b0ded10d53aec3c815f140d` | `r04_abi_version_2.unit` |
| `d1a57a64536b99144ab0d270cb7d8270ce558440c224a08b212010396fd8c9c3` | `r05_unknown_flags.unit` |
| `eda845c0f82ca9b380517cf28caeccc1f852545d8bdda9eca85a14af0f56eaea` | `r06_header_field_reserved.unit` |
| `e52a2d136387c8424cf471f9713fc8eebfcaab2f4f277bbc9cca71aade53af9c` | `r07_truncated_file.unit` |
| `7026de6780e9c26ef76314bbea8a49cfe441b538db461f977eecaded94f7203e` | `r08_section_bounds.unit` |
| `11f6a186378779ebf08e3a5366915fc6874b1802c148c1d3e66f1a08b4216267` | `r09_section_overlap.unit` |
| `18aa1923d0d32814e23f09e509641d072ea71d2dc52307bece551a29a950a669` | `r10_section_layout_offset.unit` |
| `8d652da89047e6010da08d5fcff7e963987c17b815c5766206875bac9ef2701a` | `r11_too_many_functions.unit` |
| `65cee58a6c288b8ece2dd1b0174d5cedac16c5b5c2d5e060e014fa1061b2f44d` | `r12_code_hash_mismatch.unit` |
| `16a0005d56f3c720c3bc9dd28c9c2393efab0cced036c30c996d7a3c45a4a276` | `r13_ir_hash_mismatch.unit` |
| `1c8456e5febe85172543dc874a69ee4aa94887342889eea3757e916bd0fe992f` | `r14_bad_signature.unit` |
| `d6603624942219f254069806b55abfa2337804d2c1513d27329609d00bc45f1e` | `r15_ir_version_mismatch.unit` |
| `c013ba363339bf37c1d360290f469564744bc973394009d6202a12c74a2b1167` | `r16_entry_table_unaligned.unit` |
| `a154f18b2c840828aa15dd0997719f7d48f2a7ecde502b55d0dd2a08e736b087` | `r17_too_many_functions.unit` |
| `54c5f236586c03139434a0333aa7bb484f09376523b839d3d4c230619812df65` | `r18_gen_not_representable.unit` |
| `5711ca0a71062f7df709bde41ed80c8e724f4826b886ecc9b0ceb55f80682da4` | `r19_test_signer_release.unit` |
| `aad288697f7527d40e1ee38f6b46eacac5e109eaa2fa541886381e3992117d88` | `r20_domain_unsupported.unit` |
| `f837ad840f1f97c5e3b802bfcae02f7f45c6e71db64adcca30eca9c53d1e473c` | `r21_untrusted_owner_signer.unit` |
| `a76227162901ed0d794f15b597292f627b9fb1173e07ceb164fa58812d974dbb` | `r22_trailing_byte.unit` |
| `2d0c6c942fe5810d53f4b8811eab78973daed1ca7bedb47be864640486e61332` | `r23_entry_name_charset.unit` |
| `d65ff046a0a792461a819942cd9aa35d502be0a864458e69940d437e10d26987` | `r24_entry_name_empty.unit` |
| `8f14347cfaa92c05e1d5c4a7f6dc687936b34bbe931f1a4442d8c170ae4a4898` | `r25_entry_name_too_long.unit` |
| `1fbd5ee080bed169b6954cf19988c9a8b546e11eae45644f9fb3db8e84de5704` | `r26_entry_name_padding.unit` |
| `e6413aaa21dab182bcdb9a3ee554a65ac3b64cbbbdbf0092c290a7952ea674bd` | `r27_entry_name_duplicate.unit` |
| `b5e77bbf38071bc71130be339ca4790c68598598a2cde38edc46ec6b507bf3b7` | `r28_entry_hash_shared_other_name.unit` |
| `1fa8a3239ed6e85505163618b4bc0bbe7ae500bdc1c330921a20ad6578a365ee` | `expected.txt` |
| `b9133467aeeba8ed6959e2a1ddbb9e8479b68e9abba295c437b8e82c8ed1e707` | `lookups.txt` |
