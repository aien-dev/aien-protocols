# OSC unit artifact container v1: conformance vectors

Contract: [`../OSC_UNIT_ARTIFACT.md`](../OSC_UNIT_ARTIFACT.md) (v1 DRAFT, frozen pending ADR reconciliation, 2026-10-08).
Each `.unit` file is a complete container. `expected.txt` lists, per vector, the loader mode, supported capability domains, trust anchors present, and the required verdict. Public keys are in [`../keys/`](../keys/): both are THROWAWAY TEST keys derived from fixed labels in [`../tools/make-vectors.sh`](../tools/make-vectors.sh). They are not any AIEN key and must never enter a real anchor set.

Regenerate and check everything: `bash specs/osc-unit-artifact/tools/check-vectors.sh`. Counts: container vectors in `expected.txt`, name lookups in `lookups.txt`, loader-state scenarios in `state.txt` (admission codes 29 and 30), launch-argument scenarios in `launch.txt` (launch code 41, judged by `../tools/osc-launch-check.c`). Launch code 40 is covered by `lookups.txt`; an out-of-range `fn_index` is a loader-side scenario with no byte vector.
The valid unit is `../src/min.osc` as compiled by omega `oscc` at `d64ccb3` (`ir_sha256=084803c2...1a1d`). Verdicts were produced by the shell generator and judged by the shell checker (and the C launch reference) only; no kernel or adapter loader has run them.

| sha256 | file |
|---|---|
| `5711ca0a71062f7df709bde41ed80c8e724f4826b886ecc9b0ceb55f80682da4` | `a01_valid_min.unit` |
| `617ccd94e08502b6d99995dfe13af7c0a3c166411b3e15ea605669dc5f216833` | `a02_valid_caps_kernel_domain.unit` |
| `aad288697f7527d40e1ee38f6b46eacac5e109eaa2fa541886381e3992117d88` | `a03_valid_hosted_domain.unit` |
| `f837ad840f1f97c5e3b802bfcae02f7f45c6e71db64adcca30eca9c53d1e473c` | `a04_valid_owner_class.unit` |
| `0212117d13d1df3a4010dfebd9b767908567956203346a0994ce8444f968d02c` | `a05_valid_cells_entry.unit` |
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
| `356b6d7db290a463f577e77009f3df9457ce9429d0d3480329114a236acfdb88` | `r29_total_length_low.unit` |
| `185ab6712784803d88537fc345b51c4d5625d3eea6a24a5c32bb85cfb32026fa` | `r30_section_table_kind.unit` |
| `241a57412e7e687701a5c7ee020b6eef2b76d6a350c415f83c905eeb017bbde2` | `r31_entry_hash_mismatch.unit` |
| `9be16c2b5c25716dd68018161197160e4937bbf628be1eb09af910b10bb566e0` | `r32_caps_hash_mismatch.unit` |
| `5a93d64db12bff325c81b306c41ef823223a7e941fa2fae6eea894d7d974f1ca` | `r33_caps_table_bad_rights.unit` |
| `95052025782d40b58581b0d5fe7dbcaff75fb671a2d088cbc1442b9888def50e` | `r34_signer_class_3.unit` |
| `fbcc5357826aa4613acc5334565a86cd94d87be2205c12618260f55bd14ba916` | `r35_signature_algorithm_2.unit` |
| `b9328b13ffdec27159c0d3e76ca0bce0e141151ae4423270d7f6f79f5a1dbad8` | `r36_domain_before_generation.unit` |
| `9114f9fa752fb2c96e24635bc7c8813b0448db899829a77c2ba45d0f6607e0b6` | `r37_code_svc.unit` |
| `a70fc513bbb8eb41f647a6e76024b9b7e7800055fa3e1e65ce97fcff584ef733` | `r38_code_hvc.unit` |
| `f5f1a84f60e0e03a690860f84e69f7a7d013afcce48a9e8232540951fb3aa1aa` | `r39_code_smc.unit` |
| `ef77cee695b16c09c8267d37d3386ea353a72898e67ffbbfd4b1ca8be14bc071` | `r40_code_msr_sysreg.unit` |
| `b71845184d818181f3fb4b59954ba1d821a9fa04af23cf3884ab5775fb3f9564` | `r41_code_mrs_sysreg.unit` |
| `4fa443999e51b85b6f746900f0a216557db055e7852d66e70667824e3b276870` | `r42_code_brk_imm0.unit` |
| `01fa909e77d89583e5cc84ea4deeae92ffa021bb425a60b0a3e14bf9dec8bf74` | `r43_code_brk_imm15.unit` |
| `63e1fe5889e9b218ab8b9ee49ca4e14d67a0ef95d5f6aa614e9bb385346e178b` | `r44_caps_disorder.unit` |
| `1ebea8138092aeefab2360ad3d8d9a512c442e9b404bc75c5e4a078c035cba72` | `r45_signature_s_not_canonical.unit` |
| `27c9787afc78499687b5e5ada5e3313b221065ba44158cdd0c745e8dfbd872be` | `r46_section_bounds_u32_wrap.unit` |
| `8f6d6d92ea0aa3783e7b6dfe4d915d67faa20f904fed8b898994789bf64baa59` | `r47_slice_kind_in_format_4.unit` |
| `f67358ef22e3652e5ac7c1081dd16a6cd3519b91d2da344c915287fb48d70a1c` | `expected.txt` |
| `b9133467aeeba8ed6959e2a1ddbb9e8479b68e9abba295c437b8e82c8ed1e707` | `lookups.txt` |
| `74ca2630b05656e1df4414657e6b6dba388d6729f91856d1c7a276930eaf67cf` | `state.txt` |
| `a56db4ab074db44c132a8bef8ab8fbb1c216e536765a036d96690193597c744d` | `launch.txt` |
