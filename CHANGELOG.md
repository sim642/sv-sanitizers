## v0.3.0
* Add `unreach-call` violation support via GNU `ld`.
* Add `unreach-call` correctness support via `nm`.
* Add YAML witness generation.
* Add violation target location parsing for YAML violation witnesses.
* Add `__VERIFIER_nondet_memory` definition.
* Remove GraphML witness generation.

## v0.2.4 (SV-COMP 2026)
* Rename from sv-sanitizers to SV-sanitizers.
* Add smoke tests.

## v0.2.3 (SV-COMP 2025)
* Fix UTC timezone in GraphML witness `creationtime`.
* Add compilation errors output.

## v0.2.2
* Add property name to all `false` verdicts.

## v0.2.1
* Add `no-overflow` compile-time violation support via `gcc`.
* Add UBSan `left shift of` detection.

## v0.2.0
* Add `no-overflow` violation support via UBSan.
* Add `no-overflow` correctness support via `nm`.

## v0.1.1 (SV-COMP 2024)
* Add ASan `stack-buffer-underflow` and `SEGV on unknown address` detection.
* Fix execution from different working directory.

## v0.1.0
Initial release.
