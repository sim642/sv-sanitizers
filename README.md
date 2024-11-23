# SV-sanitizers
SV-COMP wrapper for sanitizers

Currently supports:
* `no-data-race` property via ThreadSanitizer (TSan).
* `valid-memsafety` properties:
    * `valid-deref` property via AddressSanitizer (ASan).
    * `valid-free` property via AddressSanitizer (ASan).
    * `valid-memtrack` property via LeakSanitizer (LSan).
* `valid-memcleanup` property via LeakSanitizer (LSan).
* `no-overflow` property via UndefinedBehaviorSanitizer (UBSan).
