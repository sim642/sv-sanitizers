#!/usr/bin/env bash

set -e # Make script fail if any command fails.
set -o pipefail # Make pipes fail if any command in pipe fails.


# Print version for reference.
./sv-sanitizers.py --version


# Run smoke tests in subdirectory for convenience.
cd smoketests/
SV_SANITIZERS="../sv-sanitizers.py"
# This will also check if SV-sanitizers works when executed from different directory (finds lib stubs, suppressions).


# Check if architectures are supported (C standard headers available for both) and return correct results.
# This is based on Goblint cram test tests/regression/29-svcomp/36-svcomp-arch.t.
# There should be overflow on ILP32:
$SV_SANITIZERS --p no-overflow.prp --d ILP32 36-svcomp-arch.c | grep "SV-COMP result: false(no-overflow)"

# There shouldn't be an overflow on LP64:
# $SV_SANITIZERS --p no-overflow.prp --d LP64 36-svcomp-arch.c | grep "SV-COMP result: true"


# Check if basic data race analysis returns correct results.
$SV_SANITIZERS --p no-data-race.prp --d ILP32 04-mutex_01-simple_rc.c | grep "SV-COMP result: false(no-data-race)"


# Check if basic memsafety analysis returns correct results.
$SV_SANITIZERS --p valid-memsafety.prp --d ILP32 null-deref.c | grep "SV-COMP result: false(valid-deref)"
$SV_SANITIZERS --p valid-memsafety.prp --d ILP32 double-free.c | grep "SV-COMP result: false(valid-free)"

# TODO: no malloc failures
# $SV_SANITIZERS --p valid-memsafety.prp --d ILP32 malloc-null-deref.c | grep "SV-COMP result: false(valid-deref)"

# TODO: no target locations from LeakSanitizer
# $SV_SANITIZERS --p valid-memsafety.prp --d ILP32 leak.c | grep "SV-COMP result: false(valid-memtrack)"
# $SV_SANITIZERS --p valid-memcleanup.prp --d ILP32 leak.c | grep "SV-COMP result: false(valid-memcleanup)"


# Check if compile-time overflow analysis returns correct results.
$SV_SANITIZERS --p no-overflow.prp --d ILP32 AdditionIntMax.c | grep "SV-COMP result: false(no-overflow)"


echo "SUCCESS"
