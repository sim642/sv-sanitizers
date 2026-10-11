#!/usr/bin/env bash

set -e # Make script fail if any command fails.
set -o pipefail # Make pipes fail if any command in pipe fails.
set -x # Make script output commands.


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
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 6" witness.yml # Check witness target line.

# There shouldn't be an overflow on LP64:
# $SV_SANITIZERS --p no-overflow.prp --d LP64 36-svcomp-arch.c | grep "SV-COMP result: true"


# Check if basic data race analysis returns correct results.
$SV_SANITIZERS --p no-data-race.prp --d ILP32 04-mutex_01-simple_rc.c | grep "SV-COMP result: false(no-data-race)"
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 17" witness.yml # Check witness target line.
grep "line: 26" witness.yml # Check witness target line.


# Check if basic memsafety analysis returns correct results.
$SV_SANITIZERS --p valid-memsafety.prp --d ILP32 null-deref.c | grep "SV-COMP result: false(valid-deref)"
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 5" witness.yml # Check witness target line.

$SV_SANITIZERS --p valid-memsafety.prp --d ILP32 double-free.c | grep "SV-COMP result: false(valid-free)"
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 6" witness.yml # Check witness target line.

# TODO: no malloc failures
# $SV_SANITIZERS --p valid-memsafety.prp --d ILP32 malloc-null-deref.c | grep "SV-COMP result: false(valid-deref)"
# grep "entry_type: violation_sequence" witness.yml # Check witness type.
# grep "line: 7" witness.yml # Check witness target line.

# TODO: no target locations from LeakSanitizer
$SV_SANITIZERS --p valid-memsafety.prp --d ILP32 leak.c | grep "SV-COMP result: false(valid-memtrack)"
# grep "entry_type: violation_sequence" witness.yml # Check witness type.
# grep "line: 6" witness.yml # Check witness target line.
$SV_SANITIZERS --p valid-memcleanup.prp --d ILP32 leak.c | grep "SV-COMP result: false(valid-memcleanup)"
# grep "entry_type: violation_sequence" witness.yml # Check witness type.
# grep "line: 6" witness.yml # Check witness target line.


# Check if basic reachability analysis returns correct results.
$SV_SANITIZERS --p unreach-call.prp --d ILP32 reach-error.c | grep "SV-COMP result: false(unreach-call)"
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 6" witness.yml # Check witness target line.


# Check if reach_error is unwrapped for non-reachability analysis.
$SV_SANITIZERS --p no-overflow.prp --d ILP32 reach-error.c | grep "SV-COMP result: true"
grep "entry_type: invariant_set" witness.yml # Check witness type.


# Check if compile-time overflow analysis returns correct results.
$SV_SANITIZERS --p no-overflow.prp --d ILP32 AdditionIntMax.c | grep "SV-COMP result: false(no-overflow)"
grep "entry_type: violation_sequence" witness.yml # Check witness type.
grep "line: 4" witness.yml # Check witness target line.

$SV_SANITIZERS --p no-overflow.prp --d ILP32 reach-error.c | grep "SV-COMP result: true"
grep "entry_type: invariant_set" witness.yml # Check witness type.


# Check if compile-time reachability analysis returns correct results.
$SV_SANITIZERS --p unreach-call.prp --d ILP32 no-reach-error.c | grep "SV-COMP result: true"
grep "entry_type: invariant_set" witness.yml # Check witness type.


# Check if reachability analysis test suite generation returns correct results.
$SV_SANITIZERS --p coverage-error-call.prp --d ILP32 invert_string-2.c | grep "SV-COMP result: done"
grep "<test-metadata>" test-suite/metadata.xml # Check metadata.
grep "<testcase coversError=\"true\">" test-suite/testcase.xml # Check testcase result.
grep "<input type=\"unsigned int\">" test-suite/testcase.xml # Check testcase input.


echo "SUCCESS"
