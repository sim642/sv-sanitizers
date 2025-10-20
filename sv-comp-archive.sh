#!/usr/bin/env bash

cd ..

rm sv-sanitizers/sv-sanitizers.zip

zip -r sv-sanitizers/sv-sanitizers.zip \
    sv-sanitizers/sv-sanitizers.py \
    sv-sanitizers/suppressions.txt \
    sv-sanitizers/sv-comp.c \
    sv-sanitizers/README.md \
    sv-sanitizers/LICENSE \
    sv-sanitizers/smoketest.sh \
    sv-sanitizers/smoketests/
