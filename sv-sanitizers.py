#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path
import sys


VERSION="0.1.0"


def parse_args():
    parser = argparse.ArgumentParser(description="SV-COMP wrapper for sanitizers")

    parser.add_argument("-p", "--property", type=str, required=True)
    parser.add_argument("-d", "--data-model", type=str, choices=["ILP32", "LP64"], default="LP64")
    parser.add_argument("program", type=str)
    parser.add_argument("-v", "--version", action="version", version=VERSION)

    args = parser.parse_args()
    return args

def parse_property(property):
    if property == "no-data-race":
        return "no-data-race"
    elif Path(property).is_file():
        text = Path(property).read_text()
        if text.startswith("""CHECK( init(main()), LTL(G ! data-race) )"""):
            return "no-data-race"
        else:
            raise RuntimeError("unsupported property")
    else:
        raise RuntimeError("unsupported property")

def compile(args):
    gcc_args = ["gcc", "-g", "sv-comp.c", args.program, "-lm"]
    if parse_property(args.property) == "no-data-race":
        gcc_args += ["-fsanitize=thread"]
    if args.data_model == "ILP32":
        gcc_args += ["-m32"]
    else:
        gcc_args += ["-m64"]
    completed = subprocess.run(gcc_args)
    if completed.returncode == 0:
        return Path("a.out").absolute()
    else:
        raise RuntimeError("compile error")

def run_one(args, executable):
    print(".", end="", flush=True)
    env={
        "TSAN_OPTIONS": r""""exitcode"=66 "halt_on_error"=1 "report_thread_leaks"=0 "report_destroy_locked"=0 "report_signal_unsafe"=0 suppressions=suppressions.txt"""
    }
    completed = subprocess.run([executable], capture_output=True, env=env)
    if completed.returncode == 66 and b"WARNING: ThreadSanitizer: data race" in completed.stderr:
        return completed.stderr
    else:
        return None

def run(args, executable):
    while True:
        result = run_one(args, executable)
        if result is not None:
            sys.stderr.buffer.write(result)
            sys.stderr.flush()
            return "false"


args = parse_args()
executable = compile(args)
result = run(args, executable)
print(f"SV-COMP result: {result}")
