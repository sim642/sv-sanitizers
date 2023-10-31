#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path
import sys
import asyncio


VERSION="0.1.0"


def parse_args():
    parser = argparse.ArgumentParser(description="SV-COMP wrapper for sanitizers")

    parser.add_argument("-p", "--property", type=str, required=True)
    parser.add_argument("-d", "--data-model", type=str, choices=["ILP32", "LP64"], default="LP64")
    parser.add_argument("program", type=str)
    parser.add_argument("-j", "--jobs", type=int, default=1)
    parser.add_argument("-v", "--version", action="version", version=VERSION)

    args = parser.parse_args()
    return args

def parse_property(property):
    if property == "no-data-race":
        return "no-data-race"
    elif property == "valid-memsafety":
        return "valid-memsafety"
    elif Path(property).is_file():
        text = Path(property).read_text()
        if text.startswith("""CHECK( init(main()), LTL(G ! data-race) )"""):
            return "no-data-race"
        else:
            raise RuntimeError("unsupported property")
    else:
        raise RuntimeError("unsupported property")

async def compile(args):
    gcc_args = ["gcc", "-g", "sv-comp.c", args.program, "-lm"]
    if parse_property(args.property) == "no-data-race":
        gcc_args += ["-fsanitize=thread"]
    if parse_property(args.property) == "valid-memsafety":
        gcc_args += ["-fsanitize=address"]
    # ignore data model because tsan is 64bit only
    # if args.data_model == "ILP32":
    #     gcc_args += ["-m32"]
    # else:
    #     gcc_args += ["-m64"]
    process = await asyncio.create_subprocess_exec(*gcc_args)
    await process.wait()
    if process.returncode == 0:
        return Path("a.out").absolute()
    else:
        raise RuntimeError("compile error")

processes = set()
stop = False

async def run_one(args, executable):
    print(".", end="", flush=True)
    env={
        "TSAN_OPTIONS": r""""exitcode"=66 "halt_on_error"=1 "report_thread_leaks"=0 "report_destroy_locked"=0 "report_signal_unsafe"=0 suppressions=suppressions.txt""",
        "ASAN_OPTIONS": r""""halt_on_error"=true "detect_leaks"=1 detect_stack_use_after_return=1"""
    }
    with open("/dev/urandom", "r") as urandom:
        process = await asyncio.create_subprocess_exec(executable, stdin=urandom, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE, env=env)
        processes.add(process)
        try:
            _, stderr = await process.communicate()
            if process.returncode == 66 and b"WARNING: ThreadSanitizer: data race" in stderr:
                return ("false", stderr)
            elif b"ERROR: AddressSanitizer: dynamic-stack-buffer-overflow" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: heap-use-after-free" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: heap-buffer-overflow" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: stack-buffer-overflow" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: global-buffer-overflow" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: stack-use-after-scope" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: stack-use-after-return" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: attempting double-free" in stderr:
                return ("false(valid-free)", stderr)
            elif b"ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed" in stderr:
                return ("false(valid-free)", stderr)
            elif b"ERROR: LeakSanitizer: detected memory leaks" in stderr:
                return ("false(valid-memtrack)", stderr)
            else:
                return None
        finally:
            processes.remove(process)

async def run_worker(args, executable):
    while not stop:
        result = await run_one(args, executable)
        if result is not None:
            return result
    return None

async def run(args, executable):
    tasks = [asyncio.create_task(run_worker(args, executable), name=f"worker-{i}") for i in range(args.jobs)]
    done, pending = await asyncio.wait(tasks, return_when="FIRST_COMPLETED")
    global stop
    stop = True
    for process in processes:
        process.kill()
    for task in pending:
        task.cancel()
    return done.pop().result()

async def main():
    args = parse_args()
    executable = await compile(args)
    result, output = await run(args, executable)
    print()
    sys.stderr.buffer.write(output)
    sys.stderr.flush()
    print(f"SV-COMP result: {result}")

asyncio.run(main())
