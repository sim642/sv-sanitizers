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

async def compile(args):
    gcc_args = ["gcc", "-g", "sv-comp.c", args.program, "-lm"]
    if parse_property(args.property) == "no-data-race":
        gcc_args += ["-fsanitize=thread"]
    # ignore data model because tsan is 64bit only
    # if args.data_model == "ILP32":
    #     gcc_args += ["-m32"]
    # else:
    #     gcc_args += ["-m64"]
    completed = await asyncio.create_subprocess_exec(*gcc_args)
    await completed.wait()
    if completed.returncode == 0:
        return Path("a.out").absolute()
    else:
        raise RuntimeError("compile error")

procs = set()
stop = False

async def run_one(args, executable):
    print(".", end="", flush=True)
    env={
        "TSAN_OPTIONS": r""""exitcode"=66 "halt_on_error"=1 "report_thread_leaks"=0 "report_destroy_locked"=0 "report_signal_unsafe"=0 suppressions=suppressions.txt"""
    }
    completed = await asyncio.create_subprocess_exec(executable, stderr=asyncio.subprocess.PIPE, env=env)
    procs.add(completed)
    _, stderr = await completed.communicate()
    if completed.returncode == 66 and b"WARNING: ThreadSanitizer: data race" in stderr:
        procs.remove(completed)
        return stderr
    else:
        procs.remove(completed)
        return None

def do_stop():
    global stop
    stop = True
    for proc in procs:
        proc.kill()

async def run_thread(args, executable):
    while not stop:
        result = await run_one(args, executable)
        if result is not None:
            sys.stderr.buffer.write(result)
            sys.stderr.flush()
            return "false"

async def run(args, executable):
    global stop
    tasks = [asyncio.create_task(run_thread(args, executable)) for i in range(4)]
    (done, pending) = await asyncio.wait(tasks, return_when="FIRST_COMPLETED")
    do_stop()
    return done.pop().result()



async def main():
    args = parse_args()
    executable = await compile(args)
    result = await run(args, executable)
    print(f"SV-COMP result: {result}")

asyncio.run(main())
