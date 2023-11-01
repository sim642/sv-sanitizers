#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path
import sys
import asyncio
import hashlib
from datetime import datetime


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
    elif property == "valid-memcleanup":
        return "valid-memcleanup"
    elif Path(property).is_file():
        text = Path(property).read_text()
        if text.startswith("""CHECK( init(main()), LTL(G ! data-race) )"""):
            return "no-data-race"
        elif text.startswith("""CHECK( init(main()), LTL(G valid-free) )
CHECK( init(main()), LTL(G valid-deref) )
CHECK( init(main()), LTL(G valid-memtrack) )"""):
            return "valid-memsafety"
        elif text.startswith("""CHECK( init(main()), LTL(G valid-memcleanup) )"""):
            return "valid-memcleanup"
        else:
            raise RuntimeError("unsupported property")
    else:
        raise RuntimeError("unsupported property")

async def compile(args):
    gcc_args = ["gcc", "-g", "sv-comp.c", args.program, "-lm"]
    if args.property == "no-data-race":
        gcc_args += ["-fsanitize=thread"]
        # ignore data model because tsan is 64bit only
    elif args.property == "valid-memsafety" or args.property == "valid-memcleanup":
        gcc_args += ["-fsanitize=address"]
        if args.data_model == "ILP32":
            gcc_args += ["-m32"]
        else:
            gcc_args += ["-m64"]
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
            elif b"ERROR: AddressSanitizer: dynamic-stack-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: heap-use-after-free" in stderr \
                or b"ERROR: AddressSanitizer: heap-use-after-free" in stderr \
                or b"ERROR: AddressSanitizer: heap-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: stack-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: global-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: stack-use-after-scope" in stderr \
                or b"ERROR: AddressSanitizer: stack-use-after-return" in stderr:
                return ("false(valid-deref)", stderr)
            elif b"ERROR: AddressSanitizer: attempting double-free" in stderr \
                or b"ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed" in stderr:
                return ("false(valid-free)", stderr)
            elif b"ERROR: LeakSanitizer: detected memory leaks" in stderr:
                if args.property == "valid-memcleanup":
                    return ("false", stderr)
                else:
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

def generate_witness(args, result):
    if args.property == "no-data-race":
        specification = """CHECK( init(main()), LTL(G ! data-race) )"""
    elif args.property == "valid-memcleanup":
        specification = """CHECK( init(main()), LTL(G valid-memcleanup) )"""
    elif result == "false(valid-deref)":
        specification = """CHECK( init(main()), LTL(G valid-deref) )"""
    elif result == "false(valid-free)":
        specification = """CHECK( init(main()), LTL(G valid-free) )"""
    elif result == "false(valid-memtrack)":
        specification = """CHECK( init(main()), LTL(G valid-memtrack) )"""
    else:
        raise RuntimeError("unknown witness specification")
    with open(args.program, "rb") as file:
        programhash = hashlib.sha256(file.read()).hexdigest()
    architecture = "32bit" if args.data_model == "ILP32" else "64bit"
    creationtime = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    witness = f"""<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <key id="witness-type" for="graph" attr.name="witness-type" attr.type="string"/>
  <key id="sourcecodelang" for="graph" attr.name="sourcecodelang" attr.type="string"/>
  <key id="producer" for="graph" attr.name="producer" attr.type="string"/>
  <key id="specification" for="graph" attr.name="specification" attr.type="string"/>
  <key id="programfile" for="graph" attr.name="programfile" attr.type="string"/>
  <key id="programhash" for="graph" attr.name="programhash" attr.type="string"/>
  <key id="architecture" for="graph" attr.name="architecture" attr.type="string"/>
  <key id="creationtime" for="graph" attr.name="creationtime" attr.type="string"/>
  <key id="entry" for="node" attr.name="entry" attr.type="boolean">
    <default>false</default>
  </key>
  <key id="sink" for="node" attr.name="sink" attr.type="boolean">
    <default>false</default>
  </key>
  <key id="violation" for="node" attr.name="violation" attr.type="boolean">
    <default>false</default>
  </key>
  <key id="invariant" for="node" attr.name="invariant" attr.type="string"/>
  <key id="invariant.scope" for="node" attr.name="invariant.scope" attr.type="string"/>
  <key id="assumption" for="edge" attr.name="assumption" attr.type="string"/>
  <key id="assumption.scope" for="edge" attr.name="assumption.scope" attr.type="string"/>
  <key id="assumption.resultfunction" for="edge" attr.name="assumption.resultfunction" attr.type="string"/>
  <key id="control" for="edge" attr.name="control" attr.type="string"/>
  <key id="startline" for="edge" attr.name="startline" attr.type="int"/>
  <key id="endline" for="edge" attr.name="endline" attr.type="int"/>
  <key id="startoffset" for="edge" attr.name="startoffset" attr.type="int"/>
  <key id="endoffset" for="edge" attr.name="endoffset" attr.type="int"/>
  <key id="enterLoopHead" for="edge" attr.name="enterLoopHead" attr.type="boolean">
    <default>false</default>
  </key>
  <key id="enterFunction" for="edge" attr.name="enterFunction" attr.type="string"/>
  <key id="returnFromFunction" for="edge" attr.name="returnFromFunction" attr.type="string"/>
  <key id="threadId" for="edge" attr.name="threadId" attr.type="string"/>
  <key id="createThread" for="edge" attr.name="createThread" attr.type="string"/>
  <key id="goblintEdge" for="edge" attr.name="goblintEdge" attr.type="string"/>
  <key id="goblintLine" for="edge" attr.name="goblintLine" attr.type="string"/>
  <graph edgedefault="directed">
    <data key="witness-type">violation_witness</data>
    <data key="sourcecodelang">C</data>
    <data key="producer">sv-sanitizers {VERSION}</data>
    <data key="specification">{specification}</data>
    <data key="programfile">{args.program}</data>
    <data key="programhash">{programhash}</data>
    <data key="architecture">{architecture}</data>
    <data key="creationtime">{creationtime}</data>
    <node id="N0">
      <data key="entry">true</data>
    </node>
    <node id="N1">
      <data key="violation">true</data>
    </node>
    <edge id="E0" source="N0" target="N1"/>
  </graph>
</graphml>
"""
    with open("witness.graphml", "w") as file:
        file.write(witness)

async def main():
    args = parse_args()
    args.property = parse_property(args.property)
    executable = await compile(args)
    result, output = await run(args, executable)
    print()
    sys.stderr.buffer.write(output)
    sys.stderr.flush()
    print(f"SV-COMP result: {result}")
    generate_witness(args, result)

asyncio.run(main())
