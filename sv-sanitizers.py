#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys
import asyncio
import hashlib
from datetime import datetime, timezone
from uuid import uuid4
import re


VERSION="0.2.4"
SCRIPT_DIR = Path(__file__).parent


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
    elif property == "no-overflow":
        return "no-overflow"
    elif property == "unreach-call":
        return "unreach-call"
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
        elif text.startswith("""CHECK( init(main()), LTL(G ! overflow) )"""):
            return "no-overflow"
        elif text.startswith("""CHECK( init(main()), LTL(G ! call(reach_error())) )"""):
            return "unreach-call"
        else:
            raise RuntimeError("unsupported property")
    else:
        raise RuntimeError("unsupported property")

def determine_witness_specification(args, result):
    if args.property == "no-data-race":
        specification = """CHECK( init(main()), LTL(G ! data-race) )"""
    elif args.property == "valid-memcleanup":
        specification = """CHECK( init(main()), LTL(G valid-memcleanup) )"""
    elif args.property == "no-overflow":
        specification = """CHECK( init(main()), LTL(G ! overflow) )"""
    elif result == "false(valid-deref)":
        specification = """CHECK( init(main()), LTL(G valid-deref) )"""
    elif result == "false(valid-free)":
        specification = """CHECK( init(main()), LTL(G valid-free) )"""
    elif result == "false(valid-memtrack)":
        specification = """CHECK( init(main()), LTL(G valid-memtrack) )"""
    elif args.property == "unreach-call":
        specification = """CHECK( init(main()), LTL(G ! call(reach_error())) )"""
    else:
        raise RuntimeError("unknown witness specification")
    return specification

async def compile(args):
    gcc_args = ["gcc", "-ffunction-sections", "-fdata-sections", "-g", str(SCRIPT_DIR / "sv-comp.c"), args.program, "-lm", "-fgnu89-inline", "-Wl,--gc-sections"] # tasks like pthread-ext/03_incdec need gnu inline, hopefully this is fine for others
    # Sections trickery for compile-time check of reach_error.
    if args.property == "no-data-race":
        gcc_args += ["-fsanitize=thread"]
        # ignore data model because tsan is 64bit only
    else:
        if args.property == "valid-memsafety" or args.property == "valid-memcleanup":
            gcc_args += ["-fsanitize=address"]
        elif args.property == "no-overflow":
            gcc_args += ["-fsanitize=signed-integer-overflow", "-fsanitize=shift-base"] #, "-fno-sanitize-recover=signed-integer-overflow"]
        elif args.property == "unreach-call":
            gcc_args += ["-DSV_SANITIZERS_REACH_ERROR", "-lbacktrace", "-Wl,--defsym,reach_error=__sv_sanitizers_reach_error"] # Trickery for wrapping non-weak functions defined in the input file: https://stackoverflow.com/a/63350723/854540.

        if args.data_model == "ILP32":
            gcc_args += ["-m32"]
        else:
            gcc_args += ["-m64"]
    process = await asyncio.create_subprocess_exec(*gcc_args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    _, stderr = await process.communicate()
    if process.returncode == 0:
        if args.property == "no-overflow" and (m := re.search(rb"^(.*):(\d+):(\d+): warning: integer overflow in expression", stderr, flags=re.MULTILINE)):
            file = m.group(1)
            line = int(m.group(2))
            return (Path("a.out").absolute(), "false(no-overflow)", [(file, line, None)], stderr)
        else:
            return (Path("a.out").absolute(), None, None, stderr)
    else:
        return (None, "ERROR (compile)", None, stderr)

async def check_symbols(args, executable):
    if args.property == "no-overflow":
        process = await asyncio.create_subprocess_exec("nm", executable, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        if b"__ubsan_" in stdout:
            return None
        else:
            return ("true", None, stdout)
    elif args.property == "unreach-call":
        process = await asyncio.create_subprocess_exec("nm", executable, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        # gc-sections still leaves reach_error, but uncalled defsym-ed __sv_sanitizers_reach_error is removed
        if b"__sv_sanitizers_reach_error" in stdout:
            return None
        else:
            return ("true", None, stdout)
    else:
        return None

processes = set()
stop = False


def parse_san_stacktraces(stackframe_re: re.Pattern, stderr):
    result = []
    last_i = None

    for m in stackframe_re.finditer(stderr): # finditer returns matches
        i = int(m.group("i"))
        fun = m.group("fun")
        if fun:
            fun = fun.decode('utf-8')
        file = m.group("file")
        if file:
            file = file.decode('utf-8')
        line = m.group("line")
        if line:
            line = int(line)

        if last_i is None or i <= last_i:
            result.append([])
        result[-1].append((file, line, fun))

        last_i = i

    return result

def find_program_stackframe(program, stacktrace):
    program_name = Path(program).name
    for stackframe in stacktrace:
        file = stackframe[0]
        if file is not None and Path(file).name == program_name:
            return stackframe
    return None

TSAN_STACKFRAME_RE = re.compile(rb"^    #(?P<i>\d+) (?P<fun>\w+) (?P<file>.*):(?P<line>\d+)(?: \(([^)]+)\))?(?: \(BuildId: ([0-9a-z]+)\))?$", flags=re.MULTILINE)

def parse_tsan_targets(program, stderr):
    stacktraces = parse_san_stacktraces(TSAN_STACKFRAME_RE, stderr)
    if len(stacktraces) >= 2:
        return [find_program_stackframe(program, stacktrace) for stacktrace in stacktraces[:2]]
    else:
        return []

ASAN_STACKFRAME_RE = re.compile(rb"^    #(?P<i>\d+) 0x[0-9a-z]+ (?:in (?P<fun>\w+))?(?: (?P<file>.*):(?P<line>\d+))?(?: \(([^)]+)\))?(?: \(BuildId: ([0-9a-z]+)\))?$", flags=re.MULTILINE)

def parse_asan_targets(program, stderr):
    stacktraces = parse_san_stacktraces(ASAN_STACKFRAME_RE, stderr)
    if stacktraces:
        return [find_program_stackframe(program, stacktraces[0])]
    else:
        return []

UBSAN_STACKFRAME_RE = ASAN_STACKFRAME_RE

def parse_ubsan_targets(program, stderr):
    stacktraces = parse_san_stacktraces(ASAN_STACKFRAME_RE, stderr)
    if stacktraces:
        return [find_program_stackframe(program, stacktraces[0])]
    else:
        return []

LIBBACKTRACE_STACKFRAME_RE = re.compile(rb"^    #(?P<i>\d+) 0x[0-9a-z]+ (?:\?\?\?|(?P<fun>\w+)) (?:\?\?\?|(?P<file>.*)):(?:0|(?P<line>\d+))$", flags=re.MULTILINE)

def parse_libbacktrace_targets(program, stderr):
    stacktraces = parse_san_stacktraces(LIBBACKTRACE_STACKFRAME_RE, stderr)
    if stacktraces:
        return [find_program_stackframe(program, stacktraces[0])]
    else:
        return []

async def run_one(args, executable):
    print(".", end="", flush=True)
    env={
        "TSAN_OPTIONS": f""""exitcode"=66 "halt_on_error"=1 "report_thread_leaks"=0 "report_destroy_locked"=0 "report_signal_unsafe"=0 suppressions={str(SCRIPT_DIR / "suppressions.txt")}""",
        "ASAN_OPTIONS": r""""halt_on_error"=true "detect_leaks"=1 detect_stack_use_after_return=1""",
        "UBSAN_OPTIONS": r"""halt_on_error=1 print_stacktrace=1"""
    }
    with open("/dev/urandom", "r") as urandom:
        process = await asyncio.create_subprocess_exec(executable, stdin=urandom, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE, env=env)
        processes.add(process)
        try:
            _, stderr = await process.communicate()
            if process.returncode == 66 and b"WARNING: ThreadSanitizer: data race" in stderr:
                return ("false(no-data-race)", parse_tsan_targets(args.program, stderr), stderr)
            elif process.returncode == 99 and b"ERROR: SV-sanitizers: reach_error" in stderr:
                return ("false(unreach-call)", parse_libbacktrace_targets(args.program, stderr), stderr)
            elif b"ERROR: AddressSanitizer: dynamic-stack-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: heap-use-after-free" in stderr \
                or b"ERROR: AddressSanitizer: heap-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: stack-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: stack-buffer-underflow" in stderr \
                or b"ERROR: AddressSanitizer: global-buffer-overflow" in stderr \
                or b"ERROR: AddressSanitizer: stack-use-after-scope" in stderr \
                or b"ERROR: AddressSanitizer: stack-use-after-return" in stderr \
                or b"ERROR: AddressSanitizer: SEGV on unknown address" in stderr:
                return ("false(valid-deref)", parse_asan_targets(args.program, stderr), stderr)
            elif b"ERROR: AddressSanitizer: attempting double-free" in stderr \
                or b"ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed" in stderr:
                return ("false(valid-free)", parse_asan_targets(args.program, stderr), stderr) # double-free has free itself as #0 and actual call as #1
            elif b"ERROR: LeakSanitizer: detected memory leaks" in stderr:
                if args.property == "valid-memcleanup":
                    return ("false(valid-memcleanup)", [], stderr) # TODO: target
                else:
                    return ("false(valid-memtrack)", [], stderr) # TODO: target
            elif b"runtime error: signed integer overflow" in stderr \
                or b"runtime error: division of" in stderr \
                or b"runtime error: negation of" in stderr \
                or b"runtime error: left shift of" in stderr:
                return ("false(no-overflow)", parse_ubsan_targets(args.program, stderr), stderr)
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

def generate_yaml_witness(args, result, targets):
    specification = determine_witness_specification(args, result)
    with open(args.program, "rb") as file:
        programhash = hashlib.sha256(file.read()).hexdigest()
    creationtime = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z') # https://stackoverflow.com/a/42777551/854540
    uuid = uuid4()
    format_version = "2.2" if targets and len(targets) >= 2 else "2.0"
    metadata = f"""metadata:
    format_version: "{format_version}"
    uuid: {uuid}
    creation_time: {creationtime}
    producer:
      name: SV-sanitizers
      version: {VERSION}
    task:
      input_files:
      - {args.program}
      input_file_hashes:
        {args.program}: {programhash}
      data_model: {args.data_model}
      language: C
      specification: {specification}"""
    if result.startswith("false"):
        if not targets:
            # raise RuntimeError("false result without target")
            return
        witness = f"""- entry_type: violation_sequence
  {metadata}
  content:
  - segment:
"""
        for target_file, target_line, target_fun in targets:
            witness += f"""    - waypoint:
        type: target
        action: follow
        location:
          file_name: {target_file}
          line: {target_line}
"""
            if target_fun is not None:
                witness += f"""          function: {target_fun}
"""
    elif result == "true":
        witness = f"""- entry_type: invariant_set
  {metadata}
  content: []
"""
    else:
        raise RuntimeError("unknown result")
    with open("witness.yml", "w") as file:
        file.write(witness)

async def main():
    args = parse_args()
    args.property = parse_property(args.property)
    executable, result, targets, output = await compile(args)
    if result is None:
        result_output = await check_symbols(args, executable)
        if result_output is None:
            result, targets, output = await run(args, executable)
        else:
            result, targets, output = result_output
    print()
    sys.stderr.buffer.write(output)
    sys.stderr.flush()
    print(f"SV-COMP result: {result}")
    if executable is not None:
        generate_yaml_witness(args, result, targets)

asyncio.run(main())
