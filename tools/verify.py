#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and verify a release candidate in an isolated Ghidra copy (no firmware)."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from zipfile import ZipFile

from check_archive import check_archive

ROOT = Path(__file__).resolve().parents[1]
# fixture, generated manifests, [(script suffix, arguments, success marker)], analysis
def case(fixture, script, marker, manifest="tsv", args=None, analysis=False):
    manifests = [f"cases.{manifest}"] if manifest else []
    return (fixture, manifests, [(script, args if args is not None else manifests, marker)], analysis)


CORE = [
    case("smoke", "Corpus", "C6000_PCODE_OK", None,
         ["image", "input.bin", "0x1000", "0", "48"]),
    case("compact-header-collision", "CompactHeader", "C6000_COMPACT_HEADER_OK", None),
    case("compact-operands", "CompactOperands", "C6000_COMPACT_OPERANDS_OK"),
    case("compact-predicated-mvk", "CompactPredicatedMvk", "C6000_COMPACT_PREDICATED_MVK_OK", "json"),
    case("compact-move-memory", "CompactMoveMemory", "C6000_COMPACT_MOVE_MEMORY_OK"),
    case("compact-memory", "CompactMemory", "C6000_COMPACT_MEMORY_OK", "json"),
    case("compact-compare-destination", "CompactCompareDestination", "C6000_COMPACT_COMPARE_DESTINATION_OK"),
    case("full32-encoding-info", "Full32EncodingInfo", "C6000_FULL32_ENCODING_INFO_OK"),
    case("return-delay", "ReturnDelay", "C6000_RETURN_DELAY_OK"),
    case("packet-call", "PacketCall", "C6000_PACKET_CALL_OK"),
    # The refusal script constructs its own memory blocks outside this small image.
    case("branch-flow", "DelaySafety", "C6000_DELAY_SAFETY_OK", args=[]),
    case("branch-flow", "FlowTarget", "C6000_FLOW_TARGET_OK"),
    case("delayed-call", "DelayedCall", "C6000_DELAYED_CALL_OK", None, analysis=True),
    case("delayed-call-safety", "DelayedCallSafety", "C6000_DELAYED_CALL_SAFETY_OK", "json"),
    ("jump-table", [], [("JumpTable", [], "C6000_JUMP_TABLE_OK"),
                        ("SwitchOwnership", [], "C6000_SWITCH_OWNERSHIP_OK")], True),
    case("constant-branch-target", "ConstantBranchTarget", "C6000_CONSTANT_BRANCH_TARGET_OK",
         args=["check", "cases.tsv"], analysis=True),
    case("predicated-register-branch", "PredicatedBranch", "C6000_PREDICATED_BRANCH_OK", analysis=True),
    case("pipeline-schedule", "PipelineSemantics", "C6000_PIPELINE_SEMANTICS_OK", None, ["decompiler.xml"]),
    case("pipeline-c67x", "PipelineCpu", "C6000_PIPELINE_CPU_OK", "json"),
    case("pipeline-resources", "PipelineResources", "C6000_PIPELINE_RESOURCES_OK", "json"),
    case("pipeline-call-contracts", "PipelineCallContract", "C6000_PIPELINE_CALL_CONTRACT_OK", "json", ["cases.json", "results.json"]),
    case("pipeline-contracts", "PipelineContract", "C6000_PIPELINE_CONTRACT_OK", "json"),
    case("pipeline-float", "PipelineFloat", "C6000_PIPELINE_FLOAT_OK"),
    case("pipeline-dp", "PipelineDp", "C6000_PIPELINE_DP_OK", "json", ["cases.json", "decompile"]),
    case("pipeline-dp-arithmetic", "PipelineDp", "C6000_PIPELINE_DP_OK", "json"),
    case("pipeline-dp-read-timing", "PipelineDp", "C6000_PIPELINE_DP_OK", "json", ["cases.json", "decompile"]),
    case("pipeline-loop", "PipelineDp", "C6000_PIPELINE_DP_OK", "json", ["cases.json", "decompile"]),
    case("loop-counter-proof", "LoopCounterProof", "C6000_LOOP_COUNTER_PROOF_OK", "json"),
    case("pipeline-counter-branch", "PipelineCounterBranch", "C6000_PIPELINE_COUNTER_BRANCH_OK", "json"),
    case("pipeline-bnop", "PipelineBnop", "C6000_PIPELINE_BNOP_OK", "json"),
    case("pipeline-predicated-return", "PipelinePredicatedReturn", "C6000_PIPELINE_PREDICATED_RETURN_OK", "json"),
    case("pipeline-andn", "PipelineAndn", "C6000_PIPELINE_ANDN_OK", "json"),
    case("pipeline-pack", "PipelinePack", "C6000_PIPELINE_PACK_OK", "json"),
    case("pipeline-rotl", "PipelineRotl", "C6000_PIPELINE_ROTL_OK", "json"),
    case("pipeline-mpyli", "PipelineMpyli", "C6000_PIPELINE_MPYLI_OK", "json"),
    case("pipeline-load-alias", "PipelineLoadAlias", "C6000_PIPELINE_LOAD_ALIAS_OK", "json"),
    case("pipeline-calls", "PipelineCalls", "C6000_PIPELINE_CALLS_OK", "json", ["cases.json", "results.json"]),
    case("closed-call", "ClosedCallTrace", "CLOSED_CALL_TRACE_TEST_OK", "json",
         ["cases.json", "results.json"]),
    case("exact-fp-selection", "ExactFloatSelection", "C6000_EXACT_FLOAT_SELECTION_OK"),
    case("float-addsub-sp", "FloatAdd", "C6000_FLOAT_ADD_OK"),
    case("mpysp", "FloatMultiply", "C6000_FLOAT_MULTIPLY_OK"),
    case("mpysp2dp", "FloatMultiply", "C6000_FLOAT_MULTIPLY_OK"),
    case("dpsp", "ConvertStatus", "C6000_CONVERT_STATUS_OK"),
    case("int-to-sp", "ConvertStatus", "C6000_CONVERT_STATUS_OK"),
    ("float-dp-arithmetic", ["add.tsv", "mul.tsv"],
     [("FloatAdd", ["add.tsv"], "C6000_FLOAT_ADD_OK"),
      ("FloatMultiply", ["mul.tsv"], "C6000_FLOAT_MULTIPLY_OK")], False),

    case("compact-dstk", "CompactDstk", "C6000_COMPACT_DSTK_OK"),
    case("compact-ndw", "CompactNdw", "C6000_COMPACT_NDW_OK"),
    case("long-arith", "LongArithmetic", "C6000_LONG_ARITH_OK", None),
    case("nop-count", "NopCount", "C6000_NOP_COUNT_OK"),
    case("compact-cross", "CompactCross", "C6000_COMPACT_CROSS_OK"),
    case("compact-cmpdst", "CompactCmpDst", "C6000_COMPACT_CMPDST_OK"),
    case("gmpy4", "Gmpy4", "C6000_GMPY4_OK"),
    case("word-shifts", "WordShifts", "C6000_WORD_SHIFTS_OK"),
    case("dp-int", "DpConvert", "C6000_DP_INT_OK"),
]
TI = [
    case("pipeline-store-tail", "PipelineStoreTail", "C6000_PIPELINE_STORE_TAIL_OK", "json", ["cases.json", "results.json"]),
    case("caller-tail", "CallerTail", "C6000_CALLER_TAIL_OK", "json", ["cases.json", "results.json"]),
    case("pipeline-predicate-facts", "PredicateFacts", "PREDICATE_FACTS_TEST_OK", "json"),
    case("pipeline-caller-continuation", "CallerContinuation", "CONTINUATION_CONTRACT_TEST_OK",
         "json", ["cases.json", "results.json"]),
    case("pipeline-postloop", "PostLoopDispatch", "C6000_POSTLOOP_OK", "json"),
]


def properties(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if "=" in line and not line.startswith("#"))


def run(command, log, env, timeout):
    with log.open("w") as output:
        process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise RuntimeError(f"Timed out after {timeout}s; see {log}")
    if code:
        raise RuntimeError(f"Exit status {code}; see {log}")
    return log.read_text(errors="replace")


def success_lines(output, marker):
    # A logged script command or stack trace is not evidence of completion.
    pattern = rf"^(?:.*?\bC6000\w+Test\.java> )?({re.escape(marker)}(?: [^\n]*)?)$"
    lines = re.findall(pattern, output, re.MULTILINE)
    if len(lines) != 1:
        raise RuntimeError(f"Expected one completion line for {marker}, found {len(lines)}")
    if re.search(r"\b(?:cases|checks|accepted|executions)=0\b", lines[0]):
        raise RuntimeError(f"Empty verification: {lines[0]}")
    return lines[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, default=os.environ.get(
        "GHIDRA_INSTALL_DIR", "/opt/homebrew/opt/ghidra/libexec"))
    parser.add_argument("--with-ti", action="store_true", help="require the three TI-assembled regressions")
    parser.add_argument("--endian", choices=["both", "le", "be"], default="both")
    parser.add_argument("--jobs", type=int, choices=[1, 2], default=1, help="parallel endian runs (separate homes)")
    parser.add_argument("--only", action="append", help="select a fixture name; repeat to select more")
    parser.add_argument("--list", action="store_true", help="list fixtures without building")
    parser.add_argument("--timeout", type=int, default=600, help="seconds per build/generator/headless invocation")
    args = parser.parse_args()
    cases = CORE + (TI if args.with_ti else [])
    if args.only:
        unknown = set(args.only) - {c[0] for c in cases}
        if unknown:
            parser.error("unknown fixture (TI fixtures require --with-ti): " + ", ".join(sorted(unknown)))
        cases = [c for c in cases if c[0] in args.only]
    if args.list:
        for fixture, _, scripts, analysis in cases:
            print(f"{fixture}: " + ", ".join(f"C6000{s[0]}Test.java" for s in scripts) +
                  (" (auto-analysis)" if analysis else ""))
        return 0
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    ghidra = args.ghidra.resolve()
    props = properties(ghidra / "Ghidra/application.properties")
    native_platform = {
        ("Darwin", "arm64"): "mac_arm_64",
        ("Darwin", "x86_64"): "mac_x86_64",
        ("Linux", "aarch64"): "linux_arm_64",
        ("Linux", "x86_64"): "linux_x86_64",
    }.get((platform.system(), platform.machine()))
    if native_platform:
        decompiler = ghidra / "Ghidra/Features/Decompiler"
        if not any(os.access(decompiler / directory / native_platform / "decompile", os.X_OK)
                   for directory in ("os", "build/os")):
            parser.error(f"missing Ghidra native decompiler for {native_platform}; "
                         f"see Building Native Components in {ghidra / 'GettingStarted.md'}")
    java_min = props["application.java.min"]
    env = os.environ.copy()
    if not env.get("JAVA_HOME"):
        candidates = [Path(f"/opt/homebrew/opt/openjdk@{java_min}/libexec/openjdk.jdk/Contents/Home"),
                      Path(f"/usr/lib/jvm/temurin-{java_min}-jdk-amd64"),
                      Path(f"/Library/Java/JavaVirtualMachines/temurin-{java_min}.jdk/Contents/Home")]
        env["JAVA_HOME"] = str(next((p for p in candidates if (p / "bin/java").is_file()), ""))
    if not (Path(env["JAVA_HOME"]) / "bin/java").is_file():
        parser.error(f"set JAVA_HOME to a JDK {java_min} or newer")
    if args.with_ti:
        compiler = Path(env.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
        if compiler.is_dir():
            compiler /= "cl6x"
        if not os.access(compiler, os.X_OK):
            parser.error("--with-ti requires cl6x; set TI_C6000_BIN")
    env["PATH"] = env["JAVA_HOME"] + "/bin:" + env["PATH"]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    (ROOT / "scratch").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="verify-", dir=ROOT / "scratch"))
    env["GHIDRA_INSTALL_DIR"] = str(ghidra)
    env["GHIDRA_WORK"] = str(work / "build")
    env.setdefault("GRADLE_USER_HOME", str(ROOT / "scratch/build/gradle"))
    print(f"Verification artifacts: {work}", flush=True)
    run([ROOT / "tools/build.sh"], work / "build.log", env, args.timeout)
    built_archive = Path((work / "build/archive-path.txt").read_text().strip())
    check_archive(built_archive, props["application.version"])
    archive = work / built_archive.name
    shutil.copy2(built_archive, archive)
    install = work / "ghidra"
    extensions = ghidra / "Ghidra/Extensions"
    shutil.copytree(ghidra, install, symlinks=True,
                    ignore=lambda directory, names: names if Path(directory) == extensions else [])
    with ZipFile(archive) as source:
        source.extractall(install / "Ghidra/Extensions")
    report = {"started_utc": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "worktree_status": subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True),
              "ghidra": props["application.version"], "java_home": env["JAVA_HOME"],
              "build_archive": str(built_archive), "archive": str(archive),
              "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
              "ti_requested": args.with_ti,
              "scope": "selected fixtures" if args.only else "release regressions",
              "results": []}

    def verify_endian(endian):
        results = []
        local_env = env.copy()
        home = work / endian / "home"
        home.mkdir(parents=True)
        local_env["_JAVA_OPTIONS"] = f"-Duser.home={home}"
        project = work / endian / "projects"
        project.mkdir()
        runs = [(item, variant) for item in cases for variant in
                (("default", "analysis", "c67x", "c67x-analysis")
                 if item[0] in {"pipeline-c67x", "pipeline-resources"} else ("default",))]
        for index, ((fixture, manifests, scripts, analysis), variant) in enumerate(runs):
            directory = work / endian / f"{index:02d}-{fixture}-{variant}"
            directory.mkdir()
            image = directory / "input.bin"
            record = {"fixture": fixture, "endian": endian, "variant": variant, "log": str(directory / "headless.log")}
            start = time.monotonic()
            try:
                run([sys.executable, ROOT / "tests/fixtures" / f"{fixture}.py", image,
                     *(directory / m for m in manifests), *(["be"] if endian == "be" else [])],
                    directory / "generate.log", local_env, args.timeout)
                command = [install / "support/analyzeHeadless", project, f"case-{index}",
                           "-import", image, "-loader", "BinaryLoader", "-loader-baseAddr", "0x1000",
                           "-processor", f"C6000:{endian.upper()}:32:{variant}", "-cspec", "default",
                           "-scriptPath", ROOT / "ghidra_scripts", "-deleteProject"]
                if not analysis:
                    command += ["-noanalysis"]
                elif fixture == "constant-branch-target":
                    command += ["-preScript", "C6000ConstantBranchTargetTest.java", "prepare", directory / "cases.tsv"]
                else:
                    command += ["-preScript", "C6000SetEntry.java", "1000"]
                for script, script_args, _ in scripts:
                    command += ["-postScript", f"C6000{script}Test.java",
                                *(directory / a if "." in a else a for a in script_args)]
                record["command"] = list(map(str, command))
                output = run(command, directory / "headless.log", local_env, args.timeout)
                record["checks"] = [success_lines(output, marker) for _, _, marker in scripts]
                if fixture == "smoke":
                    coverage = success_lines(output, "C6000_COVERAGE")
                    if not re.search(r"\bundecoded=0\b", coverage):
                        raise RuntimeError("Smoke image has undecoded slots: " + coverage)
                    record["checks"].append(coverage)
                record["passed"] = True
            except (RuntimeError, OSError, ValueError) as error:
                record.update(passed=False, error=str(error))
            record["seconds"] = round(time.monotonic() - start, 2)
            results.append(record)
            print(f"{'PASS' if record['passed'] else 'FAIL'} {endian} {fixture} {variant} ({record['seconds']}s)", flush=True)
        return results

    endians = ["le", "be"] if args.endian == "both" else [args.endian]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for results in pool.map(verify_endian, endians):
            report["results"].extend(results)
    report["passed"] = all(r["passed"] for r in report["results"])
    (work / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{'VERIFIED' if report['passed'] else 'FAILED'}: {work / 'summary.json'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(f"error: {error}")
