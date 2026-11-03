#!/usr/bin/env python3
"""Reproduce nushell#19419 on Windows under a real pseudoconsole.

Each scenario starts a process under ConPTY, the same mechanism Windows Terminal uses, and presses
Ctrl-C by writing 0x03 to the console input. The console host turns that into a CTRL_C_EVENT for
every attached process. Handles to every descendant are opened while it is alive, so the exit code
of a process that has already gone can still be read.

Usage: probe.py --nu <path to nu.exe> --out <dir> [--only a,b]
"""
import argparse
import collections
import ctypes
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
import traceback
from ctypes import wintypes

import psutil
from winpty import PtyProcess

SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_TIMEOUT = 0x102

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
k32.OpenProcess.restype = wintypes.HANDLE
k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
k32.GetExitCodeProcess.restype = wintypes.BOOL
k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
k32.WaitForSingleObject.restype = wintypes.DWORD

KNOWN_EXIT_CODES = {
    0xC000013A: "STATUS_CONTROL_C_EXIT",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN (abort or fast fail)",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
}

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
TERMINAL_QUERY = re.compile(r"\x1b\[(6n|0?c)")


def clean(text):
    """Terminal output as plain text."""
    return ANSI.sub("", text).replace("0011Ignore", "")


def describe_exit(code):
    if code is None:
        return "unknown"
    name = KNOWN_EXIT_CODES.get(code)
    signed = code - (1 << 32) if code >= (1 << 31) else code
    return f"{signed} (0x{code:08X}{', ' + name if name else ''})"


class Tracked:
    """One descendant, with a handle that outlives the process."""

    def __init__(self, info):
        self.pid = info["pid"]
        self.ppid = info["ppid"]
        self.name = info["name"] or "?"
        self.cmdline = " ".join(info["cmdline"] or [])[:200]
        self.created = info["create_time"]
        self.handle = k32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
        self.died_at = None

    def alive(self):
        if not self.handle:
            return psutil.pid_exists(self.pid)
        return k32.WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT

    def exit_code(self):
        if not self.handle or self.alive():
            return None
        code = wintypes.DWORD()
        return code.value if k32.GetExitCodeProcess(self.handle, ctypes.byref(code)) else None


class Tracker:
    """Follows the process tree under `root`, including children of a parent that has died."""

    def __init__(self, root):
        self.root = root
        self.procs = {}
        self.lock = threading.Lock()
        self.t0 = None
        self.stop_flag = threading.Event()
        self.poll_tree()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def poll_tree(self):
        rows = [p.info for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"])]
        by_pid = {r["pid"]: r for r in rows}
        by_parent = collections.defaultdict(list)
        for row in rows:
            by_parent[row["ppid"]].append(row)
        with self.lock:
            if self.root in by_pid and self.root not in self.procs:
                self.procs[self.root] = Tracked(by_pid[self.root])
            frontier = [t.pid for t in self.procs.values() if t.alive()]
            seen = set()
            while frontier:
                pid = frontier.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                parent = self.procs.get(pid)
                for child in by_parent.get(pid, []):
                    # A process older than its "parent" only shares a recycled pid with it.
                    if parent and child["create_time"] and child["create_time"] < parent.created:
                        continue
                    if child["pid"] not in self.procs:
                        self.procs[child["pid"]] = Tracked(child)
                    frontier.append(child["pid"])

    def _loop(self):
        tick = 0
        while not self.stop_flag.is_set():
            with self.lock:
                for t in self.procs.values():
                    if t.died_at is None and not t.alive():
                        t.died_at = time.monotonic()
            tick += 1
            if tick % 5 == 0:
                try:
                    self.poll_tree()
                except Exception:
                    traceback.print_exc()
            time.sleep(0.05)

    def has(self, wanted):
        with self.lock:
            counts = collections.Counter(t.name.lower() for t in self.procs.values() if t.alive())
        return all(counts[name] >= count for name, count in wanted.items())

    def snapshot(self):
        with self.lock:
            procs = list(self.procs.values())
        alive = {t.pid for t in procs if t.alive()}
        rows = []
        for t in procs:
            is_alive = t.pid in alive
            rows.append(
                {
                    "name": t.name,
                    "pid": t.pid,
                    "ppid": t.ppid,
                    "alive": is_alive,
                    "orphan": is_alive and t.pid != self.root and t.ppid not in alive,
                    "exit": None if is_alive else describe_exit(t.exit_code()),
                    "died_after_ctrl_c_s": (
                        round(t.died_at - self.t0, 2) if t.died_at and self.t0 else None
                    ),
                    "cmdline": t.cmdline,
                }
            )
        return rows

    def leftovers(self):
        """Live descendants, the newest first, so the leaf goes before whoever waits for it."""
        with self.lock:
            procs = list(self.procs.values())
        return [t for t in reversed(procs) if t.pid != self.root and t.alive()]

    def stop_and_kill(self):
        self.stop_flag.set()
        self.thread.join(timeout=5)
        with self.lock:
            procs = list(self.procs.values())
        for t in reversed(procs):
            if t.alive():
                subprocess.run(["taskkill", "/F", "/PID", str(t.pid)], capture_output=True, timeout=20)


class Pty:
    """A process under a pseudoconsole, with its output collected in the background."""

    def __init__(self, argv, cwd, env, raw_path):
        self.proc = PtyProcess.spawn(argv, cwd=cwd, env=env, dimensions=(40, 120))
        self.raw = open(raw_path, "w", encoding="utf-8", newline="")
        self.out = ""
        self.scanned = 0
        self.marked = 0
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                data = self.proc.read(4096)
            except EOFError:
                return
            except Exception:
                traceback.print_exc()
                return
            if not data:
                continue
            self.raw.write(data)
            self.raw.flush()
            with self.lock:
                self.out += data
            self._answer_queries()

    def _answer_queries(self):
        """Stand in for the terminal: the console host and reedline can wait for these replies."""
        with self.lock:
            matches = list(TERMINAL_QUERY.finditer(self.out, self.scanned))
            if matches:
                self.scanned = matches[-1].end()
        for match in matches:
            self.write("\x1b[1;1R" if match.group(1) == "6n" else "\x1b[?61;4c")

    def write(self, text):
        try:
            with self.write_lock:
                self.proc.write(text)
            return True
        except EOFError:
            return False

    def type_line(self, line):
        ok = self.write(line)
        time.sleep(0.3)
        return self.write("\r") and ok

    def text(self):
        with self.lock:
            return self.out

    def since_last_mark(self):
        with self.lock:
            chunk = self.out[self.marked :]
            self.marked = len(self.out)
        return clean(chunk)


def wait_until(condition, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


INNER_CMD = "@echo off\r\nping -t 127.0.0.1\r\n"
PRINT_EXIT_CODE = 'print $"LEC=($env.LAST_EXIT_CODE)"'
REPL = None  # replaced by the nu under test, started as a REPL
PING = {"ping.exe": 1}


def scenario(name, line=None, root=REPL, ready=PING, after="kill", lec=PRINT_EXIT_CODE):
    return {"name": name, "line": line, "root": root, "ready": ready, "after": after, "lec": lec}


SCENARIOS = [
    # What nu does on Ctrl-C when no batch file is involved.
    scenario("nested_sleep", "nu -c 'sleep 1hr'", ready={"nu.exe": 2}),
    # The control from the issue: no orphan, and the batch prompt can be answered.
    scenario("direct_answer", "^cmd /c inner.cmd", after="answer"),
    # The report.
    scenario("nested_answer", "nu -c '^cmd /c inner.cmd'", after="answer"),
    scenario("nested_kill", "nu -c '^cmd /c inner.cmd'"),
    scenario("script_kill", "nu start.nu"),
    scenario("ignore_kill", "nu -c '^cmd /c inner.cmd | ignore'"),
    scenario("complete_kill", "nu -c '^cmd /c inner.cmd | complete | ignore'"),
    # A plain executable, which the issue says behaves.
    scenario("nested_ping", "nu -c '^ping -t 127.0.0.1'"),
    # A child that survives Ctrl-C with no cmd.exe: does the outer nu still go away?
    scenario(
        "survivor",
        """nu -c '^nu -c "loop { try { sleep 1sec } catch { print caught } }"'""",
        ready={"nu.exe": 3},
    ),
    # Does the parent matter? No parent shell at all, then cmd.exe in place of the REPL.
    scenario("no_parent", root=["NU", "-c", "^cmd /c inner.cmd"], lec=None),
    scenario(
        "cmd_parent",
        'nu -c "^cmd /c inner.cmd"',
        root=["cmd.exe"],
        after="answer",
        lec="echo LEC=%ERRORLEVEL%",
    ),
]


def run_scenario(spec, args, work, out_dir):
    env = dict(os.environ)
    env["PATH"] = str(pathlib.Path(args.nu).parent) + os.pathsep + env.get("PATH", "")
    root = spec["root"] or [args.nu, "-n", "--no-history"]
    root = [args.nu if part == "NU" else part for part in root]
    result = {"name": spec["name"], "line": spec["line"], "root": root, "checkpoints": []}
    pty = Pty(root, str(work), env, out_dir / f"{spec['name']}.raw.txt")
    tracker = Tracker(pty.proc.pid)

    def checkpoint(label):
        result["checkpoints"].append(
            {"label": label, "tree": tracker.snapshot(), "screen": pty.since_last_mark()[-1500:]}
        )

    try:
        if spec["line"]:
            result["prompt_seen"] = wait_until(lambda: ">" in clean(pty.text()), 60)
            time.sleep(1)
            pty.type_line(spec["line"])
        result["ready"] = wait_until(lambda: tracker.has(spec["ready"]), 60)
        time.sleep(3)
        checkpoint("before ctrl-c")

        tracker.t0 = time.monotonic()
        pty.write("\x03")
        time.sleep(4)
        checkpoint("after ctrl-c")

        if spec["after"] == "answer":
            pty.write("y")
            time.sleep(0.3)
            pty.write("\r")
            time.sleep(4)
            checkpoint("after y + enter")

        killed = []
        for proc in tracker.leftovers():
            if proc.alive():
                killed.append(f"{proc.name}:{proc.pid}")
                subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=20)
                time.sleep(1)
        result["killed_by_probe"] = killed
        time.sleep(2)
        checkpoint("after killing leftovers")

        if spec["lec"]:
            for attempt in (1, 2):
                pty.type_line(spec["lec"])
                time.sleep(3)
                checkpoint(f"after exit code query {attempt}")
    finally:
        tracker.stop_and_kill()
    return result


def print_result(result):
    print(f"\n===== {result['name']}: {result['line'] or ' '.join(result['root'])}")
    print(f"prompt_seen={result.get('prompt_seen')} ready={result.get('ready')}")
    print(f"killed_by_probe={result.get('killed_by_probe')}")
    for point in result["checkpoints"]:
        print(f"--- {point['label']}")
        for row in point["tree"]:
            state = "ALIVE" if row["alive"] else f"exited {row['exit']} at +{row['died_after_ctrl_c_s']}s"
            flag = "  <-- ORPHAN" if row["orphan"] else ""
            print(f"  {row['name']:<12} pid={row['pid']:<6} ppid={row['ppid']:<6} {state}{flag}")
        screen = "\n".join(line.rstrip() for line in point["screen"].splitlines() if line.strip())
        print("  screen:")
        print("\n".join("    | " + line[:150] for line in screen.splitlines()[-14:]))
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nu", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", default="")
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out).absolute()
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "work"
    work.mkdir(exist_ok=True)
    (work / "inner.cmd").write_text(INNER_CMD, newline="")
    (work / "start.nu").write_text("^cmd /c inner.cmd\n")

    print("windows:", sys.getwindowsversion(), flush=True)
    print(subprocess.run([args.nu, "--version"], capture_output=True, text=True).stdout, flush=True)

    only = set(filter(None, args.only.split(",")))
    results = []
    for spec in SCENARIOS:
        if only and spec["name"] not in only:
            continue
        print(f"running {spec['name']}", flush=True)
        try:
            result = run_scenario(spec, args, work, out_dir)
        except Exception:
            traceback.print_exc()
            result = {"name": spec["name"], "line": spec["line"], "root": [], "checkpoints": [], "crashed": True}
        results.append(result)
        print_result(result)
        (out_dir / "results.json").write_text(json.dumps(results, indent=2, default=str))

    consoles = [
        p.info for p in psutil.process_iter(["pid", "name", "cmdline"]) if (p.info["name"] or "").lower() in ("openconsole.exe", "conhost.exe")
    ]
    print("console hosts:", json.dumps(consoles, default=str)[:1500], flush=True)
    # Open pseudoconsoles can make interpreter shutdown wait, and nothing is left to flush.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
