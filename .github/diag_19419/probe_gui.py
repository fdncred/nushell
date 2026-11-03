#!/usr/bin/env python3
"""Reproduce nushell#19419 with real key events in a real terminal window.

probe.py writes 0x03 into a pseudoconsole. This drives the desktop instead: it opens Windows
Terminal or a classic console window, types with wscript's SendKeys, and takes screenshots. Output
can't be read back here, so the process tree shows what happened, and a file saved by the REPL shows
that it still takes input.

Usage: probe_gui.py --nu <path to nu.exe> --out <dir>
"""
import argparse
import glob
import json
import pathlib
import shutil
import subprocess
import sys
import time
import traceback

from probe import Tracker, process_rows, wait_until


def powershell(script):
    done = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=90,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return (done.stdout + done.stderr).strip()


def send_keys(host_pid, keys):
    """Give the window focus and press `keys`, written in SendKeys syntax. Returns AppActivate's answer."""
    escaped = keys.replace("'", "''")
    return powershell(
        f"$w = New-Object -ComObject wscript.shell; $ok = $w.AppActivate({host_pid}); "
        f"Start-Sleep -Milliseconds 300; $w.SendKeys('{escaped}'); $ok"
    )


def screenshot(path):
    return powershell(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
        "$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "
        "$i = New-Object System.Drawing.Bitmap $b.Width,$b.Height; "
        "$g = [System.Drawing.Graphics]::FromImage($i); "
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); "
        f"$i.Save('{path}'); $b.ToString()"
    )


def find_wt():
    found = shutil.which("wt.exe")
    if found:
        return found
    packaged = glob.glob(r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_*\wt.exe")
    return packaged[0] if packaged else None


def pids_named(name):
    return {row["pid"] for row in process_rows() if (row["name"] or "").lower() == name.lower()}


def repl_pids():
    return {
        row["pid"]
        for row in process_rows()
        if (row["name"] or "").lower() == "nu.exe" and "--no-history" in (row["cmdline"] or [])
    }


def open_window(host, nu, work):
    """Start a REPL in a new window. Returns (repl pid, window's pid, whether that process is new).

    The runner's own processes can live under an existing Windows Terminal, so only a process that
    this call started is safe to kill afterwards.
    """
    before_repl, before_wt = repl_pids(), pids_named("WindowsTerminal.exe")
    if host == "wt":
        wt = find_wt()
        print("wt:", wt, flush=True)
        if not wt:
            raise RuntimeError("Windows Terminal not found")
        started = subprocess.Popen([wt, "-w", "new", "-d", str(work), nu, "-n", "--no-history"])
    else:
        started = subprocess.Popen(["conhost.exe", nu, "-n", "--no-history"], cwd=str(work))
    if not wait_until(lambda: repl_pids() - before_repl, 40):
        raise RuntimeError("the REPL did not start")
    repl = sorted(repl_pids() - before_repl)[0]
    if host == "wt":
        new_terminals = pids_named("WindowsTerminal.exe") - before_wt
        terminal = sorted(new_terminals or pids_named("WindowsTerminal.exe"))[0]
        return repl, terminal, bool(new_terminals)
    return repl, started.pid, True


def run(name, host, keys, after, args, work, out_dir):
    result = {"name": name, "line": keys, "root": [host], "checkpoints": [], "focus": []}
    repl, host_pid, host_is_new = open_window(host, args.nu, work)
    tracker = Tracker(repl)

    def checkpoint(label):
        shot = out_dir / f"{name}_{label.replace(' ', '_').replace('+', 'and')}.png"
        result["screenshot"] = screenshot(shot)
        result["checkpoints"].append({"label": label, "tree": tracker.snapshot(), "screen": ""})

    try:
        time.sleep(6)
        checkpoint("prompt")
        result["focus"].append(send_keys(host_pid, keys + "{ENTER}"))
        result["ready"] = wait_until(lambda: tracker.has({"ping.exe": 1}), 25)
        time.sleep(3)
        checkpoint("before ctrl-c")

        tracker.t0 = time.monotonic()
        result["focus"].append(send_keys(host_pid, "^c"))
        time.sleep(5)
        checkpoint("after ctrl-c")

        if after == "answer":
            result["focus"].append(send_keys(host_pid, "y{ENTER}"))
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

        # Saved by the REPL itself, so the file only appears if it still takes input.
        for attempt in (1, 2):
            target = work / f"{name}_{attempt}.txt"
            result["focus"].append(
                send_keys(host_pid, f"$env.LAST_EXIT_CODE | save -f {target.name}" + "{ENTER}")
            )
            time.sleep(3)
            result[f"lec_{attempt}"] = target.read_text() if target.exists() else None
        checkpoint("after exit code query")
    finally:
        tracker.stop_and_kill()
        if host_is_new:
            subprocess.run(["taskkill", "/F", "/PID", str(host_pid)], capture_output=True, timeout=20)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nu", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args.nu = str(pathlib.Path(args.nu).absolute())

    out_dir = pathlib.Path(args.out).absolute()
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "work"
    work.mkdir(exist_ok=True)
    (work / "inner.cmd").write_text("@echo off\r\nping -t 127.0.0.1\r\n", newline="")

    # `^` is special to SendKeys, so it is written {^}.
    direct = "{^}cmd /c inner.cmd"
    nested = "{^}" + args.nu + " -c '{^}cmd /c inner.cmd'"
    plans = [
        (f"{host}_{label}", host, keys, after)
        for host in ("wt", "conhost")
        for label, keys, after in (
            ("direct_answer", direct, "answer"),
            ("nested_answer", nested, "answer"),
            ("nested_kill", nested, "kill"),
        )
    ]

    results = []
    for name, host, keys, after in plans:
        print(f"running {name}", flush=True)
        try:
            result = run(name, host, keys, after, args, work, out_dir)
        except Exception:
            traceback.print_exc()
            result = {"name": name, "line": keys, "root": [host], "checkpoints": [], "crashed": True}
        results.append(result)
        print(json.dumps({k: v for k, v in result.items() if k != "checkpoints"}, default=str), flush=True)
        (out_dir / "results.json").write_text(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
