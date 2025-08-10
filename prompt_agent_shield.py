import argparse
import os
import shlex
import signal
import shutil
import pexpect
import subprocess
import sys
import time
from datetime import datetime
from enum import Enum, auto

# === DEFAULT CONFIG (overridable via CLI/ENV) ===

AGENT_PROMPT = (
    "Continue working on the next ticket located in @PRDs/tickets/. "
    "Implement the ticket's requirements completely, ensuring the solution is robust and production-ready. "
    "Write at least 15 comprehensive tests in the /tests directory to verify correctness, stability, and edge cases. "
    "If the ticket involves Python code, place the tests in tests/. "
    "After implementation and successful test execution, move the completed ticket to @PRDs/tickets/Done/. "
    "All mocked classes should be in /tests/mocks/ directory. "
    "Do not put the mocked classes in the implementation files. "
    "Confirm that all tests from /tests/ pass before committing the code. "
    "Commit the implementation and tests together."
)


DEFAULT_PROMPT = (
    os.environ.get(
        "CURSOR_PROMPT",
        AGENT_PROMPT,
    )
)
DEFAULT_CURSOR_AGENT_CMD = os.environ.get("CURSOR_AGENT_CMD", "cursor-agent")
DEFAULT_PYTEST_CMD = os.environ.get("PYTEST_CMD", "pytest tests/ -s -vv")
DEFAULT_COMMIT_MESSAGE = os.environ.get("COMMIT_MESSAGE", "Automated commit from script")
DEFAULT_STARTUP_TIMEOUT_S = int(os.environ.get("CURSOR_AGENT_STARTUP_TIMEOUT_S", "60"))
DEFAULT_IDLE_SECONDS = int(os.environ.get("CURSOR_AGENT_IDLE_SECONDS", "8"))
DEFAULT_CYCLE_SLEEP_S = float(os.environ.get("CURSOR_AGENT_CYCLE_SLEEP_S", "2"))
DEFAULT_CYCLES = int(os.environ.get("CURSOR_AGENT_CYCLES", "0"))  # 0 = infinite
DEFAULT_OVERALL_GEN_TIMEOUT_S = int(os.environ.get("CURSOR_AGENT_GEN_TIMEOUT_S", "1800"))
DEFAULT_MAX_PROMPT_CHARS = int(os.environ.get("CURSOR_AGENT_MAX_PROMPT_CHARS", "12000"))

def run_cmd(cmd, check=True, capture_output=False):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)

def drain_output_until_idle(
    child: pexpect.spawn,
    idle_seconds: int,
    overall_timeout_s: int,
    on_line: "callable | None" = None,
) -> None:
    """Stream child output until there is no output for `idle_seconds`.

    Also abort if `overall_timeout_s` elapses to avoid infinite waits.
    """
    last_activity = time.time()
    deadline = last_activity + overall_timeout_s
    while True:
        if time.time() > deadline:
            print("⚠️ Reached overall generation timeout; proceeding.")
            break
        try:
            line = child.readline().rstrip("\n")
        except pexpect.TIMEOUT:
            # No new line; check idle
            if time.time() - last_activity >= idle_seconds:
                break
            continue
        except pexpect.EOF:
            print("⚠️ cursor-agent terminated (EOF).")
            break
        if line is None:
            # pexpect can return None on timeout in some cases
            if time.time() - last_activity >= idle_seconds:
                break
            continue
        if line.strip():
            print(line)
            if on_line is not None:
                try:
                    on_line(line)
                except Exception as _e:
                    # Non-fatal handler failure
                    pass
        last_activity = time.time()

def run_pytest(pytest_cmd: str) -> tuple[bool, str, int]:
    """Run pytest and return (passed, combined_output, returncode)."""
    cmd_list = shlex.split(pytest_cmd)
    print(f"$ {' '.join(cmd_list)}")
    completed = subprocess.run(cmd_list, check=False, capture_output=True, text=True)
    combined = (completed.stdout or "")
    if completed.stderr:
        combined += ("\n" if combined else "") + completed.stderr
    return completed.returncode == 0, combined, completed.returncode

def git_has_changes():
    status = run_cmd(["git", "status", "--porcelain"], capture_output=True)
    return bool(status.stdout.strip())

def git_has_new_commit():
    result = run_cmd(["git", "status", "-sb"], capture_output=True)
    return "[ahead" in result.stdout

def git_commit_and_push(commit_message: str):
    run_cmd(["git", "add", "-A"], check=True)
    # Commit may fail if there are no changes staged; handle gracefully
    commit_result = run_cmd(["git", "commit", "-m", commit_message], check=False)
    if commit_result.returncode != 0:
        print("ℹ️ Nothing to commit or commit failed; attempting push if there are local commits ahead.")
    run_cmd(["git", "push"], check=False)

def git_push_only():
    run_cmd(["git", "push"], check=False)


def ensure_command_available(command_name: str) -> str:
    """Return absolute path to `command_name` or raise SystemExit if not found."""
    resolved = shutil.which(command_name)
    if not resolved:
        print(f"❌ Required command not found on PATH: {command_name}")
        sys.exit(2)
    return resolved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Continuous cursor-agent driver")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help="Prompt to send to cursor-agent each cycle")
    parser.add_argument("--cursor-agent-cmd", default=DEFAULT_CURSOR_AGENT_CMD, help="cursor-agent executable to run")
    parser.add_argument("--pytest", dest="pytest_cmd", default=DEFAULT_PYTEST_CMD, help="Pytest command to run")
    parser.add_argument("--commit-message", default=DEFAULT_COMMIT_MESSAGE, help="Git commit message when tests pass")
    parser.add_argument("--startup-timeout", type=int, default=DEFAULT_STARTUP_TIMEOUT_S, help="Seconds to wait for cursor-agent to become ready")
    parser.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE_SECONDS, help="Idle seconds to consider generation finished")
    parser.add_argument("--gen-timeout", type=int, default=DEFAULT_OVERALL_GEN_TIMEOUT_S, help="Overall generation timeout per cycle in seconds")
    parser.add_argument("--cycle-sleep", type=float, default=DEFAULT_CYCLE_SLEEP_S, help="Seconds to sleep between cycles")
    parser.add_argument("--cycles", type=int, default=DEFAULT_CYCLES, help="Number of cycles to run (0 = infinite)")
    parser.add_argument("--log-raw", action="store_true", help="Also tee raw child output to stdout")
    parser.add_argument("--slash-mode", action="store_true", help="Send '/' before the prompt to focus command input")
    parser.add_argument("--enter-twice", action="store_true", help="Press Enter twice after sending the prompt")
    parser.add_argument("--max-prompt-chars", type=int, default=DEFAULT_MAX_PROMPT_CHARS, help="Max characters from logs to include in failure prompt")
    parser.add_argument("--send-initial-prompt", action="store_true", help="Send the base prompt once before the first pytest run")
    return parser.parse_args()


def wait_for_ready(child: pexpect.spawn, timeout_s: int, on_line: "callable | None" = None) -> None:
    """Wait until cursor-agent shows a ready prompt or UI. Best-effort."""
    patterns = [
        r"→",  # arrow prompt commonly used
        r"for commands",  # UI hint line
        r"Claude",  # model banner line
        r"cursor-agent",  # any mention
    ]
    # Use a polling read with timeout to avoid relying on specific prompt
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            line = child.readline().rstrip("\n")
        except pexpect.TIMEOUT:
            # Try nudging with a newline to get a prompt
            child.sendline("")
            continue
        except pexpect.EOF:
            print("❌ cursor-agent exited during startup.")
            sys.exit(3)
        if not line:
            continue
        print(line)
        if on_line is not None:
            try:
                on_line(line)
            except Exception:
                pass
        if any(pat in line for pat in patterns):
            # Give it a brief moment and then assume ready
            time.sleep(0.2)
            return
    print("⚠️ Startup wait elapsed without clear ready signal; proceeding optimistically.")


def send_shift_tab(child: pexpect.spawn) -> None:
    # Shift+Tab in most terminals is ESC [ Z
    child.send("\x1b[Z")


def make_line_handler(child: pexpect.spawn, auto_allow_commands: bool):
    auto_allowed = {"sent": False}

    def handle(line: str) -> None:
        if not auto_allow_commands or auto_allowed["sent"]:
            return
        # Heuristics to detect allowlist prompt
        if (
            "Run this command?" in line
            or "Not in allowlist:" in line
            or "Auto-run all commands (shift+tab)" in line
            or "Add Shell(" in line
        ):
            print("↪️ Detected allowlist prompt — sending Shift+Tab to enable auto-run...")
            try:
                send_shift_tab(child)
                auto_allowed["sent"] = True
            except Exception:
                pass

    return handle


def send_prompt(child: pexpect.spawn, prompt_text: str, use_slash: bool, enter_twice: bool) -> None:
    """Best-effort send of a multi-line prompt to the TUI and submit it.

    We try to focus the command input by sending '/' first, then type the prompt, then press Enter.
    """
    print("→ Preparing to send prompt...")
    try:
        # Nudge terminal to ensure input focus somewhere sensible
        child.send("\x1b")  # ESC
        time.sleep(0.05)
        if use_slash:
            print("→ Sending '/' to focus command input...")
            child.send("/")
            time.sleep(0.05)

        # Clear potential residual input line (Ctrl-U clears to line start in many shells/TUIs)
        child.sendcontrol("u")
        time.sleep(0.02)

        print("→ Typing prompt (length: {} chars)...".format(len(prompt_text)))
        child.send(prompt_text)
        time.sleep(0.05)

        print("→ Submitting prompt (Enter)...")
        child.sendcontrol("m")  # Enter
        if enter_twice:
            time.sleep(0.05)
            child.sendcontrol("m")
    except Exception as e:
        print(f"⚠️ Failed to send prompt cleanly: {e}. Falling back to simple sendline().")
        child.sendline(prompt_text)
        child.sendcontrol("m")


def truncate_text(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    # Keep the tail where the most relevant errors usually are
    return "…(truncated)\n" + text[-max_chars:]


def build_failure_prompt(pytest_cmd: str, returncode: int, combined_output: str, max_chars: int) -> str:
    header = (
        "Tests failed. Please analyze the pytest output below and fix the code.\n"
        "- Do not disable tests; modify implementation to satisfy them.\n"
        "- After applying edits, save all files.\n"
        f"Command: {pytest_cmd}\nReturn code: {returncode}\nTimestamp: {datetime.now()}\n"
        "Pytest output (possibly truncated):\n\n"
    )
    body = truncate_text(combined_output, max_chars)
    return header + body

def main():
    args = parse_args()
    print("🚀 Starting continuous cursor-agent session...")

    # Ensure cursor-agent binary is available
    resolved_cmd = ensure_command_available(args.cursor_agent_cmd)

    # Spawn child
    child = pexpect.spawn(resolved_cmd, encoding="utf-8", timeout=10, maxread=4096, searchwindowsize=256)
    if args.log_raw:
        # Mirror raw output for easier troubleshooting
        child.logfile = sys.stdout

    # Handle Ctrl-C gracefully by terminating child
    def _handle_sigint(signum, frame):
        print("\n🛑 Interrupt received; terminating cursor-agent and exiting...")
        try:
            child.sendcontrol("c")
            child.terminate(force=True)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    # Wait for initial readiness (best-effort)
    print("Waiting for cursor-agent to become ready...")
    # Line handler to auto-approve allowlist prompts
    line_handler = make_line_handler(child, auto_allow_commands=True)

    wait_for_ready(child, timeout_s=args.startup_timeout, on_line=line_handler)

    cycle_index = 0
    while True:
        cycle_index += 1
        if args.cycles and cycle_index > args.cycles:
            print("✅ Reached requested number of cycles; exiting.")
            break

        print(f"\n=== Prompt cycle {cycle_index} started at {datetime.now()} ===")

        # Send prompt
        send_prompt(child, args.prompt, use_slash=args.slash_mode, enter_twice=args.enter_twice)

        # Drain output until idle
        print("Waiting for generation to go idle...")
        drain_output_until_idle(
            child,
            idle_seconds=args.idle_seconds,
            overall_timeout_s=args.gen_timeout,
            on_line=line_handler,
        )

        # Run pytest
        # print("Running pytest...")
        # passed, combined_output, rc = run_pytest(args.pytest_cmd)
        # while not passed:
        #     print("❌ Tests failed — sending logs to agent to fix...")
        #     failure_prompt = build_failure_prompt(
        #         args.pytest_cmd, rc, combined_output, args.max_prompt_chars
        #     )
        #     send_prompt(child, failure_prompt, use_slash=args.slash_mode, enter_twice=args.enter_twice)
        #     print("Waiting for agent response to failure prompt...")
        #     drain_output_until_idle(
        #         child,
        #         idle_seconds=args.idle_seconds,
        #         overall_timeout_s=args.gen_timeout,
        #         on_line=line_handler,
        #     )
        #     print(f"=== Prompt cycle {cycle_index} ended after failure handling at {datetime.now()} ===\n")
        #     time.sleep(args.cycle_sleep)
        #     passed, combined_output, rc = run_pytest(args.pytest_cmd)

        if git_has_changes():
            print("📝 Changes detected — committing and pushing.")
            git_commit_and_push(args.commit_message)
        elif git_has_new_commit():
            print("⬆️ Pushing existing commit.")
            git_push_only()
        else:
            print("ℹ️ No changes to commit or push.")

        print(f"=== Prompt cycle {cycle_index} ended at {datetime.now()} ===\n")
        time.sleep(args.cycle_sleep)  # short pause before next iteration
        

if __name__ == "__main__":
    try:
        main()
    except (pexpect.EOF, pexpect.TIMEOUT) as e:
        print(f"❌ Cursor-agent session error: {e}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        sys.exit(1)
