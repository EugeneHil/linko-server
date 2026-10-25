"""Claude Code PreToolUse guard: blocks access to secrets and unsafe git operations.

Exit code 2 blocks the tool call (reason on stderr); 0 allows it. Any internal
error fails closed. Must run on the stock macOS Python (3.9), hence the
`from __future__ import annotations`.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Callable

PROTECTED_BRANCHES = {"main", "develop"}
SECRET_GLOBS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.p8",
    "*.cer",
    "*.mobileprovision",
    "config.local.json",
]
ALLOWED_NAMES = {".env.example"}
FILE_TOOLS = {"Read", "Edit", "Write", "NotebookEdit"}
WRITE_TOOLS = {"Edit", "Write", "NotebookEdit"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "env", "command", "nohup", "time", "exec", "builtin"}
PUNCT = "();<>|&`"
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WORD = re.compile(r"[\w.*?\[\]/~@%+-]+")
INTERPRETERS = {"node", "ruby", "perl", "php", "deno", "bun", "lua", "osascript"}
SECRET_GLOB_SAMPLES = (".env", ".env.local")
GUARD_FILE = re.compile(r"(?:^|/)(?:tooling/claude/guard\.py|\.claude/settings(?:\.local)?\.json)$")
SHELL_WRITE_TO_GUARD = re.compile(
    r"(?:\b(?:sed|tee|cp|mv|rm|ln|chmod|truncate|perl|ed|dd|install|awk)\b[^;&|\n]*|>>?\s*)"
    r"\S*(?:tooling/claude/guard\.py|\.claude/settings(?:\.local)?\.json)",
    re.IGNORECASE,
)
MAX_DEPTH = 4

BranchLookup = Callable[[str], "str | None"]


def is_secret_path(path: str) -> bool:
    name = os.path.basename(path.rstrip("/")).lower()
    if name in ALLOWED_NAMES:
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in SECRET_GLOBS)


def is_secret_glob(name: str) -> bool:
    """A dotfile glob such as `.e*` that the shell would expand to a secret name."""
    name = name.lower()
    if not name.startswith(".") or not any(c in name for c in "*?["):
        return False
    return any(fnmatch.fnmatchcase(sample, name) for sample in SECRET_GLOB_SAMPLES)


def is_interpreter(command: str) -> bool:
    return command.startswith("python") or command in INTERPRETERS


def secret_reason(token: str, scan_words: bool) -> str | None:
    candidates = WORD.findall(token) if scan_words else [token]
    for candidate in candidates:
        name = os.path.basename(candidate.rstrip("/"))
        if is_secret_path(name) or is_secret_glob(name):
            return f"access to secret file '{candidate}' is forbidden"
    return None


def normalize_newlines(command: str) -> str:
    """Turn unquoted newlines into `;` so they separate commands."""
    out, quote, escaped = [], None, False
    for ch in command:
        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\" and quote != "'":
            out.append(ch)
            escaped = True
        elif quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            out.append(ch)
            quote = ch
        else:
            out.append(";" if ch == "\n" else ch)
    return "".join(out)


def split_segments(command: str) -> list[list[str]]:
    command = normalize_newlines(command)
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=PUNCT)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:  # unbalanced quotes: approximate, still scanning every word
        tokens = []
        for part in re.split(r"(&&|\|\||[;|&()`<>])", command):
            tokens.extend([part] if part and all(c in PUNCT for c in part) else part.split())
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and all(c in PUNCT for c in token):
            if segments[-1]:
                segments.append([])
        else:
            segments[-1].append(token)
    return [s for s in segments if s]


def strip_wrappers(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens):
        if ASSIGNMENT.match(tokens[i]):
            i += 1
        elif os.path.basename(tokens[i]) in WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
        else:
            break
    return tokens[i:]


def split_git(args: list[str]) -> tuple[list[str], str | None, list[str]]:
    """Return (-c configs, -C directory, remaining args starting at the subcommand)."""
    configs: list[str] = []
    repo_dir = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-C" and i + 1 < len(args):
            repo_dir = args[i + 1]
            i += 2
        elif arg == "-c" and i + 1 < len(args):
            configs.append(args[i + 1])
            i += 2
        elif arg in ("--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            break
    return configs, repo_dir, args[i:]


def check_git(args: list[str], ctx: dict) -> str | None:
    configs, repo_dir, rest = split_git(args)
    if any(c.lower().startswith("core.hookspath") for c in configs):
        return "overriding core.hooksPath is forbidden: hooks must run"
    if repo_dir:
        ctx["dir"] = os.path.normpath(os.path.join(ctx["dir"], os.path.expanduser(repo_dir)))
        ctx["branch"] = ctx["lookup"](ctx["dir"])
    if not rest:
        return None
    sub, sargs = rest[0], rest[1:]
    branch = ctx["branch"]
    protected = branch in PROTECTED_BRANCHES
    if "--no-verify" in sargs:
        return "git --no-verify is forbidden: hooks must run"
    if sub == "commit":
        if any(re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", a) for a in sargs):
            return "git commit -n skips hooks and is forbidden"
        if protected:
            return f"committing on protected branch '{branch}' is forbidden; use a feature branch"
    if sub == "push":
        flags = [a for a in sargs if a.startswith("-")]
        positional = [a for a in sargs if not a.startswith("-")]
        if any(a.startswith("--force") or re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", a) for a in flags):
            return "force push is forbidden"
        if "--mirror" in flags or "--all" in flags:
            return "push --mirror/--all is forbidden"
        refs = positional[1:]
        for ref in refs:
            target = ref.lstrip("+").split(":")[-1].removeprefix("refs/heads/")
            if target in PROTECTED_BRANCHES or (protected and target == "HEAD"):
                return f"pushing to protected branch '{target}' is forbidden; open a PR"
        if protected and not refs:
            return f"pushing from protected branch '{branch}' is forbidden; open a PR"
    if sub in ("checkout", "switch"):
        names = [a for a in sargs if not a.startswith("-")]
        if sargs and sargs[0] in ("-b", "-B", "-c", "-C", "--create") and len(sargs) > 1:
            ctx["branch"] = sargs[1]
        elif names and "--" not in sargs:
            ctx["branch"] = names[0]
    return None


def check_segment(tokens: list[str], ctx: dict) -> str | None:
    core = strip_wrappers(tokens)
    command = os.path.basename(core[0]) if core else ""
    is_git = command == "git"
    for token in tokens:
        # Prose arguments (PR titles, echo text) may mention secret names; only code is word-scanned.
        scan_words = not is_git and (is_interpreter(command) or not re.search(r"\s", token))
        reason = secret_reason(token, scan_words)
        if reason:
            return reason
    if not core:
        return None
    if command == "cd" and len(core) > 1:
        ctx["dir"] = os.path.normpath(os.path.join(ctx["dir"], os.path.expanduser(core[1])))
        ctx["branch"] = ctx["lookup"](ctx["dir"])
        return None
    if command in SHELLS:
        for i, token in enumerate(core[1:], start=1):
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", token) and i + 1 < len(core):
                return check_command(core[i + 1], ctx)
        return None
    if command == "eval":
        return check_command(" ".join(core[1:]), ctx)
    if is_git:
        return check_git(core[1:], ctx)
    return None


def check_command(command: str, ctx: dict) -> str | None:
    ctx["depth"] = ctx.get("depth", 0) + 1
    try:
        if ctx["depth"] > MAX_DEPTH:
            return "shell command nested too deeply"
        for tokens in split_segments(command):
            reason = check_segment(tokens, ctx)
            if reason:
                return reason
        return None
    finally:
        ctx["depth"] -= 1


def decide(event: dict, current_branch: str | None, branch_lookup: BranchLookup | None = None) -> str | None:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if path and is_secret_path(path):
            return f"access to secret file '{path}' is forbidden"
        if path and tool in WRITE_TOOLS and GUARD_FILE.search(path.replace("\\", "/")):
            return f"'{path}' configures the guard itself; edit it by hand, not through the agent"
        return None
    if tool == "Bash":
        command = tool_input.get("command", "")
        if SHELL_WRITE_TO_GUARD.search(command):
            return "writing to the guard or its settings through the shell is forbidden"
        ctx = {
            "branch": current_branch,
            "dir": event.get("cwd") or os.getcwd(),
            "lookup": branch_lookup or current_branch_in,
        }
        return check_command(command, ctx)
    return None


def current_branch_in(cwd: str | None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd or None,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def main() -> int:
    try:
        event = json.load(sys.stdin)
        reason = decide(event, current_branch_in(event.get("cwd")))
    except Exception as exc:  # fail closed
        reason = f"guard error: {exc}"
    if reason:
        print(f"Blocked by linko guard: {reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
