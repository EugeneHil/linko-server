import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard import decide, main  # noqa: E402

GUARD = str(Path(__file__).resolve().parent / "guard.py")
SYSTEM_PYTHON = "/usr/bin/python3"


def E(tool, **inp):
    return {"tool_name": tool, "tool_input": inp, "cwd": "/tmp"}


class GuardTests(unittest.TestCase):
    def test_blocks_reading_env(self):
        self.assertIsNotNone(decide(E("Read", file_path="/r/api/.env"), "feature/x"))

    def test_blocks_editing_env_local(self):
        self.assertIsNotNone(decide(E("Edit", file_path="/r/.env.local"), "feature/x"))

    def test_blocks_writing_pem(self):
        self.assertIsNotNone(decide(E("Write", file_path="/r/certs/server.pem"), "feature/x"))

    def test_blocks_config_local(self):
        self.assertIsNotNone(decide(E("Read", file_path="/r/config.local.json"), "feature/x"))

    def test_allows_env_example(self):
        self.assertIsNone(decide(E("Read", file_path="/r/.env.example"), "feature/x"))

    def test_allows_config_example(self):
        self.assertIsNone(decide(E("Read", file_path="/r/config.example.json"), "feature/x"))

    def test_allows_normal_source(self):
        self.assertIsNone(decide(E("Edit", file_path="/r/src/Engine.cpp"), "feature/x"))

    def test_blocks_cat_secret_in_bash(self):
        self.assertIsNotNone(decide(E("Bash", command="cat ~/.ssh/id.key"), "feature/x"))

    def test_blocks_commit_on_develop(self):
        self.assertIsNotNone(decide(E("Bash", command="git commit -m 'x'"), "develop"))

    def test_allows_commit_on_feature(self):
        self.assertIsNone(decide(E("Bash", command="git commit -m 'feat: x'"), "feature/LNK-1-x"))

    def test_blocks_plain_push_from_main(self):
        self.assertIsNotNone(decide(E("Bash", command="git push"), "main"))

    def test_blocks_push_refspec_to_protected(self):
        for c in ["git push origin HEAD:main", "git push -u origin develop", "git push origin main"]:
            self.assertIsNotNone(decide(E("Bash", command=c), "feature/x"), c)

    def test_allows_push_feature(self):
        self.assertIsNone(
            decide(E("Bash", command="git push -u origin feature/LNK-1-x"), "feature/LNK-1-x")
        )

    def test_blocks_force_push(self):
        self.assertIsNotNone(decide(E("Bash", command="git push --force-with-lease"), "feature/x"))

    def test_blocks_no_verify(self):
        self.assertIsNotNone(decide(E("Bash", command="git commit --no-verify -m x"), "feature/x"))

    def test_blocks_push_in_compound_command(self):
        self.assertIsNotNone(decide(E("Bash", command="cd repo && git push origin main"), "feature/x"))

    def test_unrelated_tool_allowed(self):
        self.assertIsNone(decide(E("Grep", pattern="TODO"), "develop"))

    def test_malformed_input_fails_closed(self):
        with mock.patch("sys.stdin", io.StringIO("not json")), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(), 2)

    def test_blocks_p8_and_mobileprovision(self):
        for p in ["/r/AuthKey_ABC123.p8", "/r/dev.mobileprovision", "/r/Profiles/App.MOBILEPROVISION"]:
            self.assertIsNotNone(decide(E("Read", file_path=p), "feature/x"), p)
        blocked(self, "cat AuthKey_ABC123.p8")

    def test_message_names_linko_guard(self):
        event = json.dumps(E("Read", file_path="/r/.env"))
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(event)), mock.patch("sys.stderr", err):
            self.assertEqual(main(), 2)
        self.assertTrue(err.getvalue().startswith("Blocked by linko guard:"), err.getvalue())


def blocked(case, command, branch="feature/x", **kw):
    case.assertIsNotNone(decide(E("Bash", command=command), branch, **kw), command)


def allowed(case, command, branch="feature/x", **kw):
    case.assertIsNone(decide(E("Bash", command=command), branch, **kw), command)


class SecretReadBypassTests(unittest.TestCase):
    def test_blocks_dotfile_globs(self):
        for c in ["cat .e*", "cat .en?", "cat .env*"]:
            blocked(self, c)

    def test_blocks_variable_indirection(self):
        blocked(self, "f=.env; cat $f")

    def test_blocks_glued_redirects(self):
        for c in ["cat<.env", "cat .env>/tmp/x"]:
            blocked(self, c)

    def test_blocks_command_substitution(self):
        for c in ["cat $(echo .env)", "cat `echo .env`"]:
            blocked(self, c)

    def test_blocks_python_open_of_secret(self):
        blocked(self, "python3 -c \"open('.env').read()\"")

    def test_blocks_case_variants_on_case_insensitive_fs(self):
        self.assertIsNotNone(decide(E("Read", file_path="/r/.ENV"), "feature/x"))

    def test_allows_secret_name_inside_commit_message(self):
        allowed(self, "git commit -m 'chore: ignore .env files'", "feature/x")

    def test_allows_prose_that_mentions_secret_names(self):
        for c in [
            'gh pr create --title "fix: handle .env parsing" --body "mentions .env files"',
            'echo "see the .env file docs"',
        ]:
            allowed(self, c)

    def test_still_blocks_secret_inside_interpreter_code(self):
        for c in ["node -e \"require('fs').readFileSync('.env')\"", "ruby -e 'File.read(\".env\")'"]:
            blocked(self, c)

    def test_allows_harmless_globs(self):
        for c in ["ls *", "rm *.o"]:
            allowed(self, c)


class GitBypassTests(unittest.TestCase):
    def test_blocks_dash_C_push_to_protected(self):
        blocked(self, "git -C ../linko-apple push origin main")

    def test_blocks_dash_c_option_commit_on_protected(self):
        blocked(self, "git -c user.name=x commit -m x", "develop")

    def test_blocks_hooks_bypass(self):
        blocked(self, "git -c core.hooksPath=/dev/null commit -m x")

    def test_blocks_dash_n_commit(self):
        for c in ["git commit -n -m x", "git commit -nm x"]:
            blocked(self, c)

    def test_blocks_wrapped_git(self):
        for c in [
            'bash -c "git push origin main"',
            "sh -c 'cd r && git push origin main'",
            "eval git push origin main",
            "sudo git push origin main",
            "/usr/bin/git push origin main",
            "(git push origin main)",
        ]:
            blocked(self, c)

    def test_blocks_plus_and_full_ref_pushes(self):
        for c in [
            "git push origin +main",
            "git push origin HEAD:refs/heads/main",
            "git push --mirror",
            "git push --all",
            "git push -fu origin x",
            "git push --delete origin develop",
            "git push origin :develop",
        ]:
            blocked(self, c)

    def test_blocks_push_head_from_protected_branch(self):
        blocked(self, "git push origin HEAD", "develop")

    def test_allows_dry_run_flag_on_push(self):
        allowed(self, "git push -n origin feature/LNK-1-x", "feature/LNK-1-x")

    def test_cd_into_other_repo_uses_that_repos_branch(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "cd ../linko-apple && git commit -m x"}, "cwd": "/r/linko-core"}
        lookup = lambda d: "develop" if d == "/r/linko-apple" else "feature/x"
        self.assertIsNotNone(decide(event, "feature/x", branch_lookup=lookup))

    def test_dash_C_uses_target_repos_branch(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "git -C ../linko-apple commit -m x"}, "cwd": "/r/linko-core"}
        lookup = lambda d: "develop" if d == "/r/linko-apple" else "feature/x"
        self.assertIsNotNone(decide(event, "feature/x", branch_lookup=lookup))

    def test_checkout_protected_then_commit(self):
        blocked(self, "git checkout develop && git commit -m x")


class SelfProtectionTests(unittest.TestCase):
    def test_blocks_editing_guard_and_settings(self):
        for p in ["/r/tooling/claude/guard.py", "/r/.claude/settings.json", "/r/.claude/settings.local.json"]:
            for tool in ["Edit", "Write"]:
                self.assertIsNotNone(decide(E(tool, file_path=p), "feature/x"), (tool, p))

    def test_blocks_shell_writes_to_guard_and_settings(self):
        for c in [
            "sed -i '' s/a/b/ tooling/claude/guard.py",
            "echo {} > .claude/settings.json",
            "cp /tmp/x tooling/claude/guard.py",
        ]:
            blocked(self, c)

    def test_allows_reading_guard_and_running_its_tests(self):
        self.assertIsNone(decide(E("Read", file_path="/r/tooling/claude/guard.py"), "feature/x"))
        allowed(self, "python3 -I -B -m unittest discover -s tooling/claude")


class InterpreterCompatibilityTests(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(SYSTEM_PYTHON), "no system python")
    def test_blocks_when_run_by_the_system_python(self):
        event = {"tool_name": "Read", "tool_input": {"file_path": "/r/.env"}, "cwd": "/tmp"}
        run = subprocess.run([SYSTEM_PYTHON, "-I", "-B", GUARD], input=json.dumps(event), capture_output=True, text=True)
        self.assertEqual(run.returncode, 2, run.stderr)


if __name__ == "__main__":
    unittest.main()
