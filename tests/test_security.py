import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("agent_aws", str(ROOT / "bin/agent-aws"))
spec = importlib.util.spec_from_loader(loader.name, loader)
agent = importlib.util.module_from_spec(spec)
loader.exec_module(agent)


def config(role="ReadOnlyAccess"):
    return {"default_profile": "test", "profiles": {"test": {
        "role_name": role, "account_id": "111111111111", "sso_session": "test",
        "sso_start_url": "https://example.invalid/start", "sso_region": "us-east-1",
        "default_region": "us-east-1",
    }}}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.path = self.home / "config.json"
        self.path.write_text(json.dumps(config()))
        self.path.chmod(0o600)
        patch = mock.patch.object(agent, "AGENT_CONFIG", self.path)
        patch.start()
        self.addCleanup(patch.stop)

    def test_secure_config_and_legacy_migration(self):
        self.assertEqual(agent.load_config(), config())
        self.path.write_text(json.dumps(config()["profiles"]["test"]))
        cfg = agent.load_config()
        agent.validate_roles(cfg)
        self.assertEqual(cfg["default_profile"], "default")

    def test_modes_rejected(self):
        for mode in (0o644, 0o660, 0o400, 0o700, 0o1600):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                with self.assertRaises(SystemExit):
                    agent.load_config()

    def test_wrong_owner(self):
        with mock.patch.object(agent.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(SystemExit):
                agent.load_config()

    def test_symlink_and_nonregular_rejected(self):
        target = self.home / "target"
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(SystemExit):
            agent.load_config()
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(SystemExit):
            agent.load_config()

    def test_missing_and_invalid_config(self):
        self.path.write_text("{")
        with self.assertRaises(SystemExit):
            agent.load_config()
        self.path.unlink()
        with self.assertRaises(SystemExit):
            agent.load_config()

    def test_all_roles_checked_before_tokens_or_minting(self):
        cfg = config()
        cfg["profiles"]["unused"] = {"role_name": "AWSAdministratorAccess"}
        self.path.write_text(json.dumps(cfg))
        with mock.patch.object(agent, "check_sandbox_tool"), mock.patch.object(
            agent, "find_sso_tokens"
        ) as tokens, mock.patch.object(agent, "mint_role_creds") as mint:
            with self.assertRaises(SystemExit):
                agent.cmd_run(argparse.Namespace(cmd=["--", "/bin/true"], profile="test"))
            tokens.assert_not_called()
            mint.assert_not_called()

    def test_default_allowlist_and_admin_precedence(self):
        for role in agent.DEFAULT_ALLOWED_ROLES:
            agent.validate_roles(config(role))
        for role in (None, "", "Developer", "AWSAdministratorAccess", "PowerUser", "FullAccess"):
            with self.subTest(role=role), self.assertRaises(SystemExit):
                agent.validate_roles(config(role))
        cfg = config("MyReadOnly")
        cfg["allowed_roles"] = ["MyReadOnly"]
        agent.validate_roles(cfg)
        cfg["profiles"]["test"]["role_name"] = "Admin"
        cfg["allowed_roles"].append("Admin")
        with self.assertRaises(SystemExit):
            agent.validate_roles(cfg)

    def test_malformed_and_empty_allowlist(self):
        for allowed in ("ReadOnlyAccess", None, [None], [], [""]):
            cfg = config()
            cfg["allowed_roles"] = allowed
            with self.subTest(allowed=allowed), self.assertRaises(SystemExit):
                agent.validate_roles(cfg)

    def test_init_persists_custom_role_and_secure_file(self):
        profiles = {"test": {"sso_session": "s", "sso_account_id": "111111111111",
                             "sso_role_name": "ReadOnlyAccess"}}
        sessions = {"s": {"sso_start_url": "https://example.invalid", "sso_region": "us-east-1"}}
        args = argparse.Namespace(all=False, profile=["test"], default=None, role="CustomReadOnly")
        target = self.home / "untouched"
        target.write_text("sentinel")
        self.path.unlink()
        self.path.symlink_to(target)
        with mock.patch.object(agent, "parse_aws_config", return_value=(profiles, sessions)), \
             mock.patch.object(agent, "AGENT_DIR", self.home):
            agent.cmd_init(args)
        cfg = agent.load_config()
        agent.validate_roles(cfg)
        self.assertEqual(cfg["profiles"]["test"]["role_name"], args.role)
        self.assertIn(args.role, cfg["allowed_roles"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(target.read_text(), "sentinel")

    def test_ai_agent_discovery_local_and_sso(self):
        src = {"sso_session": "s", "sso_account_id": "111111111111", "sso_role_name": "ReadOnlyAccess"}
        sessions = {"s": {"sso_start_url": "url", "sso_region": "us-east-1"}}
        with mock.patch.object(agent, "resolve_aws_cli", return_value="/trusted/aws"), \
             mock.patch.object(agent.subprocess, "run") as run:
            self.assertEqual(agent.preferred_role(src, sessions, {
                "agent": dict(src, sso_role_name="ai-agent")}, {}), "ai-agent")
            run.assert_not_called()
            self.assertEqual(agent.preferred_role(src, sessions, {}, {}), "ReadOnlyAccess")
            run.return_value = mock.Mock(returncode=0, stdout='{"roleList":[{"roleName":"ai-agent"}]}')
            self.assertEqual(agent.preferred_role(src, sessions, {}, {"url": "fake"}), "ai-agent")
            self.assertIn("list-account-roles", run.call_args.args[0])
            run.return_value = mock.Mock(returncode=1)
            with self.assertRaises(SystemExit):
                agent.preferred_role(src, sessions, {}, {"url": "fake"})

    def test_linux_missing_paths_are_private_and_existing_rc_readonly(self):
        (self.home / ".zshrc").write_text("sentinel")
        (self.home / "project").mkdir()
        (self.home / ".config").mkdir()
        (self.home / ".config/brnr").mkdir()
        with mock.patch.multiple(agent, HOME=self.home, AWS_DIR=self.home / ".aws",
                                 AGENT_DIR=self.home / ".agent-aws"):
            argv = agent.build_sandbox_argv_linux(self.home / "creds")
        joined = " ".join(argv)
        self.assertIn(f"--tmpfs {self.home}", joined)
        self.assertIn(f"--ro-bind {self.home}/.zshrc {self.home}/.zshrc", joined)
        self.assertIn(f"--bind {self.home}/project {self.home}/project", joined)
        self.assertIn(f"--ro-bind {self.home}/.config/brnr {self.home}/.config/brnr", joined)
        self.assertIn("--tmpfs /tmp", joined)
        self.assertNotIn("--unshare-net", argv)
        self.assertFalse((self.home / ".bashrc").exists())

    def test_review7_config_diagnostics(self):
        self.path.write_text("{")
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
            agent.load_config()
        self.assertIn("invalid config JSON", error.getvalue())
        self.assertNotIn("symlink", error.getvalue())
        target = self.home / "target"
        self.path.rename(target)
        self.path.symlink_to(target)
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
            agent.load_config()
        self.assertIn("must not be a symlink", error.getvalue())

    def test_review8_invalid_config_shapes(self):
        for cfg in ([], {}, {"profiles": []}, {"profiles": {"test": "invalid"}}):
            self.path.write_text(json.dumps(cfg))
            error = io.StringIO()
            with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
                agent.load_config()
            self.assertIn("must be", error.getvalue())

    def test_review4_interpreter_protection_and_formula_shebang(self):
        interpreter = self.home / "runtime/bin/python3"
        with mock.patch.object(agent.sys, "executable", str(interpreter)):
            paths = agent.protected_paths()
        self.assertIn(interpreter, paths)
        formula = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn('depends_on "python@3.14"', formula)
        self.assertIn('rewrite_shebang detected_python_shebang, "bin/agent-aws"', formula)
        self.assertIn('"#!/usr/bin/env -S python3 -I", "#!/usr/bin/env python3 -I"', formula)

    def test_review1_mint_uses_resolved_absolute_cli(self):
        with mock.patch.object(agent.subprocess, "run", return_value=mock.Mock(
                returncode=0, stdout='{"roleCredentials": {}}')) as run:
            agent.mint_role_creds("fake-token", config()["profiles"]["test"], "/trusted/aws")
        self.assertEqual(run.call_args.args[0][0], "/trusted/aws")


if __name__ == "__main__":
    unittest.main()
