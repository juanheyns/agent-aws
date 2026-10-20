import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
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

    def test_round3_all_interpreter_site_packages_are_protected(self):
        protected = agent.protected_paths()
        for name in agent.site.getsitepackages():
            for path in (Path(name), Path(name).resolve()):
                with self.subTest(path=path):
                    self.assertTrue(any(root == path or root in path.parents for root in protected))

    def test_round3_site_packages_outside_prefix_and_symlink_target(self):
        external = self.home / "external-site"
        external.mkdir()
        link = self.home / "site-link"
        link.symlink_to(external, target_is_directory=True)
        with mock.patch.object(agent.site, "getsitepackages", return_value=[str(link)]):
            protected = agent.protected_paths()
        self.assertIn(link, protected)
        self.assertIn(external, protected)

    def test_issue4_script_python_shebangs(self):
        cases = {
            b"#!/opt/x/bin/python3.13\n": "/opt/x/bin/python3.13",
            b"#!/venv/bin/python -sE\n": "/venv/bin/python",
            b"#!/usr/bin/env -S python3 -I\n": agent.shutil.which(
                "python3", path=agent.executable_path()),
            b"#!/bin/sh\nexec aws\n": None,
            b"\xcf\xfa\xed\xfe frozen binary": None,
        }
        for content, expected in cases.items():
            with self.subTest(content=content):
                script = self.home / "aws"
                script.write_bytes(content)
                self.assertEqual(agent.script_python(script), expected)
        self.assertIsNone(agent.script_python(self.home / "missing"))

    def test_issue4_python_paths_fail_closed(self):
        for python in ("false", str(self.home / "missing-python")):
            with self.subTest(python=python), self.assertRaises(SystemExit):
                agent.python_paths(shutil.which(python) or python)

    def run_until_setup_fails(self, cfg, calls, **patches):
        """Run cmd_run with fakes; every temp dir it makes goes into a test-owned root."""
        root = self.home / "tmp-root"
        root.mkdir()
        real_mkdtemp = tempfile.mkdtemp
        self.path.write_text(json.dumps(cfg))

        def record(name, value):
            def fake(*args, **kwargs):
                calls.append(name)
                if isinstance(value, BaseException):
                    raise value
                return value() if callable(value) else value
            return fake

        fakes = {
            "check_sandbox_tool": None,
            "resolve_aws_cli": "/fake/aws",
            "find_sso_tokens": {"https://example.invalid/start": "FAKE-NOT-A-TOKEN"},
            "mint_role_creds": {"accessKeyId": "FAKE-KEY", "secretAccessKey": "FAKE-SECRET",
                                "sessionToken": "FAKE-SESSION"},
            "protected_paths": set,
            **patches,
        }
        with mock.patch.multiple(agent, HOME=self.home, AGENT_DIR=self.home / ".agent-aws",
                                 **{name: mock.Mock(side_effect=record(name, value))
                                    for name, value in fakes.items()}), \
             mock.patch.object(agent.subprocess, "run", side_effect=SystemExit(3)), \
             mock.patch.object(agent.tempfile, "mkdtemp",
                               side_effect=lambda **kw: real_mkdtemp(prefix=kw["prefix"], dir=root)), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            agent.cmd_run(argparse.Namespace(cmd=["--", "/bin/true"], profile=None))
        return root

    def test_round4_probe_failure_before_token_use_and_no_temp_dir_left(self):
        # Review round 1, finding 1: the interpreter probe in protected_paths()
        # can die(). It must run before any SSO token is read or handed to
        # `aws`, and the run must leave nothing in the temp root.
        calls = []
        root = self.run_until_setup_fails(
            config(), calls, protected_paths=lambda: agent.die("probe failed"))
        self.assertEqual([c for c in calls if c != "check_sandbox_tool"],
                         ["resolve_aws_cli", "protected_paths"])
        self.assertEqual(list(root.iterdir()), [], "temp dir left after probe failure")

    def test_round4_mint_failure_leaves_no_temp_dir(self):
        cfg = config()
        cfg["profiles"]["second"] = dict(cfg["profiles"]["test"], account_id="222222222222")
        creds = {"accessKeyId": "K", "secretAccessKey": "S", "sessionToken": "T"}
        minted = iter([creds, SystemExit(1)])

        def mint():
            value = next(minted)
            if isinstance(value, BaseException):
                raise value
            return value
        calls = []
        root = self.run_until_setup_fails(cfg, calls, mint_role_creds=mint)
        self.assertEqual(calls.count("mint_role_creds"), 2)
        self.assertEqual(list(root.iterdir()), [], "temp dir left after mint failure")

    def test_round4_probe_runs_before_tokens_and_mint(self):
        calls = []
        root = self.run_until_setup_fails(config(), calls)
        self.assertEqual([c for c in calls if c != "check_sandbox_tool"],
                         ["resolve_aws_cli", "protected_paths", "find_sso_tokens",
                          "mint_role_creds"])
        self.assertEqual(list(root.iterdir()), [], "temp dir left after sandbox exit")

    def make_venv(self, root, version="3.9"):
        # Layout of `python3.9 -m venv`; bin/python is a symlink to the base.
        (root / "bin").mkdir(parents=True)
        site_dir = root / f"lib/python{version}/site-packages"
        site_dir.mkdir(parents=True)
        (root / "pyvenv.cfg").write_text("home = /base/bin\ninclude-system-site-packages = false\n"
                                         f"version = {version}.6\n")
        (root / "bin/python").symlink_to(sys.executable)
        return root / "bin/python", site_dir

    def protected_for_wrapper(self, python, probe_result):
        wrapper_dir = self.home / "wrapper-bin"
        wrapper_dir.mkdir(exist_ok=True)
        aws = wrapper_dir / "aws"
        aws.write_text(f"#!{python}\nimport sys\n")
        aws.chmod(0o700)
        probe = mock.Mock(return_value=probe_result)
        with mock.patch.dict(os.environ, {"PATH": str(wrapper_dir)}), \
             mock.patch.multiple(agent, HOME=self.home, python_paths=probe):
            protected = agent.protected_paths()
        probe.assert_called_once_with(str(python))
        return protected

    def test_round4_venv_root_of_wrapper_interpreter_is_protected(self):
        # Review round 1, finding 2: before 3.11, `-I -S` reports only the base
        # install for a venv interpreter. An `aws` wrapper outside the venv
        # (shebang = the venv's python) must still protect the venv.
        venv = self.home / "venvs/awscli"
        python, site_dir = self.make_venv(venv)
        protected = self.protected_for_wrapper(python, [Path("/base/prefix")])
        self.assertTrue(venv in protected, f"venv root {venv} not protected")
        planted = site_dir / "zz-evil.pth"
        self.assertTrue(any(root == planted or root in planted.parents for root in protected))
        # site.venv() also accepts pyvenv.cfg next to the executable.
        venv2 = self.home / "other/env"
        python2, _ = self.make_venv(venv2)
        (venv2 / "pyvenv.cfg").rename(venv2 / "bin/pyvenv.cfg")
        self.assertTrue(venv2 in self.protected_for_wrapper(python2, [Path("/base/prefix")]),
                        f"venv root {venv2} not protected")

    def test_round4_venv_guard_keeps_home_writable(self):
        # HOME is never protected as a venv root, but its pyvenv.cfg is.
        python, _ = self.make_venv(self.home)
        protected = self.protected_for_wrapper(python, [])
        self.assertFalse(self.home in protected, "HOME must stay writable")
        self.assertTrue(self.home / "pyvenv.cfg" in protected, "HOME/pyvenv.cfg not protected")

    def test_round4_script_python_trampoline_env_options_and_pypy(self):
        # Review round 1, finding 6.
        bindir = self.home / "pathbin"
        bindir.mkdir()
        for name in ("python3", "pypy3"):
            (bindir / name).write_text("#!/bin/sh\n")
            (bindir / name).chmod(0o700)
        on_path = str(bindir / "python3")
        # `env -i` / `-u PATH` search the libc default path, not PATH.
        default = shutil.which("python3", path=os.defpath)
        if not default:
            self.skipTest(f"no python3 in the default path {os.defpath}")
        cases = {
            b"#!/usr/bin/env -u PYTHONPATH python3\n": on_path,
            b"#!/usr/bin/env --unset=PYTHONPATH python3\n": on_path,
            b"#!/usr/bin/env --unset PYTHONPATH python3\n": on_path,
            b"#!/usr/bin/env -uPYTHONPATH python3\n": on_path,
            b"#!/usr/bin/env -S -u PYTHONHOME python3 -I\n": on_path,
            b"#!/usr/bin/env PYTHONSAFEPATH=1 python3\n": on_path,
            b"#!/usr/bin/env -- python3\n": on_path,
            b"#!/usr/bin/env -i python3\n": default,
            b"#!/usr/bin/env - python3\n": default,
            b"#!/usr/bin/env -u PATH python3\n": default,
            b"#!/usr/bin/env -i PATH=" + str(bindir).encode() + b" python3\n": on_path,
            b"#!/usr/bin/env -P " + str(bindir).encode() + b" python3\n": on_path,
            b"#!/usr/bin/env pypy3\n": str(bindir / "pypy3"),
            b"#!/opt/pypy/bin/pypy3.10 -I\n": "/opt/pypy/bin/pypy3.10",
            # pip/distlib trampoline (interpreter path > 127 bytes or with spaces).
            b"#!/bin/sh\n'''exec' \"/Users/a b/venv/bin/python\" \"$0\" \"$@\"\n' '''\n":
                "/Users/a b/venv/bin/python",
            b"#!/bin/sh\n'''exec' /long/venv/bin/python3 -E \"$0\" \"$@\"\n' '''\n":
                "/long/venv/bin/python3",
            b"#!/usr/bin/env bash\nexec ~/.asdf/shims/aws \"$@\"\n": None,
            b"#!/bin/sh\nexec aws\n": None,
        }
        warned = (
            b"#!python3\n",  # relative: the kernel resolves it against the cwd
            b"#!/usr/bin/env -u python3\n",
            b"#!/usr/bin/env python3.99\n",  # not on PATH
            b"#!/usr/bin/env PATH=/nonexistent python3\n",
            b"#!/bin/sh\n'''exec' \"/unbalanced/python \"$0\"\n",
        )
        script = self.home / "aws"
        with mock.patch.dict(os.environ, {"PATH": str(bindir)}):
            for content, expected in cases.items():
                with self.subTest(content=content):
                    script.write_bytes(content)
                    error = io.StringIO()
                    with contextlib.redirect_stderr(error):
                        self.assertEqual(agent.script_python(script), expected)
                    self.assertEqual(error.getvalue(), "")
            for content in warned:
                with self.subTest(content=content):
                    script.write_bytes(content)
                    error = io.StringIO()
                    with contextlib.redirect_stderr(error):
                        self.assertIsNone(agent.script_python(script))
                    self.assertIn("cannot follow the Python interpreter", error.getvalue())


if __name__ == "__main__":
    unittest.main()
