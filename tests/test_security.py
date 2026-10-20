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

# Issue #6 resolvers, kept before setUpModule replaces them.
git_config_paths = getattr(agent, "git_config_paths", None)
ssh_config_paths = getattr(agent, "ssh_config_paths", None)
# Issue #8 resolver.
agent_config_paths = getattr(agent, "agent_config_paths", None)
HAS_TOMLLIB = importlib.util.find_spec("tomllib") is not None


def setUpModule():
    # Tests that call protected_paths() with the real HOME must not read the
    # developer's real git, ssh or agent configuration.
    for name in ("git_config_paths", "ssh_config_paths", "agent_config_paths"):
        patcher = mock.patch.object(agent, name, return_value=set(), create=True)
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


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

    def protected_for_path_exe(self, home, name, target):
        # PATH holds `name -> target`; target is a non-Python stub.
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\n")
        target.chmod(0o700)
        path_dir = self.home / f"path-{name}-{len(list(self.home.iterdir()))}"
        path_dir.mkdir()
        (path_dir / name).symlink_to(target)
        with mock.patch.dict(os.environ, {"PATH": str(path_dir)}), \
             mock.patch.multiple(agent, HOME=home, python_paths=mock.Mock(return_value=[])):
            return agent.protected_paths()

    def test_issue19_prefix_guard_keeps_home_and_ancestors_writable(self):
        # Issue #19: an `aws`/`python3` whose prefix is HOME's parent must not
        # protect that ancestor (and so all of HOME); its bin dir is protected.
        for name in ("aws", "python3"):
            with self.subTest(name=name):
                home = self.home / name / "a/home"
                home.mkdir(parents=True)
                bin_dir = home.parent / "bin"
                protected = self.protected_for_path_exe(home, name, bin_dir / name)
                self.assertFalse(home in protected, "HOME must stay writable")
                leaked = sorted(p for p in protected if p in home.parents and self.home in p.parents)
                self.assertEqual(leaked, [], f"HOME ancestors protected via the {name} prefix")
                self.assertTrue(bin_dir in protected, f"{bin_dir} not protected (fallback)")
                # Control: a prefix outside HOME's ancestors is still protected.
                prefix = self.home / name / "opt/cli"
                self.assertTrue(prefix in self.protected_for_path_exe(
                    home, name, prefix / "bin" / name), f"prefix {prefix} not protected")

    def test_issue19_symlinked_home_path_uses_resolved_home(self):
        # PR #21 review round 1, nit 2: HOME `<W>/link/home` with `<W>/link -> <W>/a`
        # and `aws -> <W>/a/bin/aws`: the resolved prefix `<W>/a` is HOME's parent.
        for name in ("aws", "python3"):
            with self.subTest(name=name):
                work = self.home / f"nit2-{name}"
                (work / "a/home").mkdir(parents=True)
                (work / "link").symlink_to(work / "a")
                home = work / "link/home"
                protected = self.protected_for_path_exe(home, name, work / "a/bin" / name)
                self.assertFalse(work / "a" in protected, "resolved HOME parent protected")
                self.assertFalse(work / "a/home" in protected, "resolved HOME protected")
                self.assertTrue(work / "a/bin" in protected, "bin dir not protected (fallback)")

    def test_issue19_fallback_bin_dir_home_or_ancestor_protects_only_executable(self):
        # PR #21 review round 1, nit 4: the executable sits directly in HOME's
        # parent (`<W>/b/aws`) or in HOME (`~/aws`); PATH itself is outside HOME.
        for name in ("aws", "python3"):
            for layout in ("b/aws", "c/home/aws"):
                with self.subTest(name=name, layout=layout):
                    work = self.home / f"nit4-{name}"
                    home = work / layout.split("/")[0] / "home"
                    home.mkdir(parents=True, exist_ok=True)
                    target = work / layout.replace("aws", name)
                    protected = self.protected_for_path_exe(home, name, target)
                    self.assertFalse(home in protected, "HOME must stay writable")
                    self.assertFalse(home.parent in protected, "HOME parent protected")
                    self.assertTrue(target in protected, f"{target} not protected")

    def test_issue19_python3_fallback_protects_its_own_python_paths(self):
        # PR #21 review round 1, nit 1 (option A): HOME `<W>/e/home`, PATH
        # `python3 -> <W>/e/bin/python3`. The prefix `<W>/e` is HOME's parent,
        # so it falls back to `<W>/e/bin`; the interpreter's own stdlib and
        # site-packages must still be protected (HOME and `<W>/e` must not).
        work = self.home / "nit1"
        home, prefix = work / "e/home", work / "e"
        home.mkdir(parents=True)
        stdlib = prefix / "lib/python3.x"
        user_site = home / ".local/lib/python3.x/site-packages"
        reported = [stdlib, stdlib / "site-packages", home, prefix, user_site, Path("rel")]
        for name in ("python3", "aws"):
            with self.subTest(name=name):
                target = prefix / "bin" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("#!/bin/sh\n")
                target.chmod(0o700)
                path_dir = self.home / f"nit1-path-{name}"
                path_dir.mkdir()
                (path_dir / name).symlink_to(target)
                probe = mock.Mock(return_value=reported)
                with mock.patch.dict(os.environ, {"PATH": str(path_dir)}), \
                     mock.patch.multiple(agent, HOME=home, python_paths=probe):
                    protected = agent.protected_paths()
                self.assertFalse(home in protected, "HOME must stay writable")
                self.assertFalse(prefix in protected, "HOME parent protected")
                self.assertTrue(prefix / "bin" in protected, "bin dir not protected (fallback)")
                self.assertFalse(Path("rel") in protected, "relative probe path protected")
                if name == "python3":
                    self.assertTrue(stdlib in protected, f"{stdlib} not protected")
                    self.assertTrue(stdlib / "site-packages" in protected,
                                    "site-packages not protected")
                    self.assertTrue(user_site in protected, "user site not protected")
                    probe.assert_called_once_with(target.resolve(), "python3 interpreter")
                    # The stub prints no JSON: the real probe fails closed.
                    with mock.patch.dict(os.environ, {"PATH": str(path_dir)}), \
                         mock.patch.object(agent, "HOME", home), \
                         self.assertRaises(SystemExit):
                        agent.protected_paths()
                else:
                    # A non-Python `aws` is not probed; its prefix dirs stay open.
                    probe.assert_not_called()
                    self.assertFalse(stdlib in protected, "aws prefix lib protected")

    def chain_fixture(self, name, layout):
        # Issue #23: PATH `<W>/p/<name>` -> a link in HOME -> target. HOME is
        # `<W>/hl/home` with `<W>/hl -> <W>/real`, so each link in HOME has a
        # resolved-parent and a HOME-lexical form.
        work = self.home / f"issue23-{name}-{layout}"
        (work / "real/home/d").mkdir(parents=True)
        (work / "hl").symlink_to(work / "real")
        home, real = work / "hl/home", work / "real/home"
        middle = {"home": "link", "x": "link", "subdir": "d/link", "dir": "d/cur"}[layout]
        target = real / name if layout == "home" else work / "opt/x/bin" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\n")
        target.chmod(0o700)
        if layout == "dir":
            # A directory link in the middle: `~/d/cur -> <W>/opt/x`.
            (real / middle).symlink_to(work / "opt/x")
            first = home / middle / "bin" / name
        else:
            (real / middle).symlink_to(target)
            first = home / middle
        (work / "p").mkdir()
        (work / "p" / name).symlink_to(first)
        return work, home, real, middle, target

    def test_issue23_middle_links_in_path_chain_are_protected(self):
        # PR #21 review round 2: `<W>/p/<name> -> ~/link -> ~/<name>` and
        # `-> ~/link -> <W>/opt/x/bin/<name>`; also a link in a HOME subdir
        # and a directory link in the middle. agent-aws has the same chain
        # protection (no install prefix).
        for name in ("aws", "python3", "agent-aws"):
            for layout in ("home", "x", "subdir", "dir"):
                with self.subTest(name=name, layout=layout):
                    work, home, real, middle, target = self.chain_fixture(name, layout)
                    with mock.patch.dict(os.environ, {"PATH": str(work / "p")}), \
                         mock.patch.multiple(agent, HOME=home,
                                             python_paths=mock.Mock(return_value=[])):
                        protected = agent.protected_paths()
                    self.assertTrue(real / middle in protected, f"~/{middle} (resolved parent) not protected")
                    self.assertTrue(home / middle in protected, f"~/{middle} (HOME-lexical) not protected")
                    self.assertTrue(work / "p" / name in protected, "PATH entry not protected")
                    for path in (home, real, work / "hl", work / "real", work, real / "d"):
                        self.assertFalse(path in protected, f"{path} (HOME, an ancestor or a link's dir) protected")
                    # The #19 rules for the final target still hold.
                    if name == "agent-aws":
                        continue
                    if layout == "home":
                        self.assertTrue(target in protected, "final target not protected")
                    else:
                        self.assertTrue(work / "opt/x" in protected, "prefix not protected")
                        self.assertFalse(work / "opt" in protected, "prefix parent protected")

    def home_link_fixture(self, name):
        # PR #25 review 1, finding 1: `<W>/p/<name> -> ~/d/h/opt/bin/<name>`
        # with `~/d/h -> ~`. HOME is `<W>/hl/home` with `<W>/hl -> <W>/real`.
        work = self.home / f"pr25-{name}"
        (work / "real/home/d").mkdir(parents=True)
        (work / "real/home/project").mkdir()
        (work / "hl").symlink_to(work / "real")
        home, real = work / "hl/home", work / "real/home"
        target = real / "opt/bin" / name
        target.parent.mkdir(parents=True)
        target.write_text("#!/bin/sh\n")
        target.chmod(0o700)
        (real / "d/h").symlink_to(home)
        (work / "p").mkdir()
        (work / "p" / name).symlink_to(home / "d/h/opt/bin" / name)
        return work, home, real

    def home_link_protected(self, name, command):
        work, home, real = self.home_link_fixture(name)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(home / "project")
        with mock.patch.dict(os.environ, {"PATH": str(work / "p")}), \
             mock.patch.multiple(agent, HOME=home, AWS_DIR=home / ".aws", AGENT_DIR=home / ".agent-aws",
                                 python_paths=mock.Mock(return_value=[])):
            paths = agent.command_paths(name) if command else set()
            protected = agent.protected_paths(set(), paths)
            argv = agent.linux_home_mounts(protected)
        return work, home, real, paths, protected, argv

    def test_pr25_link_to_home_on_chain_is_protected(self):
        # A link whose target is HOME (or an ancestor of HOME) was skipped, so
        # run 1 could repoint `~/d/h` and run 2 pinned another `aws`.
        for name, command in (("aws", False), ("python3", False), ("claude", True)):
            with self.subTest(name=name):
                work, home, real, paths, protected, _ = self.home_link_protected(name, command)
                self.assertTrue(real / "d/h" in protected, "~/d/h (resolved parent) not protected")
                self.assertTrue(home / "d/h" in protected, "~/d/h (HOME-lexical) not protected")
                if command:
                    self.assertTrue({real / "d/h", home / "d/h"} <= paths, "command_paths() skips ~/d/h")
                for path in (home, real, work / "hl", work / "real", work, *work.parents,
                             home / "d", real / "d"):
                    self.assertFalse(path in protected, f"{path} (HOME, an ancestor or a link's dir) protected")

    def test_pr25_linux_link_to_home_is_private_symlink(self):
        # Pure argv check (also on macOS): a protected link to HOME must not
        # be mounted from its target (that would show the real HOME, with
        # ~/.aws, at the link, and `--ro-bind HOME HOME`).
        for name, command in (("aws", False), ("claude", True)):
            with self.subTest(name=name):
                work, home, real, _, _, argv = self.home_link_protected(name, command)
                homes = {home, real, *home.parents, *real.parents}
                ro_binds = [(argv[i + 1], argv[i + 2]) for i, arg in enumerate(argv) if arg == "--ro-bind"]
                for source, destination in ro_binds:
                    self.assertNotIn(Path(source), homes, f"--ro-bind {source} {destination}")
                joined = " ".join(argv) + " "
                self.assertIn(f"--tmpfs {home}/d ", joined)
                self.assertIn(f"--symlink {home} {home}/d/h ", joined)

    @unittest.skipUnless(Path("/var").is_symlink(), "macOS /var -> private/var")
    def test_issue23_system_link_to_home_ancestor_not_protected(self):
        # `/var -> private/var` is on the chain when PATH uses the lexical
        # /var path; its target is an ancestor of HOME. The link itself may be
        # protected (PR #25 review 1: Seatbelt matches resolved paths, and
        # /var is root-owned), but never its target /private/var.
        if not str(self.home).startswith("/private/var/"):
            self.skipTest("temp dir is not below /private/var")
        home = self.home / "var-home"
        home.mkdir()
        bin_dir = self.home / "var-opt/x/bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "aws").write_text("#!/bin/sh\n")
        (bin_dir / "aws").chmod(0o700)
        with mock.patch.dict(os.environ, {"PATH": str(bin_dir)[len("/private"):]}), \
             mock.patch.multiple(agent, HOME=home, python_paths=mock.Mock(return_value=[])):
            protected = agent.protected_paths()
        self.assertFalse(Path("/private/var") in protected, "/private/var protected")
        self.assertTrue(self.home / "var-opt/x" in protected, "prefix not protected")

    def test_issue23_symlink_chain_hop_limit_fails_closed(self):
        (self.home / "a").symlink_to(self.home / "b")
        (self.home / "b").symlink_to(self.home / "a")
        (self.home / "loop").symlink_to(self.home / "a")
        with self.assertRaises(SystemExit):
            agent.symlink_chain(self.home / "loop/x")
        # Exactly SYMLINK_HOPS (40) links is accepted; 41 fails closed.
        previous = self.home / "end"
        previous.write_text("x")
        for index in range(41):
            (self.home / f"hop{index}").symlink_to(previous)
            previous = self.home / f"hop{index}"
        with mock.patch.object(agent, "HOME", self.home / "elsewhere"):
            self.assertEqual(len(agent.symlink_chain(self.home / "hop39")), 40)
            with self.assertRaises(SystemExit):
                agent.symlink_chain(self.home / "hop40")

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


class Issue6ResolverTests(unittest.TestCase):
    """Git and ssh config targets (issue #6), with a scratch HOME only."""

    def setUp(self):
        self.assertIsNotNone(git_config_paths, "git_config_paths() is missing")
        self.assertIsNotNone(ssh_config_paths, "ssh_config_paths() is missing")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        environ = {k: v for k, v in os.environ.items()
                   if not k.startswith("GIT_") and k != "XDG_CONFIG_HOME"}
        environ["HOME"] = str(self.home)
        for patcher in (mock.patch.dict(os.environ, environ, clear=True),
                        mock.patch.object(agent, "HOME", self.home)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, name, text):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def resolve(self, resolver):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            paths = resolver()
        return paths, error.getvalue()

    def assert_protected(self, paths, *names):
        for name in names:
            path = Path(name) if os.path.isabs(name) else self.home / name
            self.assertIn(path, paths, f"{path} not protected")

    def test_issue6_git_includes_include_if_and_relative_paths(self):
        self.write(".gitconfig", "[include]\n\tpath = ~/dotfiles/git/extra\n"
                   '[includeIf "gitdir:~/never-matches/"]\n\tpath = dotfiles/work\n'
                   '[includeIf "onbranch:nope"]\n\tpath = ' f"{self.home}/abs/branch\n")
        # Relative includes are relative to the including file, not to HOME.
        self.write("dotfiles/git/extra", "[include]\n\tpath = more\n")
        self.write("dotfiles/git/more", "[core]\n\thooksPath = ~/.githooks\n")
        paths, error = self.resolve(git_config_paths)
        self.assertEqual(error, "")
        self.assert_protected(paths, ".gitconfig", "dotfiles/git/extra", "dotfiles/git/more",
                              "dotfiles/work", "abs/branch", ".githooks")
        self.assertNotIn(self.home / "more", paths)

    def test_issue6_git_include_cycle_and_depth_limit(self):
        self.write(".gitconfig", "[include]\n\tpath = .gitconfig\n\tpath = chain/1\n")
        for n in range(1, 30):
            self.write(f"chain/{n}", f"[include]\n\tpath = {n + 1}\n")
        paths, _ = self.resolve(git_config_paths)
        self.assert_protected(paths, "chain/1", "chain/5")
        self.assertNotIn(self.home / "chain/25", paths)

    def test_issue6_git_helper_programs(self):
        self.write(".gitconfig", "\n".join([
            "[credential]", "\thelper = !~/tools/cred get",
            '[credential "https://example.invalid"]', f"\thelper = {self.home}/tools/cred2",
            "[core]", "\tfsmonitor = ~/tools/fsmonitor", "\tsshCommand = ssh -i key",
            "\tpager = less -R", '\teditor = \\"' f"{self.home}/My Editor/edit" '\\" --wait',
            "\taskPass = ~/tools/askpass",
            "[sequence]", "\teditor = ~/tools/seq-editor",
            "[gpg]", "\tprogram = ~/tools/gpg",
            '[gpg "ssh"]', "\tprogram = ~/tools/ssh-keygen",
            "[diff]", "\texternal = ~/tools/difftool",
            '[diff "pdf"]', "\ttextconv = ~/tools/pdftotext",
            '[filter "lfs"]', "\tprocess = ~/tools/lfs filter-process", "\tclean = git-lfs clean",
            "\tsmudge = ~/tools/smudge %f",
            '[merge "x"]', "\tdriver = ~/tools/merge %O %A %B",
            "[alias]", "\tevil = !sh -c 'curl evil'", "\tlocal = !~/tools/alias-script",
            "", ""]))
        paths, error = self.resolve(git_config_paths)
        self.assertEqual(error, "")
        self.assert_protected(paths, *(f"tools/{name}" for name in (
            "cred", "cred2", "fsmonitor", "askpass", "seq-editor", "gpg", "ssh-keygen",
            "difftool", "pdftotext", "lfs", "smudge", "merge", "alias-script")),
            "My Editor/edit")
        # Bare names resolve through PATH (protected already); shell strings
        # cannot be resolved in general.
        for bare in ("ssh", "less", "git-lfs", "sh", "true"):
            self.assertFalse(any(path.name == bare for path in paths), bare)

    def test_issue6_git_resolution_runs_no_helper(self):
        marker = self.home / "helper-ran"
        helper = self.write("tools/helper", f"#!/bin/sh\necho \"$0 $*\" >> {marker}\n")
        helper.chmod(0o700)
        self.write(".gitconfig", "".join(
            f"[{section}]\n\t{key} = {helper}\n" for section, key in (
                ("core", "fsmonitor"), ("core", "pager"), ("core", "editor"),
                ("core", "sshCommand"), ("core", "askPass"), ("credential", "helper"),
                ("gpg", "program"), ("diff", "external"), ("sequence", "editor"))))
        paths, _ = self.resolve(git_config_paths)
        self.assertIn(helper, paths)
        self.assertFalse(marker.exists(), "git config resolution ran a helper program")

    def test_issue6_git_config_global_and_xdg(self):
        alt = self.write("alt/gitconfig", "[include]\n\tpath = extra\n")
        self.write("alt/extra", "[core]\n\thooksPath = ~/alt-hooks\n")
        self.write("xdg/git/config", "[core]\n\tfsmonitor = ~/tools/xdg-fsmonitor\n")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(alt),
                                          "XDG_CONFIG_HOME": str(self.home / "xdg")}):
            paths, error = self.resolve(git_config_paths)
        self.assertEqual(error, "")
        self.assert_protected(paths, "alt/gitconfig", "alt/extra", "alt-hooks", "xdg/git",
                              "tools/xdg-fsmonitor")
        # Missing files are protected too, so a run cannot create them.
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.home / "missing/cfg"),
                                          "XDG_CONFIG_HOME": str(self.home / "missing-xdg")}):
            paths, _ = self.resolve(git_config_paths)
        self.assert_protected(paths, "missing/cfg", "missing-xdg/git")

    def test_issue6_git_missing_or_failing_warns_and_continues(self):
        self.write(".gitconfig", "[include]\n\tpath = ~/dotfiles/extra\n")
        real_which = shutil.which
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.home / "alt")}), \
             mock.patch.object(agent.shutil, "which",
                               side_effect=lambda name, **kw: None if name == "git"
                               else real_which(name, **kw)):
            paths, error = self.resolve(git_config_paths)
        self.assertIn("git not found", error)
        self.assert_protected(paths, "alt")
        bindir = self.home / "fake-git-bin"
        for body in ("exit 3", "sleep 5"):
            with self.subTest(body=body):
                self.write("fake-git-bin/git", f"#!/bin/sh\n{body}\n").chmod(0o700)
                with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}"}), \
                     mock.patch.object(agent, "GIT_TIMEOUT", 0.5):
                    paths, error = self.resolve(git_config_paths)
                self.assertIn("warning: cannot read git config", error)
                self.assert_protected(paths, ".gitconfig")

    def test_issue6_git_home_and_ancestors_never_protected(self):
        self.write(".gitconfig", "[core]\n\thooksPath = ~\n\tfsmonitor = /\n"
                   f"[include]\n\tpath = {self.home.parent}\n\tpath = ~/notes.txt/sub\n")
        self.write("notes.txt", "not a directory\n")
        paths, _ = self.resolve(git_config_paths)
        self.assertNotIn(self.home, paths)
        self.assertFalse(paths & set(self.home.parents), paths & set(self.home.parents))
        self.assertNotIn(self.home / "notes.txt/sub", paths)

    def test_issue6_ssh_includes_and_commands(self):
        self.write(".ssh/config", "\n".join([
            "# Include ~/commented-out",
            "Include config.d/*.conf ~/ssh-extra/hosts",
            'include "~/quoted dir/cfg"',
            "Include=~/missing-include",
            "Include *.inc",  # glob directly in ~/.ssh: the files only
            "Host jump",
            "  ProxyCommand exec ~/tools/proxy %h %p",
            "  LocalCommand /opt/tools/local %n",
            "  PKCS11Provider ~/lib/pkcs11.so",
            '  Match host x !exec "~/tools/match-neg %h" exec ~/tools/match',
            "Host bare",
            "  ProxyCommand nc %h %p",
            "  KnownHostsCommand none",
            ""]))
        # A relative Include in a nested file is relative to ~/.ssh too.
        self.write(".ssh/config.d/a.conf", "Include nested.cfg\nKnownHostsCommand ~/tools/khc %H\n")
        self.write(".ssh/config.d/b.conf", "Host b\n")
        self.write(".ssh/nested.cfg", "SecurityKeyProvider ~/lib/sk.so\n")
        self.write(".ssh/config.d/b.conf.unused", "ProxyCommand ~/tools/not-included\n")
        self.write(".ssh/x.inc", "ProxyCommand ~/tools/inc\n")
        self.write("ssh-extra/hosts", "Include ~/.ssh/config\n")  # cycle
        self.write("quoted dir/cfg", "Host q\n")
        paths, error = self.resolve(ssh_config_paths)
        self.assertEqual(error, "")
        self.assert_protected(
            paths, ".ssh/config", ".ssh/config.d", ".ssh/config.d/a.conf", ".ssh/config.d/b.conf",
            ".ssh/nested.cfg",
            "ssh-extra/hosts", "quoted dir/cfg", "missing-include", ".ssh/x.inc",
            "tools/proxy", "/opt/tools/local", "lib/pkcs11.so", "tools/match-neg", "tools/match",
            "tools/khc", "lib/sk.so", "tools/inc")
        for absent in ("tools/not-included", "commented-out", "nc", ".ssh/config.d/nested.cfg"):
            self.assertNotIn(self.home / absent, paths)
        # ~/.ssh itself stays writable (known_hosts); see docs for the gap.
        self.assertNotIn(self.home / ".ssh", paths)
        self.assertNotIn(self.home, paths)

    def test_review1_git_hooks_template_dir_and_more_command_keys(self):
        # PR #16 review round 1, findings 1 and 3: these values are hook
        # directories or commands that a later, unsandboxed git runs.
        self.write(".gitconfig", "\n".join([
            '[hook "lint"]', f"\tcommand = {self.home}/tools/lint-hook", "\tevent = pre-commit",
            "[init]", "\ttemplateDir = ~/.git-templates",
            '[gpg "ssh"]', "\tdefaultKeyCommand = ~/tools/keycmd",
            "[interactive]", "\tdiffFilter = ~/tools/filt --color",
            "[core]", "\talternateRefsCommand = ~/tools/altrefs",
            "[sendemail]", "\tsendmailCmd = ~/tools/sendmail -i", "\ttoCmd = ~/tools/to",
            "\tccCmd = ~/tools/cc", "\theaderCmd = ~/tools/header",
            '[trailer "sign"]', "\tcommand = ~/tools/trailer-command",
            '[trailer "ack"]', "\tcmd = ~/tools/trailer-cmd",
            '[remote "origin"]', "\turl = https://example.invalid/r.git",
            "\tuploadpack = ~/tools/upload-pack", "\treceivepack = ~/tools/receive-pack",
            "", ""]))
        paths, error = self.resolve(git_config_paths)
        self.assertEqual(error, "")
        self.assert_protected(paths, ".git-templates", *(f"tools/{name}" for name in (
            "lint-hook", "keycmd", "filt", "altrefs", "sendmail", "to", "cc", "header",
            "trailer-command", "trailer-cmd", "upload-pack", "receive-pack")))
        self.assertFalse(any("example.invalid" in str(path) for path in paths))

    def test_review1_linux_skeleton_note(self):
        # PR #16 review round 1, findings 2 and 4: on Linux every directory
        # between HOME and a target is a private skeleton, also when the
        # target is missing. The run warns about them before it starts.
        self.write(".gitconfig", "\n".join([
            "[include]", "\tpath = ~/Source/github.com/me/dotfiles/git-extra",
            '[includeIf "gitdir:~/work/"]', "\tpath = ~/work/.gitconfig",  # missing
            "[core]", "\thooksPath = ~/.config/git/hooks",
            "", ""]))
        self.write("Source/github.com/me/dotfiles/git-extra", "[user]\n\tname = x\n")
        (self.home / "Source/github.com/other").mkdir(parents=True)
        (self.home / "work").mkdir()
        self.write(".ssh/config", "Host x\n")
        with mock.patch.multiple(agent, AWS_DIR=self.home / ".aws",
                                 AGENT_DIR=self.home / ".agent-aws"):
            targets = self.resolve(git_config_paths)[0] | self.resolve(ssh_config_paths)[0]
            protected = agent.protected_paths(targets)
            argv = " ".join(agent.linux_home_mounts(protected))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                agent.linux_skeleton_note(protected, targets)
            quiet = io.StringIO()
            with contextlib.redirect_stderr(quiet):
                agent.linux_skeleton_note(protected, {self.home / ".gitconfig"})
        home = self.home
        for skeleton in ("Source", "Source/github.com", "Source/github.com/me",
                         "Source/github.com/me/dotfiles", "work"):
            self.assertIn(f"--tmpfs {home / skeleton} ", argv, skeleton)
        self.assertIn(f"--bind {home}/Source/github.com/other {home}/Source/github.com/other", argv)
        note = error.getvalue()
        self.assertIn("agent-aws: Linux: new top-level entries in these directories are lost "
                      "when the run ends (they hold protected git/ssh/agent config, "
                      "$PYTHONSTARTUP, the run's command or PATH symlinks): ", note)
        self.assertIn("~/Source, ~/Source/github.com, ~/Source/github.com/me, "
                      "~/Source/github.com/me/dotfiles, ~/work\n", note)
        # Skeletons that STARTUP_PATHS make anyway, and read-only
        # directories, are not listed.
        for name in ("~/.config", "~/.ssh", "~/.config/git"):
            self.assertNotIn(f"{name},", note)
            self.assertNotIn(f"{name}\n", note)
        self.assertEqual(quiet.getvalue(), "")



class Issue8AgentConfigTests(unittest.TestCase):
    """Programs that user-level agent config names (issue #8), scratch HOME only."""

    def setUp(self):
        self.assertIsNotNone(agent_config_paths, "agent_config_paths() is missing")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        patcher = mock.patch.object(agent, "HOME", self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    write = Issue6ResolverTests.write
    assert_protected = Issue6ResolverTests.assert_protected

    def resolve(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            paths = agent_config_paths()
        return paths, error.getvalue()

    def test_issue8_instructions_protected_and_config_files_writable(self):
        paths = {agent.HOME / path for path in agent.STARTUP_PATHS}
        self.assert_protected(paths, ".claude/CLAUDE.md", ".claude/agents", ".claude/commands",
                              ".claude/skills", ".codex/AGENTS.md", ".codex/AGENTS.override.md")
        for name in (".claude.json", ".claude", ".claude/plugins", ".claude/projects", ".codex",
                     ".codex/config.toml", ".codex/auth.json", ".codex/sessions"):
            self.assertNotIn(self.home / name, paths, name)

    def test_issue8_claude_hooks_helpers_and_mcp_servers(self):
        marker = self.home / "ran"
        self.write(".claude/settings.json", json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "~/.claude/hooks/pre.sh --flag"},
                {"type": "command", "command": f"touch {marker}"},  # bare: PATH
                {"type": "command", "command": "./relative-hook"},
                {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/p.sh'},
                {"type": "prompt", "prompt": "no command"}]}],
                "Stop": [{"hooks": [{"type": "command", "command": '"$HOME/hooks dir/stop.sh"'}]}]},
            "statusLine": {"type": "command", "command": "${HOME}/bin-x/status"},
            "apiKeyHelper": "/opt/helpers/key-helper",
        }))
        self.write(".claude/settings.local.json", json.dumps({"hooks": {"PostToolUse": [
            {"hooks": [{"type": "command", "command": f"exec {self.home}/local-hook"}]}]}}))
        self.write(".claude.json", json.dumps({
            "mcpServers": {"a": {"command": "~/My Tools/server", "args": ["--x"]},
                           "b": {"command": "npx", "args": ["-y", "pkg"]},
                           "c": {"type": "http", "url": "https://example.invalid/mcp"}},
            "projects": {"/some/project": {"mcpServers": {"p": {"command": f"{self.home}/proj-mcp"}}},
                         "/other": {"mcpServers": []}},
        }))
        paths, error = self.resolve()
        self.assertEqual(error, "")
        self.assert_protected(paths, ".claude/hooks/pre.sh", "hooks dir/stop.sh", "bin-x/status",
                              "/opt/helpers/key-helper", "local-hook", "My Tools/server", "proj-mcp")
        for absent in ("touch", "npx", "relative-hook", ".claude/hooks/p.sh", ".claude.json",
                       ".claude/settings.json", ".claude/settings.local.json"):
            self.assertNotIn(self.home / absent, paths)
        self.assertFalse(any(path.name in ("touch", "npx") for path in paths), paths)
        self.assertFalse(marker.exists(), "a configured command was executed")

    @unittest.skipUnless(HAS_TOMLLIB, "tomllib requires Python 3.11+")
    def test_issue8_codex_mcp_servers_and_notify(self):
        self.write(".codex/config.toml", "\n".join([
            'model = "fixture"',
            'notify = ["~/tools/notify", "--flag"]',
            "[mcp_servers.a]", 'command = "/opt/mcp/a"',
            "[mcp_servers.b]", 'command = "uvx"',
            "[mcp_servers.c]", 'url = "https://example.invalid/mcp"', ""]))
        paths, error = self.resolve()
        self.assertEqual(error, "")
        self.assert_protected(paths, "tools/notify", "/opt/mcp/a")
        self.assertNotIn(self.home / "uvx", paths)
        self.assertNotIn(self.home / ".codex/config.toml", paths)
        self.write(".codex/config.toml", 'notify = ["notify-send"]\n')
        self.assertEqual(self.resolve(), (set(), ""))

    def test_issue8_bad_config_warns_and_continues(self):
        self.write(".claude/settings.json", "{not json")
        self.write(".claude/settings.local.json", json.dumps({"hooks": {"Stop": [
            {"hooks": [{"type": "command", "command": "~/ok-hook"}]}]}}))
        self.write(".claude.json", "[1, 2]")  # valid JSON, unexpected shape
        self.write(".codex/config.toml", "notify = [unterminated\n")
        paths, error = self.resolve()
        self.assertIn("cannot parse", error)
        self.assertIn("settings.json", error)
        if HAS_TOMLLIB:
            self.assertIn("config.toml", error)
        self.assert_protected(paths, "ok-hook")
        # Wrong types anywhere are skipped without an error.
        codex = self.home / ".codex/config.toml"
        codex.write_text('notify = "not a list"\n') if HAS_TOMLLIB else codex.unlink()
        self.write(".claude/settings.json", json.dumps({"hooks": {"Stop": "x", "Pre": [1, {"hooks": "y"}]},
                                                        "statusLine": "z", "apiKeyHelper": 3}))
        self.write(".claude.json", json.dumps({"mcpServers": {"a": 1, "b": {"command": 2}},
                                               "projects": [1]}))
        paths, error = self.resolve()
        self.assertEqual(error, "")
        self.assertEqual(paths, {self.home / "ok-hook"})
        with mock.patch.object(agent, "tomllib", None, create=True):
            self.write(".codex/config.toml", 'notify = ["~/tools/notify"]\n')
            paths, error = self.resolve()
        self.assertIn("tomllib", error)
        self.assertEqual(paths, {self.home / "ok-hook"})

    def test_issue8_quoted_home_hook_commands(self):
        # Review round 1, finding 2: a quoted "$HOME" followed by the path.
        forms = ('"$HOME"/.claude/hooks/a.sh', '"$HOME/.claude/hooks/b.sh"',
                 "$HOME/.claude/hooks/c.sh --x", "${HOME}/.claude/hooks/f.sh",
                 '"${HOME}"/.claude/hooks/g.sh arg')
        self.write(".claude/settings.json", json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": command} for command in forms]}]}}))
        paths, error = self.resolve()
        self.assertEqual(error, "")
        self.assertEqual(paths, {self.home / f".claude/hooks/{name}.sh" for name in "abcfg"})

    def linux_argv(self, targets=frozenset()):
        with mock.patch.multiple(agent, AWS_DIR=self.home / ".aws",
                                 AGENT_DIR=self.home / ".agent-aws"):
            protected = agent.protected_paths(set(targets))
            return agent.linux_home_mounts(protected), protected

    def test_issue8_linux_codex_parent_bind(self):
        # Review round 1, finding 4: ~/.codex is bound read-write on Linux
        # (config.toml can be replaced by rename); only the existing
        # instruction files below it are read-only mounts.
        self.write(".codex/AGENTS.md", "# fixture\n")
        self.write(".codex/config.toml", 'model = "fixture"\n')
        home = self.home
        argv, _ = self.linux_argv()
        text = " ".join(argv) + " "
        codex = f"{home}/.codex"
        self.assertIn(f"--bind {codex} {codex} ", text)
        self.assertIn(f"--ro-bind {codex}/AGENTS.md {codex}/AGENTS.md ", text)
        self.assertNotIn(f"--tmpfs {codex} ", text)
        self.assertNotIn("AGENTS.override.md", text)
        self.assertNotIn(f"{codex}/config.toml", text)
        # The parent bind comes before the read-only child.
        self.assertLess(text.index(f"--bind {codex} "), text.index(f"--ro-bind {codex}/AGENTS.md"))
        # A config target below ~/.codex keeps the skeleton: a missing
        # program there must not be creatable.
        argv, protected = self.linux_argv({home / ".codex/hooks/notify.sh"})
        text = " ".join(argv) + " "
        self.assertIn(f"--tmpfs {codex} ", text)
        self.assertNotIn(f"--bind {codex} {codex} ", text)
        self.assertNotIn(home / ".codex", agent.linux_parent_binds(protected))
        # Review round 2, R2-1: a protected child that is a symlink (stow-style
        # dotfiles) keeps the skeleton. Inside a read-write bind its --ro-bind
        # destination would be a host symlink: bwrap fails, or rm plus a new
        # file persists on the host.
        self.write("dotfiles/AGENTS.md", "# dotfiles\n")
        agents = home / ".codex/AGENTS.md"
        for link in ("../dotfiles/AGENTS.md", str(home / "dotfiles/AGENTS.md")):
            with self.subTest(link=link):
                agents.unlink()
                agents.symlink_to(link)
                argv, protected = self.linux_argv()
                text = " ".join(argv) + " "
                self.assertIn(f"--tmpfs {codex} ", text)
                self.assertNotIn(f"--bind {codex} {codex} ", text)
                self.assertIn(f"--ro-bind {home}/dotfiles/AGENTS.md {codex}/AGENTS.md ", text)
                self.assertNotIn(home / ".codex", agent.linux_parent_binds(protected))

    def test_issue8_home_and_ancestors_never_protected(self):
        self.write("notes.txt", "not a directory\n")
        self.write(".claude/settings.json", json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": command}
            for command in ("~", "/", str(self.home.parent), "~/notes.txt/sub")]}]}}))
        self.write(".claude.json", json.dumps({"mcpServers": {"a": {"command": "~"}}}))
        paths, _ = self.resolve()
        self.assertNotIn(self.home, paths)
        self.assertFalse(paths & set(self.home.parents), paths & set(self.home.parents))
        self.assertNotIn(self.home / "notes.txt/sub", paths)


class Issue9StartupCodeTests(unittest.TestCase):
    """Shell and tool startup code (issue #9), scratch HOME only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        patcher = mock.patch.multiple(agent, HOME=self.home, AWS_DIR=self.home / ".aws",
                                      AGENT_DIR=self.home / ".agent-aws")
        patcher.start()
        self.addCleanup(patcher.stop)

    write = Issue6ResolverTests.write
    assert_protected = Issue6ResolverTests.assert_protected

    def test_issue9_startup_paths_and_tool_state_writable(self):
        paths = {agent.HOME / path for path in agent.STARTUP_PATHS}
        self.assert_protected(paths, ".config/fish/config.fish", ".config/fish/conf.d",
                              ".config/fish/functions", ".config/fish/completions",
                              ".oh-my-zsh/custom", ".zpreztorc", ".npmrc", ".inputrc",
                              ".config/starship.toml", ".config/direnv", ".tmux.conf",
                              ".config/tmux/tmux.conf", ".vimrc", ".vim/vimrc",
                              ".config/vim/vimrc", ".config/nvim/init.lua",
                              ".config/nvim/init.vim", ".ipython/profile_default/startup",
                              ".ipython/profile_default/ipython_config.py")
        for name in (".config", ".config/fish", ".config/fish/fish_variables", ".oh-my-zsh",
                     ".oh-my-zsh/cache", ".zprezto", ".config/nvim", ".config/tmux", ".ipython",
                     ".vim", ".config/vim", ".local/share/fish"):
            self.assertNotIn(self.home / name, paths, name)
        # LINUX_PARENT_BIND needs its protected entries as direct children.
        for name in (".config/fish", ".oh-my-zsh"):
            self.assertIn(name, agent.LINUX_PARENT_BIND)
            below = [path for path in paths if agent.HOME / name in path.parents]
            self.assertTrue(below, name)
            self.assertTrue(all(path.parent == agent.HOME / name for path in below), name)

    def test_issue9_python_startup_file(self):
        startup = self.write("dotfiles/pythonrc.py", "# fixture\n")
        for value, expected in ((str(startup), True), ("relative.py", False), ("", False)):
            with mock.patch.dict(agent.os.environ, {"PYTHONSTARTUP": value}):
                self.assertEqual(startup in agent.protected_paths(), expected, value)
        # It is a config target: the Linux note lists ~/dotfiles, which is a
        # skeleton only because of it.
        with mock.patch.dict(agent.os.environ, {"PYTHONSTARTUP": str(startup)}):
            targets = agent.config_targets()
            self.assertIn(startup, targets)
            protected = agent.protected_paths(targets)
            self.assertEqual(agent.linux_target_skeletons(protected, targets),
                             [self.home / "dotfiles"])

    def test_issue9_linux_fish_and_omz_parent_bind(self):
        for name in (".config/fish/config.fish", ".config/fish/fish_variables",
                     ".config/fish/conf.d/x.fish", ".config/other/settings",
                     ".oh-my-zsh/custom/x.zsh", ".oh-my-zsh/oh-my-zsh.sh", ".npmrc"):
            self.write(name, "# fixture\n")
        (self.home / ".oh-my-zsh/cache").mkdir()
        (self.home / ".vim/plugin").mkdir(parents=True)
        joined = " ".join(agent.build_sandbox_argv_linux(self.home / "creds")) + " "
        # Review round 1: ~/.config/fish and ~/.oh-my-zsh are read-write binds
        # (fish_variables and omz files can be replaced by rename); only the
        # existing protected children are read-only on top. ~/.vim stays a
        # skeleton, so a missing ~/.vim/vimrc cannot be created.
        for name in (".config", ".vim"):
            self.assertIn(f"--tmpfs {self.home}/{name} ", joined, name)
        for name in (".config/fish", ".oh-my-zsh"):
            self.assertNotIn(f"--tmpfs {self.home}/{name} ", joined, name)
            self.assertIn(f"--bind {self.home}/{name} {self.home}/{name} ", joined, name)
        for name in (".config/fish/config.fish", ".config/fish/conf.d", ".oh-my-zsh/custom", ".npmrc"):
            self.assertIn(f"--ro-bind {self.home}/{name} {self.home}/{name} ", joined, name)
            parent = str(Path(name).parent)
            if parent != ".":
                self.assertLess(joined.index(f"--bind {self.home}/{parent} "),
                                joined.index(f"--ro-bind {self.home}/{name} "), name)
        for name in (".config/fish/functions", ".config/fish/completions"):
            self.assertNotIn(f"{self.home}/{name}", joined, name)
        for name in (".config/fish/fish_variables", ".oh-my-zsh/oh-my-zsh.sh", ".oh-my-zsh/cache"):
            self.assertNotIn(f"{self.home}/{name}", joined, name)
        for name in (".config/other", ".vim/plugin"):
            self.assertIn(f"--bind {self.home}/{name} {self.home}/{name} ", joined, name)
        # Review round 2, R2-1: a symlinked protected child (absolute
        # config.fish link, relative custom dir link into a dotfiles repo)
        # keeps the skeleton for that directory only.
        self.write("dotfiles/fish/config.fish", "# dotfiles\n")
        self.write("dotfiles/omz-custom/x.zsh", "# dotfiles\n")
        fish, omz = self.home / ".config/fish", self.home / ".oh-my-zsh"
        (fish / "config.fish").unlink()
        (fish / "config.fish").symlink_to(self.home / "dotfiles/fish/config.fish")
        joined = " ".join(agent.build_sandbox_argv_linux(self.home / "creds")) + " "
        self.assertIn(f"--tmpfs {fish} ", joined)
        self.assertNotIn(f"--bind {fish} {fish} ", joined)
        self.assertIn(f"--ro-bind {self.home}/dotfiles/fish/config.fish {fish}/config.fish ", joined)
        self.assertIn(f"--bind {omz} {omz} ", joined)
        shutil.rmtree(omz / "custom")
        (omz / "custom").symlink_to("../dotfiles/omz-custom")
        joined = " ".join(agent.build_sandbox_argv_linux(self.home / "creds")) + " "
        self.assertIn(f"--tmpfs {omz} ", joined)
        self.assertNotIn(f"--bind {omz} {omz} ", joined)
        self.assertIn(f"--ro-bind {self.home}/dotfiles/omz-custom {omz}/custom ", joined)
        # Skeleton: the existing oh-my-zsh.sh is a writable mount point.
        self.assertIn(f"--bind {omz}/oh-my-zsh.sh {omz}/oh-my-zsh.sh ", joined)


class Issue13CommandTests(unittest.TestCase):
    """Install location of the run's own command (issue #13), scratch HOME only."""

    CODEX_RELEASE = ".codex/packages/standalone/releases/0.160.1-aarch64-apple-darwin"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        home = self.home
        (home / "project").mkdir()
        (home / ".local/bin").mkdir(parents=True)
        # claude: `~/.local/bin/claude -> ~/.local/share/claude/versions/2.1.301`.
        self.executable(".local/share/claude/versions/2.1.301")
        (home / ".local/bin/claude").symlink_to(home / ".local/share/claude/versions/2.1.301")
        # codex standalone: `~/.local/bin/codex -> …/current/bin/codex`, with
        # `current -> releases/0.160.1-aarch64-apple-darwin`.
        self.executable(f"{self.CODEX_RELEASE}/bin/codex")
        (home / ".codex/packages/standalone/current").symlink_to("releases/0.160.1-aarch64-apple-darwin")
        (home / ".local/bin/codex").symlink_to(home / ".codex/packages/standalone/current/bin/codex")
        self.executable("tool")
        self.executable("project/script")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(home / "project")
        for patcher in (mock.patch.dict(os.environ, {"PATH": f"{home}/.local/bin:/usr/bin:/bin"}),
                        mock.patch.object(agent, "HOME", home)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def executable(self, name):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)
        return path

    def assert_home_and_tree_open(self, paths, *trees):
        for path in (self.home, *self.home.parents, *trees):
            self.assertNotIn(path, paths, f"{path} protected")
        for tree in trees:
            self.assertFalse(any(tree in path.parents for path in paths), f"path inside {tree} protected")

    def test_pr25_plain_command_in_home_tool_prefix_protects_bin_dir(self):
        # PR #25 review 1, finding 2: a plain file in `~/.local/bin`,
        # `~/.cargo/bin`, `~/go/bin` or `~/.bun/bin` must not make the whole
        # tool prefix (a direct child of HOME) read-only, only its bin dir.
        home = self.home
        bins = (".local/bin", ".cargo/bin", "go/bin", ".bun/bin")
        for index, bin_dir in enumerate(bins):
            self.executable(f"{bin_dir}/tool{index}")
        with mock.patch.dict(os.environ, {"PATH": ":".join(str(home / b) for b in bins)}):
            for index, bin_dir in enumerate(bins):
                with self.subTest(bin_dir=bin_dir):
                    paths = agent.command_paths(f"tool{index}")
                    self.assertEqual(paths, {home / bin_dir})
                    self.assertNotIn(home / bin_dir.split("/")[0], paths)
        # aws and python3 keep the #19/#21 rule: their `../..` is protected.
        self.assertEqual(agent.install_paths(home / ".local/bin/tool0", agent.home_or_ancestor),
                         {home / ".local"})

    def test_issue13_claude_and_codex_install_locations(self):
        home = self.home
        claude = agent.command_paths("claude")
        self.assertEqual(claude, {home / ".local/bin/claude", home / ".local/share/claude"})
        codex = agent.command_paths("codex")
        self.assertEqual(codex, {home / ".local/bin/codex", home / ".codex/packages/standalone/current",
                                 home / self.CODEX_RELEASE})
        self.assert_home_and_tree_open(claude | codex, home / "project")
        self.assertEqual(agent.command_paths("no-such-command-agent-aws"), set())
        # The paths are final: protected_paths() keeps the link itself and
        # does not resolve a directory link to its target's parent.
        with mock.patch.multiple(agent, AWS_DIR=home / ".aws", AGENT_DIR=home / ".agent-aws"):
            protected = agent.protected_paths(set(), codex | claude)
        self.assertTrue(codex | claude <= protected)
        self.assertNotIn(home / ".codex/packages/standalone/releases", protected)
        self.assertNotIn(home / ".codex/packages/standalone", protected)

    def test_issue13_system_shell_protects_neither_root_nor_home(self):
        paths = agent.command_paths("/bin/sh")
        resolved = Path("/bin/sh").resolve()
        self.assertNotIn(Path("/"), paths)
        self.assertIn(resolved.parent.parent if resolved.parent.parent != Path("/") else resolved.parent,
                      paths)  # macOS: /bin; Linux (merged /usr): /usr
        self.assert_home_and_tree_open(paths, self.home / "project")

    def test_issue13_command_in_working_tree_protects_nothing_there(self):
        home = self.home
        project = home / "project"
        for program in ("./script", str(project / "script")):
            with self.subTest(program=program):
                self.assertEqual(agent.command_paths(program), set())
        # A git toplevel above cwd (a `.git` dir or a worktree's `.git` file).
        for kind in ("dir", "file"):
            with self.subTest(git=kind):
                repo = home / f"repo-{kind}"
                (repo / "sub").mkdir(parents=True)
                (repo / ".git").mkdir() if kind == "dir" else (repo / ".git").write_text("gitdir: x\n")
                self.executable(f"repo-{kind}/tools/x")
                (home / ".local/bin" / f"x-{kind}").symlink_to(repo / "tools/x")
                os.chdir(repo / "sub")
                for program in ("../tools/x", f"x-{kind}"):
                    paths = agent.command_paths(program)
                    self.assertEqual(paths, set(), program)
                    self.assert_home_and_tree_open(paths, repo)
        # cwd = <W>/project with no .git: `../tool` (in HOME) protects the executable only.
        os.chdir(project)
        self.assertEqual(agent.command_paths("../tool"), {home / "tool"})

    def test_issue13_cwd_home_and_dotfiles_repo_in_home(self):
        home = self.home
        for setup in ("cwd-home", "dotfiles-git"):
            with self.subTest(setup=setup):
                if setup == "cwd-home":
                    os.chdir(home)
                else:
                    (home / ".git").mkdir()
                    os.chdir(home / "project")
                self.assertEqual(agent.command_paths(str(home / "tool")), {home / "tool"})
                claude = agent.command_paths("claude")
                self.assertIn(home / ".local/share/claude", claude)
                self.assert_home_and_tree_open(claude)

    def linux_mounts(self, targets):
        home = self.home
        with mock.patch.multiple(agent, AWS_DIR=home / ".aws", AGENT_DIR=home / ".agent-aws"):
            protected = agent.protected_paths(set(targets))
            argv = " ".join(agent.linux_home_mounts(protected)) + " "
            return protected, argv, agent.linux_target_skeletons(protected, set(targets))

    def test_issue13_linux_codex_install_keeps_codex_parent_bind(self):
        # Pure argv check (also on macOS). The codex install below
        # ~/.codex/packages must not make ~/.codex a skeleton: codex replaces
        # ~/.codex/config.toml by rename.
        home = self.home
        (home / ".codex/config.toml").write_text('model = "fixture"\n')
        (home / ".codex/AGENTS.md").write_text("# fixture\n")
        codex = {home / ".local/bin/codex", home / ".codex/packages/standalone/current",
                 home / self.CODEX_RELEASE}
        claude = {home / ".local/bin/claude", home / ".local/share/claude"}
        protected, argv, skeletons = self.linux_mounts(codex | claude)
        self.assertIn(home / ".codex", agent.linux_parent_binds(protected))
        dot_codex, packages = home / ".codex", home / ".codex/packages"
        standalone = packages / "standalone"
        self.assertIn(f"--bind {dot_codex} {dot_codex} ", argv)
        self.assertNotIn(f"--tmpfs {dot_codex} ", argv)
        self.assertIn(f"--ro-bind {dot_codex}/AGENTS.md {dot_codex}/AGENTS.md ", argv)
        self.assertIn(f"--tmpfs {packages} ", argv)
        self.assertIn(f"--tmpfs {standalone} ", argv)
        self.assertIn(f"--ro-bind {home / self.CODEX_RELEASE} {standalone}/current ", argv)
        self.assertIn(f"--ro-bind {home / self.CODEX_RELEASE} {home / self.CODEX_RELEASE} ", argv)
        self.assertNotIn(f"{dot_codex}/config.toml", argv)
        self.assertLess(argv.index(f"--bind {dot_codex} "), argv.index(f"--tmpfs {packages} "))
        self.assertIn(f"--ro-bind {home}/.local/share/claude {home}/.local/share/claude ", argv)
        self.assertEqual(skeletons, [home / ".codex/packages", standalone, standalone / "releases",
                                     home / ".local/share"])
        # A missing or symlinked direct child on the way keeps the skeleton.
        shutil.rmtree(packages)
        (home / "elsewhere/standalone").mkdir(parents=True)
        packages.symlink_to(home / "elsewhere")
        protected, argv, _ = self.linux_mounts({packages / "standalone/x"})
        self.assertNotIn(home / ".codex", agent.linux_parent_binds(protected))
        self.assertIn(f"--tmpfs {dot_codex} ", argv)
        packages.unlink()
        protected, argv, _ = self.linux_mounts({packages / "standalone/x"})
        self.assertNotIn(home / ".codex", agent.linux_parent_binds(protected))
        self.assertIn(f"--tmpfs {dot_codex} ", argv)


if __name__ == "__main__":
    unittest.main()
