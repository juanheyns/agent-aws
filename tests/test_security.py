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
                      "when the run ends (they hold protected git/ssh/agent config or "
                      "$PYTHONSTARTUP targets): ", note)
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


if __name__ == "__main__":
    unittest.main()
