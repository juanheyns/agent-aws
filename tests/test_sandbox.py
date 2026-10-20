"""Real sandbox acceptance with a scratch HOME and a fake aws executable.

No login or AWS request is made. Run on macOS with:
    python3 -m unittest discover -s tests -p test_sandbox.py -v
On Linux the same fixture exercises bwrap when it is installed.
"""
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_security import ROOT, config

HAS_TOMLLIB = importlib.util.find_spec("tomllib") is not None
SUPPORTED = sys.platform == "darwin" or (sys.platform.startswith("linux") and shutil.which("bwrap"))


@unittest.skipUnless(SUPPORTED, "requires sandbox-exec or bwrap")
class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="sandbox-check-", dir="/tmp")
        cls.home = Path(cls.tmp.name).resolve()
        # GIT_* and XDG_CONFIG_HOME of the developer would point the git
        # config resolver (issue #6) outside the scratch HOME.
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "GIT_")) and k != "XDG_CONFIG_HOME"}
        cls.env["HOME"] = str(cls.home)
        for relative in (".aws/sso/cache", ".agent-aws", "Library/LaunchAgents", ".config/brnr", "bin", "project", ".local/bin"):
            (cls.home / relative).mkdir(parents=True)
        for name in (".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".aws/config"):
            (cls.home / name).write_text("# sentinel\n")
        (cls.home / "x.plist").write_text("fixture, not a real launch agent\n")
        cls.config_path = cls.home / ".agent-aws/config.json"
        cls.config_path.write_text(json.dumps(config()))
        cls.config_path.chmod(0o600)
        (cls.home / ".aws/sso/cache/fake.json").write_text(json.dumps({
            "startUrl": "https://example.invalid/start", "accessToken": "FAKE-NOT-A-TOKEN",
            "expiresAt": "2999-01-01T00:00:00Z",
        }))
        fake_aws = cls.home / "bin/aws"
        fake_aws.write_text(f"#!{sys.executable} -I\n" + '''import json, os, sys
if sys.argv[1:3] != ["sso", "get-role-credentials"]:
    sys.exit("unexpected fake AWS call")
print(json.dumps({"roleCredentials": {"accessKeyId": os.environ.get("FAKE_AWS_KEY", "FAKE-KEY"),
    "secretAccessKey": "FAKE-SECRET", "sessionToken": "FAKE-SESSION"}}))
''')
        fake_aws.chmod(0o700)
        cls.env["PATH"] = f"{cls.home}/.local/bin:{cls.home}/bin:" + os.environ["PATH"]
        (cls.home / "bin/python3").symlink_to(sys.executable)
        # Exercise the source shebang, not a caller-supplied Python flag.
        cls.base = [str(ROOT / "bin/agent-aws"), "run", "--", "/bin/sh", "-c"]
        result = cls.run_shell('test "$AGENT_AWS_ACTIVE" = 1 && cat "$AWS_SHARED_CREDENTIALS_FILE"')
        if result.returncode or "FAKE-KEY" not in result.stdout:
            cls.tmp.cleanup()
            raise AssertionError(f"sandbox positive control failed: {result.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_shell(cls, command):
        return subprocess.run(cls.base + [command], env=cls.env, cwd=cls.home,
                              capture_output=True, text=True, timeout=20)

    def denied(self, command):
        result = self.run_shell(command)
        self.assertNotEqual(result.returncode, 0, command)
        self.assertRegex(result.stderr.lower(), "not permitted|permission denied|read-only file system")
        print(f"ACCEPTANCE PASS: {command} [exit {result.returncode}; {result.stderr.strip()}]", flush=True)
        return result

    def test_01_config_overwrite(self):
        before = self.config_path.read_text()
        self.denied('echo \'{"profiles":{"test":{"role_name":"AWSAdministratorAccess"}}}\' > ~/.agent-aws/config.json')
        self.assertEqual(self.config_path.read_text(), before)

    def test_02_shell_rc_and_launchagents(self):
        self.denied('echo x >> ~/.zshrc')
        self.denied('cp x.plist ~/Library/LaunchAgents/')
        self.assertEqual((self.home / ".zshrc").read_text(), "# sentinel\n")
        self.assertFalse((self.home / "Library/LaunchAgents/x.plist").exists())

    def test_03_aws_config(self):
        self.denied("printf '[default]\\ncredential_process=/tmp/x\\n' >> ~/.aws/config")
        self.assertEqual((self.home / ".aws/config").read_text(), "# sentinel\n")

    @unittest.skipUnless(sys.platform == "darwin", "macOS launch services")
    def test_04_open(self):
        self.denied('open -a Terminal /tmp/x.command')

    def test_05_other_active_run(self):
        ready = self.home / "project/ready"
        stop = self.home / "project/stop"
        other = subprocess.Popen(self.base + [
            'echo "$AWS_SHARED_CREDENTIALS_FILE" > "$HOME/project/ready"; '
            'while [ ! -f "$HOME/project/stop" ]; do sleep 0.1; done'
        ], env=dict(self.env, FAKE_AWS_KEY="FAKE-OTHER"), cwd=self.home,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and other.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(ready.exists(), "second sandbox did not become ready")
            other_creds = ready.read_text().strip()
            self.denied(f'cat "{other_creds}"') if sys.platform == "darwin" else self.assertNotEqual(
                self.run_shell(f'cat "{other_creds}"').returncode, 0)
            # Do not print stdout: a regression could expose another run's secret.
            if sys.platform == "darwin":
                glob = self.denied('cat /tmp/agent-aws.*/credentials')
                self.assertIn('FAKE-KEY', glob.stdout)
                self.assertNotIn('FAKE-OTHER', glob.stdout)
                self.denied(f'cat "{Path(other_creds).resolve()}"')
            other_config = str(Path(other_creds).with_name("config"))
            before = Path(other_config).read_text()
            for command in (
                f'mv "{other_creds}" "$(dirname "$AWS_SHARED_CREDENTIALS_FILE")/stolen-mv"',
                f'printf "credential_process=/tmp/evil\\n" >> "{other_config}"',
            ):
                result = self.run_shell(command)
                self.assertNotEqual(result.returncode, 0, command)
            self.assertTrue(Path(other_creds).exists())
            self.assertEqual(Path(other_config).read_text(), before)
        finally:
            stop.touch()
            other.communicate(timeout=10)
        self.assertEqual(other.returncode, 0)
        self.assertFalse(Path(other_creds).exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS devfs mount")
    def test_06_mount(self):
        (self.home / "m").mkdir(exist_ok=True)
        self.denied('mount -t devfs devfs "$HOME/m"')

    def test_07_other_protected_files_and_positive_control(self):
        for path in (".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/brnr/new"):
            self.denied(f'echo x >> "$HOME/{path}"')
        self.denied(f'echo x >> "{ROOT}/bin/agent-aws"')
        result = self.run_shell('echo ok > "$HOME/project/ok"; cat "$HOME/project/ok"; cat "$AWS_CONFIG_FILE"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.home / "project/ok").read_text(), "ok\n")
        self.assertIn("us-east-1", result.stdout)

    @unittest.skipUnless(sys.platform == "darwin", "macOS process execution denies")
    def test_08_other_launchers(self):
        self.denied('/usr/bin/osascript -e "return 1"')
        self.denied('/bin/launchctl help')

    def test_09_missing_startup_file_and_symlink_target(self):
        missing = self.home / ".bashrc"
        missing.unlink()
        try:
            result = self.run_shell('echo planted > "$HOME/.bashrc"')
            if sys.platform == "darwin":
                self.assertNotEqual(result.returncode, 0)
            self.assertFalse(missing.exists(), "missing startup file persisted to host")
        finally:
            missing.write_text("# sentinel\n")
        target = self.home / "project/real-rc"
        target.write_text("# sentinel\n")
        missing.unlink()
        missing.symlink_to(target)
        try:
            self.denied('echo planted >> "$HOME/.bashrc"')
            self.denied('echo planted >> "$HOME/project/real-rc"')
            self.assertEqual(target.read_text(), "# sentinel\n")
        finally:
            missing.unlink()
            missing.write_text("# sentinel\n")

    @unittest.skipUnless(sys.platform == "darwin", "macOS Mach services")
    def test_10_launchservices_mach_lookup(self):
        probe = self.home / "mach_probe.py"
        probe.write_text('''import ctypes, sys
lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
port = ctypes.c_uint.in_dll(lib, "bootstrap_port")
service = ctypes.c_uint()
rc = lib.bootstrap_look_up(port, b"com.apple.coreservices.launchservicesd", ctypes.byref(service))
print(rc)
sys.exit(0 if rc == 0 else 1)
''')
        outside = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True)
        self.assertEqual(outside.returncode, 0, "Launch Services unavailable in positive control")
        inside = self.run_shell(f'"{sys.executable}" "$HOME/mach_probe.py"')
        self.assertNotEqual(inside.returncode, 0)
        print(f"MACH LOOKUP: outside={outside.stdout.strip()}, inside={inside.stdout.strip()}", flush=True)

    def not_persisted(self, command, path):
        # Missing paths: EPERM on macOS; private to the run's skeleton on Linux.
        result = self.run_shell(command)
        if sys.platform == "darwin":
            self.assertNotEqual(result.returncode, 0, command)
        self.assertFalse(path.exists(), f"{path} persisted to host")

    def test_issue4_git_ssh_and_agent_settings(self):
        files = {".gitconfig": "[user]\n\tname = Fixture User\n", ".ssh/config": "# sentinel\n",
                 ".ssh/authorized_keys": "# sentinel\n", ".ssh/known_hosts": "# sentinel\n",
                 ".claude/settings.json": "{}\n"}
        for name, text in files.items():
            (self.home / name).parent.mkdir(parents=True, exist_ok=True)
            (self.home / name).write_text(text)
        (self.home / ".claude/projects").mkdir()
        try:
            for command in (
                "printf '[core]\\n\\tfsmonitor = /tmp/evil\\n' >> ~/.gitconfig",
                "printf 'Host *\\n  ProxyCommand /tmp/evil\\n' >> ~/.ssh/config",
                "echo 'ssh-ed25519 AAAA fixture' >> ~/.ssh/authorized_keys",
                'echo \'{"hooks": {}}\' > ~/.claude/settings.json',
            ):
                self.denied(command)
            for name in (".config/git/config", ".ssh/rc", ".claude/settings.local.json"):
                self.not_persisted(f'mkdir -p "$(dirname "$HOME/{name}")" && '
                                   f'echo /tmp/evil > "$HOME/{name}"', self.home / name)
            for name, text in files.items():
                self.assertEqual((self.home / name).read_text(), text, name)
            # Reads and ordinary state still work: git reads its global config,
            # ssh records host keys and Claude Code writes session state.
            result = self.run_shell("git config --global --get user.name && "
                                    "echo 'host ssh-ed25519 AAAA' >> ~/.ssh/known_hosts && "
                                    "echo '{}' > ~/.claude/projects/session.jsonl")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Fixture User", result.stdout)
            self.assertIn("host ssh-ed25519", (self.home / ".ssh/known_hosts").read_text())
            self.assertTrue((self.home / ".claude/projects/session.jsonl").exists())
        finally:
            (self.home / ".gitconfig").unlink()
            shutil.rmtree(self.home / ".ssh")
            shutil.rmtree(self.home / ".claude")

    def write_fixtures(self, files):
        for name, text in files.items():
            (self.home / name).parent.mkdir(parents=True, exist_ok=True)
            (self.home / name).write_text(text)

    def denied_all(self, commands, label="ISSUE6"):
        # Run every attack first, so a failure reports all writable paths.
        results = {command: self.run_shell(command) for command in commands}
        for command, result in results.items():
            state = "DENIED" if result.returncode else "WRITABLE"
            print(f"{label} {state} exit={result.returncode} {command} "
                  f"[{result.stderr.strip()}]", flush=True)
        writable = [command for command, result in results.items() if not result.returncode]
        self.assertEqual(writable, [], "writable from a run")
        for command, result in results.items():
            self.assertRegex(result.stderr.lower(),
                             "not permitted|permission denied|read-only file system", command)

    def assert_unchanged(self, files):
        for name, text in files.items():
            self.assertEqual((self.home / name).read_text(), text, name)

    def test_issue6_git_include_targets_hooks_path_and_helpers(self):
        # Issue #6: ~/.gitconfig is protected (#5), but the files and programs
        # it refers to were writable. The includeIf condition does not match
        # the run's cwd, so git alone would not list that target.
        home = self.home
        gitconfig = ("[include]\n\tpath = ~/dotfiles/git-extra\n"
                     '[includeIf "gitdir:~/work/"]\n\tpath = dotfiles/work-extra\n'
                     "[core]\n\thooksPath = ~/.githooks\n"
                     f"[credential]\n\thelper = {home}/tools/git-cred --fixture\n"
                     # Review round 1 (PR #16): config-based hooks and the
                     # init template directory that `git init` copies hooks from.
                     f'[hook "lint"]\n\tcommand = {home}/tools/lint-hook\n\tevent = pre-commit\n'
                     "[init]\n\ttemplateDir = ~/.git-templates\n")
        protected = {
            ".gitconfig": gitconfig,
            "dotfiles/git-extra": "[user]\n\tname = Included User\n[include]\n\tpath = nested-extra\n",
            "dotfiles/nested-extra": "[core]\n\tfsmonitor = ~/tools/git-fsmonitor\n",
            ".githooks/pre-commit": "#!/bin/sh\nexit 0\n",
            "tools/git-cred": "#!/bin/sh\nexit 0\n",
            "tools/git-fsmonitor": "#!/bin/sh\nexit 0\n",
            "tools/lint-hook": "#!/bin/sh\nexit 0\n",
            ".git-templates/hooks/post-checkout": "#!/bin/sh\nexit 0\n",
        }
        writable = {"dotfiles/unrelated": "# sentinel\n", "tools/unrelated": "# sentinel\n",
                    ".ssh/known_hosts": "# sentinel\n"}
        self.write_fixtures({**protected, **writable})
        try:
            self.denied_all((
                "echo '[core]fsmonitor=/tmp/evil' >> ~/dotfiles/git-extra",
                "echo '[core]fsmonitor=/tmp/evil' >> ~/dotfiles/nested-extra",
                "echo 'curl evil' >> ~/.githooks/pre-commit",
                "echo 'curl evil' > ~/.githooks/post-checkout",
                "echo 'curl evil' >> ~/tools/git-cred",
                "echo 'curl evil' >> ~/tools/git-fsmonitor",
                "echo 'curl evil' >> ~/tools/lint-hook",
                "echo 'curl evil' >> ~/.git-templates/hooks/post-checkout",
                "echo 'curl evil' > ~/.git-templates/hooks/pre-commit",
            ))
            self.not_persisted("echo '[core]fsmonitor=/tmp/evil' > ~/dotfiles/work-extra",
                               home / "dotfiles/work-extra")
            self.assertFalse((home / ".githooks/post-checkout").exists())
            self.assertFalse((home / ".git-templates/hooks/pre-commit").exists())
            self.assert_unchanged(protected)
            # Positive controls: git still reads the included config, and
            # files that the git config does not refer to stay writable.
            # (--global alone does not follow includes.)
            result = self.run_shell("git config --global --includes --get user.name && "
                                    "git config --global --get core.hooksPath && "
                                    "echo ok >> ~/dotfiles/unrelated && "
                                    "echo ok >> ~/tools/unrelated && "
                                    "echo 'host ssh-ed25519 AAAA' >> ~/.ssh/known_hosts")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Included User", result.stdout)
            self.assertIn("~/.githooks", result.stdout)
            for name in writable:
                self.assertIn("ok" if "unrelated" in name else "host ssh-ed25519",
                              (home / name).read_text(), name)
            print(f"ISSUE6 GIT CONTROL: {result.stdout.strip()}", flush=True)
        finally:
            (home / ".gitconfig").unlink()
            for name in ("dotfiles", ".githooks", ".git-templates", "tools", ".ssh"):
                shutil.rmtree(home / name)

    def test_issue6_ssh_include_targets_and_commands(self):
        # Issue #6: ssh `Include` targets and the programs that ssh runs
        # (ProxyCommand, Match exec, KnownHostsCommand) outside ~/.ssh/config.
        home = self.home
        protected = {
            ".ssh/config": ("Include config.d/*\nInclude ~/ssh-extra/hosts\n"
                            "Host jump\n  ProxyCommand ~/tools/ssh-proxy %h %p\n"
                            'Match exec "~/tools/ssh-match %h"\n  User fixture\n'),
            ".ssh/config.d/work": f"Host work\n  KnownHostsCommand={home}/tools/ssh-known %H\n",
            "ssh-extra/hosts": "Host extra\n  User fixture\n",
            "tools/ssh-proxy": "#!/bin/sh\nexit 0\n",
            "tools/ssh-match": "#!/bin/sh\nexit 0\n",
            "tools/ssh-known": "#!/bin/sh\nexit 0\n",
        }
        writable = {"ssh-extra/unrelated": "# sentinel\n", "tools/unrelated": "# sentinel\n",
                    ".ssh/known_hosts": "# sentinel\n"}
        self.write_fixtures({**protected, **writable})
        try:
            self.denied_all((
                "echo 'ProxyCommand /tmp/evil' >> ~/.ssh/config.d/work",
                "echo 'ProxyCommand /tmp/evil' > ~/.ssh/config.d/zz-new",
                "echo 'ProxyCommand /tmp/evil' >> ~/ssh-extra/hosts",
                "echo 'curl evil' >> ~/tools/ssh-proxy",
                "echo 'curl evil' >> ~/tools/ssh-match",
                "echo 'curl evil' >> ~/tools/ssh-known",
            ))
            self.assertFalse((home / ".ssh/config.d/zz-new").exists())
            self.assert_unchanged(protected)
            result = self.run_shell("echo ok >> ~/ssh-extra/unrelated && "
                                    "echo ok >> ~/tools/unrelated && "
                                    "echo 'host ssh-ed25519 AAAA' >> ~/.ssh/known_hosts")
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in writable:
                self.assertIn("ok" if "unrelated" in name else "host ssh-ed25519",
                              (home / name).read_text(), name)
        finally:
            for name in ("ssh-extra", "tools", ".ssh"):
                shutil.rmtree(home / name)

    def test_issue8_agent_instructions_and_config_programs(self):
        # Issue #8: user-level agent instructions, and the programs that agent
        # config names (hooks, MCP servers, Codex notify), were writable. The
        # config files themselves stay writable: the agents write them.
        home = self.home
        settings = json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "~/.claude/hooks/check.sh --fixture"}]}]}})
        claude_json = json.dumps({
            "mcpServers": {"fixture": {"command": f"{home}/tools/mcp-server", "args": []}},
            "projects": {str(home / "project"): {"mcpServers": {"p": {"command": "~/tools/project-mcp"}}}}})
        codex_toml = ('notify = ["~/tools/codex-notify", "--fixture"]\n'
                      '[mcp_servers.fixture]\ncommand = "~/tools/codex-mcp"\n')
        script = "#!/bin/sh\nexit 0\n"
        protected = {
            ".claude/settings.json": settings,
            ".claude/agents/reviewer.md": "# fixture\n",
            ".claude/commands/deploy.md": "# fixture\n",
            ".codex/AGENTS.md": "# fixture\n",
            ".claude/hooks/check.sh": script,
            "tools/mcp-server": script,
            "tools/project-mcp": script,
        }
        # Codex config is TOML: protected only where tomllib exists (3.11+).
        codex_programs = {"tools/codex-mcp": script, "tools/codex-notify": script}
        if HAS_TOMLLIB:
            protected.update(codex_programs)
        writable = {".claude.json": claude_json, ".codex/config.toml": codex_toml,
                    ".codex/auth.json": '{"token": "FAKE-NOT-A-TOKEN"}\n',
                    ".claude/projects/old.jsonl": "{}\n", ".codex/sessions/old": "{}\n",
                    ".claude/plugins/installed_plugins.json": "{}\n",
                    "tools/unrelated": "# sentinel\n", ".claude/hooks/unrelated.sh": "# sentinel\n",
                    **({} if HAS_TOMLLIB else codex_programs)}
        self.write_fixtures({**protected, **writable})
        try:
            self.denied_all([f"echo 'curl evil' >> ~/{name}" for name in protected]
                            + ["echo 'curl evil' > ~/.claude/agents/new.md",
                               "echo 'curl evil' > ~/.claude/hooks/check.sh"], label="ISSUE8")
            # Missing instruction files and directories cannot be planted.
            for name in (".claude/CLAUDE.md", ".claude/skills/x/SKILL.md", ".codex/AGENTS.override.md"):
                self.not_persisted(f'mkdir -p "$(dirname "$HOME/{name}")" && '
                                   f'echo "run evil" > "$HOME/{name}"', home / name.split("/x/")[0])
                print(f"ISSUE8 NOT PERSISTED {name}", flush=True)
            self.assert_unchanged(protected)
            # Positive controls: the agents' own config and state stay writable.
            result = self.run_shell(" && ".join(
                ["echo '{\"mcpServers\": {}}' >> ~/.claude.json",
                 "echo '{}' > ~/.claude/projects/x.jsonl",
                 "echo 'model = \"fixture\"' >> ~/.codex/config.toml",
                 "echo '{}' > ~/.codex/auth.json",
                 "echo '{}' > ~/.codex/sessions/x",
                 "echo '{}' > ~/.claude/plugins/installed_plugins.json",
                 "echo ok >> ~/tools/unrelated",
                 "echo ok >> ~/.claude/hooks/unrelated.sh"]))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mcpServers\": {}}", (home / ".claude.json").read_text())
            self.assertIn("fixture", (home / ".codex/config.toml").read_text())
            for name in (".claude/projects/x.jsonl", ".codex/sessions/x"):
                self.assertTrue((home / name).exists(), name)
            for name in ("tools/unrelated", ".claude/hooks/unrelated.sh"):
                self.assertIn("ok", (home / name).read_text(), name)
            print("ISSUE8 CONTROLS WRITABLE: ~/.claude.json ~/.claude/projects ~/.codex/config.toml "
                  "~/.codex/auth.json ~/.codex/sessions ~/.claude/plugins, unrelated files", flush=True)
        finally:
            (home / ".claude.json").unlink()
            for name in (".claude", ".codex", "tools"):
                shutil.rmtree(home / name)

    def test_issue4_homebrew_prefix_dependencies(self):
        # Scratch model of a user-owned Homebrew prefix: PATH holds symlinks
        # into Cellar/, and interpreters load libraries through opt/.
        prefix = self.home / "homebrew"
        targets = ("Cellar/git/1.0/bin/git", "Cellar/xz/1.0/lib/liblzma.5.dylib",
                   "lib/node_modules/pkg/cli.js")
        for name in targets:
            (prefix / name).parent.mkdir(parents=True, exist_ok=True)
            (prefix / name).write_text("sentinel")
        (prefix / "bin").mkdir()
        (prefix / "bin/git").symlink_to("../Cellar/git/1.0/bin/git")
        (prefix / "opt").mkdir()
        (prefix / "opt/xz").symlink_to("../Cellar/xz/1.0")
        (prefix / "var/db").mkdir(parents=True)
        old_path = self.env["PATH"]
        self.env["PATH"] = f"{prefix}/bin:" + old_path
        try:
            for name in targets:
                self.denied(f'echo injected >> "{prefix}/{name}"')
                self.assertEqual((prefix / name).read_text(), "sentinel")
            self.denied(f'echo injected >> "{prefix}/opt/xz/lib/liblzma.5.dylib"')
            # var/ holds service data (databases, logs) and stays writable.
            result = self.run_shell(f'echo ok > "{prefix}/var/db/ok"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((prefix / "var/db/ok").read_text(), "ok\n")
        finally:
            self.env["PATH"] = old_path
            shutil.rmtree(prefix)

    def test_issue4_aws_script_using_other_python(self):
        # Round-3 note: `aws` may be a non-isolated script for another Python
        # (e.g. `pip install --user awscli`) whose user site we do not use.
        other = "/usr/bin/python3"
        probe = subprocess.run([other, "-I", "-c", "import site, sys; "
                                "print(tuple(sys.version_info[:2]), site.getusersitepackages())"],
                               env=self.env, capture_output=True, text=True) \
            if os.path.exists(other) else None
        if not probe or probe.returncode or probe.stdout.startswith(str(tuple(sys.version_info[:2]))):
            self.skipTest("requires a second Python version at /usr/bin/python3")
        user_site = Path(probe.stdout.split(") ", 1)[1].strip())
        self.assertIn(self.home, user_site.parents, "user site must stay inside scratch HOME")
        user_site.mkdir(parents=True, exist_ok=True)  # as `pip install --user` leaves it
        aws = self.home / "bin/aws"
        original = aws.read_text()
        marker = self.home / "project/aws-pth-ran"
        pth = user_site / "zz-agent-aws-test.pth"
        payload = (f"import pathlib, sys; pathlib.Path({str(marker)!r}).write_text("
                   "' '.join(sys.argv))\n")
        aws.write_text(f"#!{other}\n" + original.split("\n", 1)[1])
        try:
            # Positive control: that interpreter executes its user-site .pth.
            pth.write_text(payload)
            subprocess.run([str(aws)], env=self.env, capture_output=True)
            self.assertTrue(marker.exists())
            pth.unlink()
            marker.unlink()
            # Run 1 cannot plant it; run 2 must not hand the token to it.
            self.denied(f"printf %s {shlex.quote(payload)} > {shlex.quote(str(pth))}")
            self.assertFalse(pth.exists())
            next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            self.assertEqual(next_run.returncode, 0, next_run.stderr)
            self.assertFalse(marker.exists(), "AWS CLI interpreter ran planted startup code")
        finally:
            aws.write_text(original)
            pth.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)

    def test_round4_probe_failure_leaves_no_credentials_and_token_unused(self):
        # Review round 1, finding 1: `python3` on PATH answers the `-I -S`
        # probe with exit 1. The run must fail before `aws` gets the token,
        # and leave no credentials in /tmp. The sandbox profile hides other
        # runs by the fixed /tmp/agent-aws.* name, so agent-aws does not use
        # TMPDIR; compare /tmp before and after instead.
        wrap = self.home / "probe-fails/bin"
        wrap.mkdir(parents=True)
        calls = self.home / "project/aws-argv"
        python3 = wrap / "python3"
        python3.write_text('#!/bin/sh\ncase " $* " in *" -I -S "*) exit 1;; esac\n'
                           f'exec {shlex.quote(sys.executable)} "$@"\n')
        python3.chmod(0o700)
        body = (self.home / "bin/aws").read_text().split("\n", 1)[1]
        (wrap / "aws").write_text(
            "#!/usr/bin/env python3\n"
            f"import sys; open({str(calls)!r}, 'a').write(' '.join(sys.argv) + '\\n')\n" + body)
        (wrap / "aws").chmod(0o700)
        old_path = self.env["PATH"]
        self.env["PATH"] = f"{wrap}:" + old_path
        before = set(Path("/tmp").glob("agent-aws.*"))
        try:
            result = self.run_shell("true")
            left = set(Path("/tmp").glob("agent-aws.*")) - before
            print(f"PROBE FAIL: exit {result.returncode}; {result.stderr.strip()}; "
                  f"aws argv recorded={calls.exists()}; left in /tmp={sorted(map(str, left))}",
                  flush=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot determine the Python paths", result.stderr)
            self.assertFalse(calls.exists() and "FAKE-NOT-A-TOKEN" in calls.read_text(),
                             "aws received the SSO token before the probe failed")
            self.assertEqual(sorted(left), [], "temp dir with credentials left in /tmp")
        finally:
            self.env["PATH"] = old_path
            for leftover in set(Path("/tmp").glob("agent-aws.*")) - before:
                shutil.rmtree(leftover, ignore_errors=True)  # fake credentials only
            calls.unlink(missing_ok=True)
            shutil.rmtree(self.home / "probe-fails")

    @staticmethod
    def python_up_to_3_10(env):
        # macOS CLT /usr/bin/python3 is 3.9; CI runners keep older toolcache builds.
        candidates = ["/usr/bin/python3", "/usr/local/bin/python3", sys.executable,
                      *(shutil.which(f"python3.{minor}") for minor in (10, 9, 8))]
        for root in ("/opt/hostedtoolcache", "/Users/runner/hostedtoolcache"):
            for pattern in ("Python/3.10.*/*/bin/python3", "Python/3.9.*/*/bin/python3"):
                candidates += sorted(map(str, Path(root).glob(pattern)))
        for python in filter(None, candidates):
            try:
                probe = subprocess.run(
                    [python, "-I", "-c", "import sys; print((3, 8) <= sys.version_info < (3, 11))"],
                    env=env, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            if probe.returncode == 0 and probe.stdout.strip() == "True":
                return python
        return None

    def test_round4_venv_wrapper_for_python_up_to_3_10(self):
        # Review round 1, finding 2: before 3.11, `-I -S` hides a venv's
        # prefix. `aws` is a wrapper outside the venv whose shebang names the
        # venv's python (e.g. ~/bin/aws -> #!~/venvs/awscli/bin/python).
        old = self.python_up_to_3_10(self.env)
        if not old:
            self.skipTest("requires a Python 3.8-3.10 interpreter (none found)")
        venv = self.home / "venvs/awscli"
        subprocess.run([old, "-I", "-m", "venv", "--without-pip", str(venv)],
                       env=self.env, capture_output=True, text=True, check=True)
        python = venv / "bin/python"
        probe = subprocess.run([str(python), "-I", "-c", "import site; print(site.getsitepackages()[0])"],
                               env=self.env, capture_output=True, text=True, check=True)
        site_dir = Path(probe.stdout.strip())
        self.assertIn(venv, site_dir.parents, "venv site-packages must stay inside scratch HOME")
        aws = self.home / "bin/aws"
        original = aws.read_text()
        marker = self.home / "project/venv-pth-ran"
        pth = site_dir / "zz-evil.pth"
        payload = (f"import pathlib, sys; pathlib.Path({str(marker)!r}).write_text("
                   "' '.join(sys.argv))\n")
        aws.write_text(f"#!{python}\n" + original.split("\n", 1)[1])
        try:
            # Positive control: the venv interpreter executes its site .pth.
            pth.write_text(payload)
            subprocess.run([str(aws)], env=self.env, capture_output=True)
            self.assertTrue(marker.exists())
            pth.unlink()
            marker.unlink()
            # Run 1 cannot plant it; run 2 must not hand the token to it.
            plant = self.run_shell(f"printf %s {shlex.quote(payload)} > {shlex.quote(str(pth))}")
            print(f"VENV ({old}) run 1: exit {plant.returncode}; {plant.stderr.strip()}", flush=True)
            next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            print(f"VENV run 2: exit {next_run.returncode}; payload saw: "
                  f"{marker.read_text() if marker.exists() else '(did not run)'}", flush=True)
            self.assertNotEqual(plant.returncode, 0, "run 1 planted a .pth in the venv")
            self.assertRegex(plant.stderr.lower(), "not permitted|permission denied|read-only file system")
            self.assertFalse(pth.exists())
            self.assertEqual(next_run.returncode, 0, next_run.stderr)
            self.assertFalse(marker.exists(), "venv interpreter ran planted startup code")
        finally:
            aws.write_text(original)
            pth.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            shutil.rmtree(venv)

    def test_review1_aws_path_poisoning_across_runs(self):
        # The candidate precedes the real fixture CLI and does not yet exist.
        candidate = self.home / ".local/bin/aws"
        marker = self.home / "project/stolen-token"
        payload = '#!/bin/sh\necho stolen > "$HOME/project/stolen-token"\n'
        self.denied(f'printf %s {shlex.quote(payload)} > "$HOME/.local/bin/aws"')
        self.assertFalse(candidate.exists())
        next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
        self.assertEqual(next_run.returncode, 0, next_run.stderr)
        self.assertFalse(marker.exists())
        # An absent earlier PATH directory must not be persistently planted.
        missing = self.home / ".local/missing-bin"
        old_path = self.env["PATH"]
        self.env["PATH"] = f"{missing}:" + old_path
        try:
            self.run_shell('mkdir -p "$HOME/.local/missing-bin" && '
                           'echo evil > "$HOME/.local/missing-bin/aws"')
            self.assertFalse((missing / "aws").exists())
        finally:
            self.env["PATH"] = old_path

    def test_review3_parent_renames(self):
        for parent in (".config", "Library"):
            original = self.home / parent
            moved = self.home / "project/moved-parent"
            relative = "brnr/config.toml" if parent == ".config" else "LaunchAgents/probe.plist"
            sentinel = original / relative
            sentinel.write_text("sentinel")
            result = self.run_shell(f'mv "$HOME/{parent}" "{moved}"')
            try:
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(original.exists())
                if sys.platform == "darwin":
                    self.assertFalse(moved.exists())
                elif moved.exists():
                    # GNU mv may copy across mount points before it fails to
                    # remove the protected source. Restoring that modified
                    # copy must still fail to replace the host mount point.
                    (moved / relative).write_text("injected")
                    restore = self.run_shell(f'mv -T "{moved}" "{original}"')
                    self.assertNotEqual(restore.returncode, 0)
                self.assertEqual(sentinel.read_text(), "sentinel")
            finally:
                if moved.exists() and not original.exists():
                    moved.rename(original)
                elif moved.exists():
                    shutil.rmtree(moved)
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir(exist_ok=True)
        target = dotfiles / "zshrc"
        target.write_text("sentinel")
        rc = self.home / ".zshrc"
        rc.unlink()
        rc.symlink_to(target)
        moved = self.home / "project/df"
        try:
            result = self.run_shell('mv "$HOME/dotfiles" "$HOME/project/df" && '
                                    'echo injected >> "$HOME/project/df/zshrc"')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(), "sentinel")
        finally:
            if moved.exists() and not dotfiles.exists():
                moved.rename(dotfiles)
            rc.unlink()
            rc.write_text("# sentinel\n")

    def test_review3_and_4_homebrew_parent_launcher_and_shim(self):
        prefix = self.home / "brew"
        install = prefix / "Cellar/agent-aws/1.0.0"
        (install / "bin").mkdir(parents=True)
        (install / "share/agent-aws").mkdir(parents=True)
        script = install / "bin/agent-aws"
        script.write_text((ROOT / "bin/agent-aws").read_text().replace(
            "#!/usr/bin/env -S python3 -I", f"#!{sys.executable} -I", 1))
        script.chmod(0o700)
        profile = install / "share/agent-aws/agent-aws.sb"
        shutil.copyfile(ROOT / "share/agent-aws/agent-aws.sb", profile)
        before_profile = profile.read_text()
        (prefix / "bin").mkdir()
        launcher = prefix / "bin/agent-aws"
        launcher.symlink_to(script)
        shim = prefix / "bin/python3"
        shim.write_text('#!/bin/sh\nexit 77\n')
        shim.chmod(0o700)
        old_path = self.env["PATH"]
        old_base = self.base
        self.env["PATH"] = f"{prefix}/bin:" + old_path
        # Invoke the installed shebang directly: the poisonous python3 shim
        # must not run. All attacked paths below are disposable fixtures.
        self.__class__.base = [str(launcher), "run", "--", "/bin/sh", "-c"]
        try:
            result = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            self.assertEqual(result.returncode, 0, result.stderr)
            for command in (
                f'mv "{prefix}/Cellar/agent-aws" "{prefix}/Cellar/aa"',
                f'ln -sfn /tmp/evil "{launcher}"',
                f'echo injected >> "{shim}"',
            ):
                self.assertNotEqual(self.run_shell(command).returncode, 0, command)
            self.assertEqual(launcher.resolve(), script)
            self.assertEqual(shim.read_text(), '#!/bin/sh\nexit 77\n')
            self.assertEqual(profile.read_text(), before_profile)
        finally:
            self.env["PATH"] = old_path
            self.__class__.base = old_base

    def test_review5_additional_startup_paths(self):
        for name in (".zlogin", ".zlogout", ".bash_login", ".bash_logout"):
            path = self.home / name
            path.write_text("sentinel")
            self.denied(f'echo injected >> "$HOME/{name}"')
            self.assertEqual(path.read_text(), "sentinel")
        for name in (".config/systemd/user", ".config/autostart"):
            directory = self.home / name
            directory.mkdir(parents=True, exist_ok=True)
            self.denied(f'echo injected > "$HOME/{name}/evil"')
            self.assertFalse((directory / "evil").exists())

    def test_review6_symlinked_config_parent(self):
        conventional = self.home / ".config"
        target = self.home / "dotfiles/config"
        target.parent.mkdir(exist_ok=True)
        conventional.rename(target)
        conventional.symlink_to(target)
        config_file = target / "brnr/config.toml"
        config_file.write_text("sentinel")
        try:
            self.denied('echo injected >> "$HOME/.config/brnr/config.toml"')
            self.denied('echo injected >> "$HOME/dotfiles/config/brnr/config.toml"')
            self.assertEqual(config_file.read_text(), "sentinel")
        finally:
            conventional.unlink()
            target.rename(conventional)

    def test_round2_user_site_pth_does_not_run(self):
        probe = subprocess.run(
            [sys.executable, "-I", "-c", "import site; print(site.getusersitepackages())"],
            env=self.env, capture_output=True, text=True, check=True)
        user_site = Path(probe.stdout.strip()).resolve()
        self.assertIn(self.home, user_site.parents, "user site must stay inside scratch HOME")
        user_site.mkdir(parents=True, exist_ok=True)
        pth = user_site / "zz-agent-aws-test.pth"
        marker = self.home / "project/pth-ran"
        fake_cache = self.home / ".aws/sso/cache"
        payload = (f"import pathlib; pathlib.Path({str(marker)!r}).write_text("
                   f"str(list(pathlib.Path({str(fake_cache)!r}).iterdir())))\n")
        try:
            # Run 1 cannot persist user-site startup code; run 2 still works.
            self.denied(f"printf %s {shlex.quote(payload)} > {shlex.quote(str(pth))}")
            self.assertFalse(pth.exists())
            next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            self.assertEqual(next_run.returncode, 0, next_run.stderr)
            self.assertFalse(marker.exists())

            # Independently verify -I: preseed the scratch fixture outside the
            # sandbox. A non-isolated Python must execute it (positive control).
            pth.write_text(payload)
            subprocess.run([sys.executable, "-c", "pass"], env=self.env, check=True)
            self.assertIn("fake.json", marker.read_text())
            marker.unlink()
            next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            self.assertEqual(next_run.returncode, 0, next_run.stderr)
            self.assertFalse(marker.exists(), "source shebang executed user-site startup code")

            # The installed form must also keep -I after its absolute Python.
            installed = self.home / "project/installed"
            (installed / "bin").mkdir(parents=True)
            (installed / "share/agent-aws").mkdir(parents=True)
            script = installed / "bin/agent-aws"
            script.write_text((ROOT / "bin/agent-aws").read_text().replace(
                "#!/usr/bin/env -S python3 -I", f"#!{sys.executable} -I", 1))
            script.chmod(0o700)
            shutil.copyfile(ROOT / "share/agent-aws/agent-aws.sb",
                            installed / "share/agent-aws/agent-aws.sb")
            result = subprocess.run([str(script), "run", "--", "/bin/sh", "-c", "true"],
                                    env=self.env, cwd=self.home, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists(), "installed shebang executed user-site startup code")
        finally:
            pth.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)

    def test_round2_relative_path_warning(self):
        old_path = self.env["PATH"]
        self.env["PATH"] = old_path + ":."
        try:
            result = self.run_shell("true")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("empty or dot PATH entries protect the current directory", result.stderr)
        finally:
            self.env["PATH"] = old_path

    def test_round3_installation_site_pth_in_scratch_venv(self):
        venv = self.home / "project/site-venv"
        subprocess.run([sys.executable, "-I", "-m", "venv", "--without-pip", str(venv)],
                       env=self.env, capture_output=True, text=True, check=True)
        python = venv / "bin/python"
        probe = subprocess.run([str(python), "-I", "-c",
                                "import json, site; print(json.dumps(site.getsitepackages()))"],
                               env=self.env, capture_output=True, text=True, check=True)
        sites = [Path(name) for name in json.loads(probe.stdout)]
        self.assertTrue(sites)
        # Model Homebrew's external site directory without touching Homebrew:
        # replace only an empty scratch venv site with a link outside its prefix.
        site_dir = sites[0]
        self.assertIn(venv, site_dir.resolve().parents)
        external = self.home / "project/external-installation-site"
        external.mkdir()
        site_dir.rmdir()
        site_dir.symlink_to(external, target_is_directory=True)
        pth = external / "zz-agent-aws-test.pth"
        marker = self.home / "project/installation-pth-ran"
        payload = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('executed')\n"
        old_base = self.base
        try:
            # Positive control: -I alone does execute installation-site .pth.
            pth.write_text(payload)
            subprocess.run([str(python), "-I", "-c", "pass"], env=self.env, check=True)
            self.assertEqual(marker.read_text(), "executed")
            pth.unlink()
            marker.unlink()

            # Load the real module under this interpreter and verify all site
            # paths and resolved aliases, including the target outside prefix.
            coverage = r'''import importlib.machinery, importlib.util, pathlib, site, sys
loader = importlib.machinery.SourceFileLoader("agent_aws", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
protected = module.protected_paths()
for name in site.getsitepackages():
    for path in (pathlib.Path(name), pathlib.Path(name).resolve()):
        assert any(root == path or root in path.parents for root in protected), str(path)
'''
            subprocess.run([str(python), "-I", "-c", coverage, str(ROOT / "bin/agent-aws")],
                           env=self.env, capture_output=True, text=True, check=True)
            self.__class__.base = [str(python), "-I", str(ROOT / "bin/agent-aws"),
                                   "run", "--", "/bin/sh", "-c"]
            for path in (site_dir / pth.name, pth):
                self.denied(f"printf %s {shlex.quote(payload)} > {shlex.quote(str(path))}")
                self.assertFalse(pth.exists())
            next_run = self.run_shell('test "$AGENT_AWS_ACTIVE" = 1')
            self.assertEqual(next_run.returncode, 0, next_run.stderr)
            self.assertFalse(marker.exists())
        finally:
            self.__class__.base = old_base
            pth.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
