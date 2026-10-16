"""Real sandbox acceptance with a scratch HOME and a fake aws executable.

No login or AWS request is made. Run on macOS with:
    python3 -m unittest discover -s tests -p test_sandbox.py -v
On Linux the same fixture exercises bwrap when it is installed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_security import ROOT, config

SUPPORTED = sys.platform == "darwin" or (sys.platform.startswith("linux") and shutil.which("bwrap"))


@unittest.skipUnless(SUPPORTED, "requires sandbox-exec or bwrap")
class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="sandbox-check-", dir="/tmp")
        cls.home = Path(cls.tmp.name).resolve()
        cls.env = dict(os.environ, HOME=str(cls.home))
        for relative in (".aws/sso/cache", ".agent-aws", "Library/LaunchAgents", ".config/brnr", "bin", "project"):
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
        fake_aws.write_text(f"#!{sys.executable}\n" + '''import json, sys
if sys.argv[1:3] != ["sso", "get-role-credentials"]:
    sys.exit("unexpected fake AWS call")
print(json.dumps({"roleCredentials": {"accessKeyId": "FAKE-KEY",
    "secretAccessKey": "FAKE-SECRET", "sessionToken": "FAKE-SESSION"}}))
''')
        fake_aws.chmod(0o700)
        cls.env["PATH"] = f"{cls.home}/bin:" + os.environ["PATH"]
        cls.base = [sys.executable, str(ROOT / "bin/agent-aws"), "run", "--", "/bin/sh", "-c"]
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
        ], env=self.env, cwd=self.home, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
                self.denied('cat /tmp/agent-aws.*/credentials')
                self.denied(f'cat "{Path(other_creds).resolve()}"')
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


if __name__ == "__main__":
    unittest.main()
