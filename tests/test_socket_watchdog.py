import os
import signal
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import socket_watchdog as watchdog  # noqa: E402


class FakeProbe:
    results_last = (True, "")

    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def __call__(self, path, timeout):
        self.calls += 1
        return self.results.pop(0) if self.results else self.results_last


FAIL = (False, "boom")
OK = (True, "")


class TickTests(unittest.TestCase):
    def make(self, *results, max_failures=3):
        fatal = mock.Mock()
        dog = watchdog.Watchdog("/x", max_failures=max_failures, on_fatal=fatal,
                                probe_fn=FakeProbe(*results))
        return dog, fatal

    def test_healthy_never_fatal(self):
        dog, fatal = self.make(OK, OK, OK)
        for _ in range(3):
            self.assertFalse(dog.tick())
        fatal.assert_not_called()

    def test_fatal_only_after_consecutive_failures(self):
        dog, fatal = self.make(FAIL, FAIL, FAIL)
        self.assertFalse(dog.tick())
        self.assertFalse(dog.tick())
        fatal.assert_not_called()
        self.assertTrue(dog.tick())
        fatal.assert_called_once()

    def test_success_resets_counter(self):
        dog, fatal = self.make(FAIL, FAIL, OK, FAIL, FAIL)
        for _ in range(5):
            dog.tick()
        fatal.assert_not_called()
        self.assertEqual(dog.failures, 2)

    def test_invalid_settings_rejected(self):
        with self.assertRaises(ValueError):
            watchdog.Watchdog("/x", interval=0)
        with self.assertRaises(ValueError):
            watchdog.Watchdog("/x", max_failures=0)

    def test_run_stops_after_fatal_and_on_stop(self):
        dog, fatal = self.make(FAIL, max_failures=1)
        dog.interval = 0.01
        dog.run()  # returns by itself after the fatal action
        fatal.assert_called_once()
        dog2, _ = self.make()
        dog2.stop()
        dog2.run()  # returns immediately, nothing probed
        self.assertEqual(dog2._probe.calls, 0)

    def test_run_survives_probe_exception(self):
        calls = []

        def flaky(path, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("bug")
            return FAIL

        fatal = mock.Mock()
        dog = watchdog.Watchdog("/x", interval=0.01, max_failures=1,
                                on_fatal=fatal, probe_fn=flaky)
        dog.run()
        fatal.assert_called_once()
        self.assertEqual(len(calls), 2)

    def test_default_fatal_sends_sigterm_to_own_pid(self):
        with mock.patch("os.kill") as kill:
            watchdog._terminate_self()
        kill.assert_called_once_with(os.getpid(), signal.SIGTERM)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "f.sock")
        self.addCleanup(self.dir.cleanup)

    def make_socket(self, mode=0o666):
        s = socket.socket(socket.AF_UNIX)
        s.bind(self.path)
        self.addCleanup(s.close)
        os.chmod(self.path, mode)

    def test_missing_socket(self):
        ok, reason = watchdog.probe(self.path)
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses permission checks")
    def test_permissions_reset(self):
        self.make_socket(0o444)
        ok, reason = watchdog.probe(self.path)
        self.assertFalse(ok)
        self.assertIn("permissions", reason)

    def _run(self, **kw):
        self.make_socket()
        with mock.patch("subprocess.run", **kw) as run:
            res = watchdog.probe(self.path, 5)
        return res, run

    def test_pong(self):
        res, run = self._run(return_value=mock.Mock(returncode=0, stdout="Server replied: pong\n", stderr=""))
        self.assertEqual(res, (True, ""))
        self.assertEqual(run.call_args[0][0], ["fail2ban-client", "-s", self.path, "ping"])

    def test_ping_error(self):
        (ok, reason), _ = self._run(return_value=mock.Mock(returncode=255, stdout="", stderr="a\nFailed to access socket\n"))
        self.assertFalse(ok)
        self.assertIn("Failed to access socket", reason)

    def test_ping_timeout(self):
        import subprocess
        (ok, reason), _ = self._run(side_effect=subprocess.TimeoutExpired("x", 5))
        self.assertFalse(ok)
        self.assertIn("timed out", reason)

    def test_client_missing(self):
        (ok, reason), _ = self._run(side_effect=FileNotFoundError())
        self.assertFalse(ok)
        self.assertIn("not found", reason)


class EnvTests(unittest.TestCase):
    def test_disabled(self):
        with mock.patch.dict(os.environ, {"WATCHDOG_ENABLED": "False"}):
            self.assertIsNone(watchdog.start_from_env())

    def test_env_number(self):
        with mock.patch.dict(os.environ, {"A": "abc", "B": "-1", "C": "7", "D": ""}):
            self.assertEqual(watchdog._env_number("A", 30.0, float), 30.0)
            self.assertEqual(watchdog._env_number("B", 3, int), 3)
            self.assertEqual(watchdog._env_number("C", 3, int), 7)
            self.assertEqual(watchdog._env_number("D", 3, int), 3)
            self.assertEqual(watchdog._env_number("MISSING", 3, int), 3)

    def test_start_uses_env(self):
        env = {"WATCHDOG_INTERVAL": "3600", "WATCHDOG_FAILURES": "5", "FAIL2BAN_SOCKET": "/s"}
        with mock.patch.dict(os.environ, env):
            dog = watchdog.start_from_env()
        self.addCleanup(dog.stop)
        self.assertEqual((dog.interval, dog.max_failures, dog.socket_path), (3600.0, 5, "/s"))


if __name__ == "__main__":
    unittest.main()
