"""Host disk guard regression: never contact Docker with either filesystem full."""
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("run.sh").resolve()


class DiskGuardTest(unittest.TestCase):
    def test_each_filesystem_and_threshold(self):
        for low in ("work", "temp", "none"):
            with self.subTest(low=low), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                work, temp = root / "work with spaces", root / "temporary with spaces"
                work.mkdir()
                temp.mkdir()
                df = root / "df"
                df.write_text(
                    '#!/bin/sh\nprintf "Filesystem 1024-blocks Used Available Capacity Mounted on\\n"\n'
                    'available=10485760\n'
                    f'case "$*" in *"{work if low == "work" else temp if low == "temp" else "/never"}"*) available=10485759;; esac\n'
                    'printf "/dev/mock 20000000 1 %s 1%% /mock\\n" "$available"\n'
                )
                docker = root / "docker"
                marker = root / "docker-called"
                docker.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 73\n')
                df.chmod(0o755)
                docker.chmod(0o755)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], TMPDIR=str(temp))
                run = subprocess.run(["sh", str(SCRIPT)], cwd=work, env=env, capture_output=True, text=True)
                if low == "none":
                    self.assertEqual(run.returncode, 73)
                    self.assertTrue(marker.exists())
                else:
                    self.assertEqual(run.returncode, 1)
                    self.assertIn("不足 10GB", run.stderr)
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
