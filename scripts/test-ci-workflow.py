#!/usr/bin/env python3
"""Test the actual workflow Bash policy without GitHub, Docker or credentials."""
import datetime
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def step(step_id):
    """Read one fixed-indent step; fail closed if its YAML structure changes."""
    text = WORKFLOW.read_text()
    marker = "        id: " + step_id + "\n"
    if text.count(marker) != 1:
        raise AssertionError("expected exactly one step: " + step_id)
    tail = text.split(marker, 1)[1]
    block = re.split(r"\n      - ", tail, maxsplit=1)[0]
    run = block.split("        run: |\n", 1)[1]
    lines = run.rstrip().splitlines()
    if not all(line.startswith("          ") or not line for line in lines):
        raise AssertionError("unexpected run indentation")
    return block, "\n".join(line[10:] for line in lines) + "\n"


class WorkflowPolicy(unittest.TestCase):
    def test_publish_matrix(self):
        _, script = step("plan")
        commit = "0123456789abcdef0123456789abcdef01234567"
        cases = [
            ("push", "refs/heads/main", "branch", "main", False),
            ("push", "refs/heads/feature/a", "branch", "feature/a", False),
            ("push", "refs/heads/v1.2.3", "branch", "v1.2.3", False),
            ("push", "refs/tags/v1.2.3", "tag", "v1.2.3", True),
            ("pull_request", "refs/pull/12/merge", "branch", "12/merge", False),
            # A PR may never publish, even if a caller were to supply main/tag refs.
            ("pull_request", "refs/heads/main", "branch", "main", False),
            ("pull_request", "refs/tags/v1.2.3", "tag", "v1.2.3", False),
            ("workflow_dispatch", "refs/heads/main", "branch", "main", False),
            ("workflow_dispatch", "refs/tags/v2.0.0", "tag", "v2.0.0", True),
            ("workflow_dispatch", "refs/heads/test", "branch", "test", False),
            ("workflow_dispatch", "refs/tags/test", "tag", "test", False),
        ]
        for event, ref, kind, name, publish in cases:
            with self.subTest(event=event, ref=ref), tempfile.TemporaryDirectory() as tmp:
                output = pathlib.Path(tmp) / "outputs"
                env = {**os.environ, "EVENT_NAME": event, "REF": ref,
                       "REF_TYPE": kind, "REF_NAME": name, "COMMIT": commit,
                       "GITHUB_OUTPUT": str(output)}
                subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, check=True)
                values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                self.assertEqual(values["publish"], str(publish).lower())
                self.assertEqual(values["latest"], str(publish and bool(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", name))).lower())
                self.assertEqual(values["platforms"], "linux/amd64,linux/arm64" if publish or (event != "pull_request" and ref == "refs/heads/main") else "linux/amd64")
                self.assertEqual(values["version"], name if kind == "tag" else "sha-0123456")
                self.assertEqual(values["commit"], commit)
                datetime.datetime.strptime(values["build_time"], "%Y-%m-%dT%H:%M:%SZ")

    def test_release_tags(self):
        _, script = step("plan")
        for tag, valid, latest in [("v1.0.0", True, True), ("v1.2.3", True, True), ("v0.0.0", True, True),
                ("v1.1.0-rc.1", True, False), ("v1.2.3-rc.1", True, False), ("v1.2.3-alpha", True, False),
                ("v1.0", False, False), ("v01.2.3", False, False), ("v1.2", False, False),
                ("v1.2.3-01", False, False), ("vbad", False, False),
                ("v1.2.3-", False, False), ("v1.2.3+meta", False, False)]:
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as tmp:
                output = pathlib.Path(tmp) / "outputs"
                env = {**os.environ, "EVENT_NAME": "push", "REF": "refs/tags/"+tag,
                       "REF_TYPE": "tag", "REF_NAME": tag, "COMMIT": "abcdef0123456789",
                       "GITHUB_OUTPUT": str(output)}
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, valid)
                if valid:
                    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                    self.assertEqual(values["latest"], str(latest).lower())
                    self.assertEqual(values["publish"], "true")
                else:
                    self.assertFalse(output.exists())

    def test_missing_credentials_fail_without_leaks(self):
        block, script = step("credentials")
        self.assertIn("if: steps.plan.outputs.publish == 'true'", block)
        for user, token in [("", ""), ("user-not-to-print", ""),
                            ("", "token-not-to-print"), ("user-not-to-print", "token-not-to-print")]:
            with self.subTest(user=bool(user), token=bool(token)):
                env = {**os.environ, "DOCKERHUB_USERNAME": user, "DOCKERHUB_TOKEN": token}
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)
                text = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0 if user and token else 1)
                if not (user and token):
                    self.assertIn("镜像发布失败", text)
                    self.assertIn("DOCKERHUB_USERNAME", text)
                    self.assertIn("DOCKERHUB_TOKEN", text)
                self.assertNotIn("user-not-to-print", text)
                self.assertNotIn("token-not-to-print", text)

    def test_workflow_guardrails(self):
        text = WORKFLOW.read_text()
        self.assertEqual(len(list((ROOT / ".github/workflows").glob("*.y*ml"))), 1)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target", text)
        self.assertIn("branches: [\"**\"]", text)
        self.assertIn('tags: ["v*"]', text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("needs: [go, web]", text)
        self.assertIn("run: sh scripts/check-examples.sh", text)
        condition = "github.event_name != 'pull_request' && startsWith(github.ref, 'refs/tags/v')"
        self.assertIn("group: ${{ github.workflow }}-${{ " + condition + " && 'publish' || github.ref }}", text)
        self.assertIn("cancel-in-progress: ${{ !(" + condition + ") }}", text)
        self.assertIn("type=raw,value=latest,enable=${{ steps.plan.outputs.latest == 'true' }}", text)
        self.assertIn("type=raw,value=${{ github.ref_name }},enable=${{ steps.plan.outputs.publish == 'true' && steps.plan.outputs.latest != 'true' }}", text)
        self.assertIn("type=semver,pattern={{version}},enable=${{ steps.plan.outputs.latest == 'true' }}", text)
        self.assertNotIn("{{major}}.{{minor}}", text)
        self.assertNotIn("type=sha", text)
        self.assertIn("type=oci,dest={0}/authgo-image-multiarch.tar", text)
        self.assertIn("contains(steps.plan.outputs.platforms, ',')", text)
        for action in re.findall(r"uses: (\S+)", text):
            self.assertRegex(action, r"^(actions|docker)/[a-z-]+@v[0-9]+$")
        # Each side effect is gated independently; forks/PRs cannot log in or push.
        login = text.split("      - name: Log in to Docker Hub\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: steps.plan.outputs.publish == 'true'", login)
        self.assertIn("push: ${{ steps.plan.outputs.publish == 'true' }}", text)
        self.assertIn("platforms: ${{ steps.plan.outputs.platforms }}", text)
        self.assertIn("type=docker,dest={0}/authgo-image-amd64.tar", text)
        for title in ("Compress test image", "Upload test image"):
            block = text.split("      - name: " + title + "\n", 1)[1].split("      - name:", 1)[0]
            self.assertIn("if: steps.plan.outputs.publish != 'true'", block)
        for expected in ("authgo-image-amd64", "authgo-image-multiarch", "retention-days: 3", "if-no-files-found: error",
                         "cache-from: type=gha", "cache-to: type=gha", "flavor: latest=false",
                         "type=semver,pattern={{version}}",
                         "type=raw,value=latest", "go-version-file: server/go.mod",
                         "make build-stubs", "server sdk/go examples/basic pack"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
