"""Tests for imgscan covering the six acceptance criteria.

The fixture layout is generated with demo.build_layout.build_layout into a
temporary directory, so the analyzer is exercised against a real OCI
layout on disk (gzip layer 0, plain-tar layer 1, whiteout in layer 1).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from demo.build_layout import build_layout  # noqa: E402
from imgscan import report as report_mod  # noqa: E402
from imgscan.cli import main as cli_main  # noqa: E402

FINDING_FIELDS = ("kind", "path", "layer_index", "layer_digest", "mode", "detail")


def _find(findings, kind, path):
    return [f for f in findings if f["kind"] == kind and f["path"] == path]


class ImgscanFixtureTest(unittest.TestCase):
    """Criterion 1: build a two-layer OCI layout and analyze it."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="imgscan-test-")
        cls.layout_dir = os.path.join(cls.tmpdir, "layout")
        build_layout(cls.layout_dir)
        cls.report = report_mod.build_report(cls.layout_dir)
        cls.findings = cls.report["findings"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_fixture_layout_structure(self):
        # index.json, oci-layout and content-addressed blobs exist.
        self.assertTrue(os.path.isfile(os.path.join(self.layout_dir, "index.json")))
        blobs = os.path.join(self.layout_dir, "blobs", "sha256")
        self.assertTrue(os.path.isdir(blobs))
        self.assertGreaterEqual(len(os.listdir(blobs)), 4)  # 2 layers+config+manifest

    def test_env_sensitive_finding_in_layer_0(self):
        # Criterion 2a: .env reported as sensitive, found in layer 0.
        hits = _find(self.findings, "sensitive_file", ".env")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["layer_index"], 0)
        self.assertTrue(hits[0]["layer_digest"].startswith("sha256:"))

    def test_id_rsa_world_readable_finding(self):
        # Criterion 2b: id_rsa in layer 0, mode 0644, world-readable flagged.
        hits = _find(self.findings, "sensitive_file", "id_rsa")
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["layer_index"], 0)
        self.assertEqual(hit["mode"], "0644")
        self.assertIn("world-readable", hit["detail"])

    def test_env_whiteout_deletion_recoverable(self):
        # Criterion 2c: .env deleted by whiteout in layer 1, still recoverable.
        hits = _find(self.findings, "whiteout_deleted", ".env")
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["layer_index"], 1)
        self.assertIn("layer 0", hit["detail"])
        self.assertIn("recoverable", hit["detail"])

    def test_final_file_listing(self):
        # Criterion 3: .env gone from final image; app.py and id_rsa remain.
        final_files = self.report["final_files"]
        self.assertNotIn(".env", final_files)
        self.assertIn("app.py", final_files)
        self.assertIn("id_rsa", final_files)
        self.assertEqual(self.report["summary"]["final_files"], 2)

    def test_root_user_finding(self):
        # Criterion 4: empty User in config means running as root.
        hits = _find(self.findings, "root_user", None)
        self.assertEqual(len(hits), 1)
        self.assertIn("root", hits[0]["detail"])

    def test_layout_files_not_reported(self):
        # Criterion 5: layout bookkeeping files are not image content.
        for finding in self.findings:
            path = finding["path"]
            if path is None:
                continue
            self.assertNotIn("blobs", path.split("/"))
            self.assertNotIn(path, ("index.json", "manifest.json", "oci-layout"))
        for name in ("index.json", "manifest.json", "oci-layout"):
            self.assertNotIn(name, self.report["final_files"])

    def test_finding_fields_and_summary(self):
        # Criterion 6: six fields per finding; summary matches reality.
        self.assertGreaterEqual(len(self.findings), 4)
        for finding in self.findings:
            for field_name in FINDING_FIELDS:
                self.assertIn(field_name, finding)
            self.assertEqual(set(finding.keys()), set(FINDING_FIELDS))
        summary = self.report["summary"]
        self.assertEqual(summary["layers"], 2)
        self.assertEqual(summary["final_files"], len(self.report["final_files"]))
        self.assertEqual(summary["findings"], len(self.findings))


class ImgscanCliTest(unittest.TestCase):
    """The CLI writes the JSON report and prints a one-line summary."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="imgscan-cli-")
        self.layout_dir = os.path.join(self.tmpdir, "layout")
        build_layout(self.layout_dir)
        self.out_path = os.path.join(self.tmpdir, "out", "report.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cli_writes_report_and_prints_summary(self):
        from io import StringIO
        captured = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            rc = cli_main(["--layout", self.layout_dir, "--out", self.out_path])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        line = captured.getvalue().strip()
        self.assertIn("layers=2", line)
        self.assertIn("final_files=2", line)
        self.assertIn("findings=4", line)
        with open(self.out_path, "r", encoding="utf-8") as handle:
            written = json.load(handle)
        self.assertEqual(written["summary"]["layers"], 2)
        self.assertEqual(written["summary"]["final_files"], 2)
        self.assertEqual(written["summary"]["findings"], len(written["findings"]))


class ImgscanGenericTest(unittest.TestCase):
    """Layering logic must not depend on the demo fixture's file names."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="imgscan-generic-")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build_layout(self, layers, user=""):
        """Assemble an arbitrary OCI layout from in-memory tar layers."""
        import hashlib
        import io
        import tarfile

        def make_tar(entries):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                for name, mode, content in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mode = mode
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
            return buffer.getvalue()

        def digest(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()

        layout_dir = os.path.join(self.tmpdir, "layout-generic")
        blobs_dir = os.path.join(layout_dir, "blobs", "sha256")
        os.makedirs(blobs_dir)

        def write_blob(data):
            blob_digest = digest(data)
            with open(os.path.join(blobs_dir, blob_digest.split(":", 1)[1]), "wb") as handle:
                handle.write(data)
            return blob_digest, len(data)

        layer_descriptors = []
        diff_ids = []
        for entries in layers:
            blob = make_tar(entries)
            blob_digest, size = write_blob(blob)
            diff_ids.append(blob_digest)
            layer_descriptors.append({
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": blob_digest,
                "size": size,
            })

        config = {
            "architecture": "amd64",
            "os": "linux",
            "config": {"User": user},
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        }
        config_bytes = json.dumps(config).encode("utf-8")
        config_digest, config_size = write_blob(config_bytes)
        manifest = {
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": config_size},
            "layers": layer_descriptors,
        }
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        manifest_digest, manifest_size = write_blob(manifest_bytes)
        index = {"schemaVersion": 2, "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest, "size": manifest_size}]}
        with open(os.path.join(layout_dir, "index.json"), "w") as handle:
            json.dump(index, handle)
        return layout_dir

    def test_subdirectory_whiteout_and_readd(self):
        layout_dir = self._build_layout([
            [("etc/secret.conf", 0o600, b"password=hunter2"),
             ("etc/keep.conf", 0o644, b"ok=1")],
            [("etc/.wh.secret.conf", 0o000, b"")],
            [("etc/secret.conf", 0o600, b"password=again")],
        ], user="appuser")
        report = report_mod.build_report(layout_dir)
        findings = report["findings"]

        # secret.conf seen in layers 0 and 2, deleted in layer 1.
        sensitive = _find(findings, "sensitive_file", "etc/secret.conf")
        self.assertEqual([f["layer_index"] for f in sensitive], [0, 2])
        deleted = _find(findings, "whiteout_deleted", "etc/secret.conf")
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["layer_index"], 1)

        # Final image contains the re-added file; keep.conf survives.
        self.assertIn("etc/secret.conf", report["final_files"])
        self.assertIn("etc/keep.conf", report["final_files"])
        self.assertEqual(report["summary"]["layers"], 3)

        # Non-root user means no root_user finding.
        self.assertEqual(_find(findings, "root_user", None), [])

    def test_opaque_directory_whiteout(self):
        layout_dir = self._build_layout([
            [("var/cache/a.tmp", 0o644, b"a"),
             ("var/cache/b.tmp", 0o644, b"b"),
             ("var/other", 0o644, b"c")],
            [("var/cache/.wh..wh..opq", 0o000, b"")],
        ])
        report = report_mod.build_report(layout_dir)
        self.assertNotIn("var/cache/a.tmp", report["final_files"])
        self.assertNotIn("var/cache/b.tmp", report["final_files"])
        self.assertIn("var/other", report["final_files"])
        deleted_paths = {f["path"] for f in report["findings"]
                         if f["kind"] == "whiteout_deleted"}
        self.assertEqual(deleted_paths, {"var/cache/a.tmp", "var/cache/b.tmp"})


if __name__ == "__main__":
    unittest.main()
