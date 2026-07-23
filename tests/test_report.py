import json
import tempfile
import unittest
from pathlib import Path

from detfuzz.report import (
    build_evidence_manifest,
    build_suite_report,
    load_suite_results,
    render_markdown_report,
    sha256_file,
    write_report_bundle,
)


class ReportTests(unittest.TestCase):
    def test_sha256_file_hashes_file_content(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "evidence.txt"
            path.write_text("detfuzz", encoding="utf-8")

            digest = sha256_file(path)

            self.assertEqual(
                digest,
                "917f81f90e57b9f5fdf271571c3f05f83b45b4e91f16e00ed458413121ecf417",
            )

    def test_build_evidence_manifest_records_relative_paths_sizes_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root) / "evidence"
            evidence.mkdir()
            (evidence / "event.xml").write_text("<Event />", encoding="utf-8")

            manifest = build_evidence_manifest(evidence)

            self.assertEqual(manifest.root, str(evidence.resolve()))
            self.assertEqual(len(manifest.files), 1)
            self.assertEqual(manifest.files[0].path, "event.xml")
            self.assertGreater(manifest.files[0].size_bytes, 0)

    def test_build_suite_report_counts_classifications(self) -> None:
        suite_results = {
            "suite_id": "suite-1",
            "suite_status": "COMPLETED",
            "abort_reason": None,
            "cases": [
                {"case_id": "B0", "classification": "DETECTED"},
                {"case_id": "M1", "classification": "VALID_BYPASS"},
                {"case_id": "M2", "classification": "VALID_BYPASS"},
            ],
        }
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root)
            (evidence / "event.xml").write_text("<Event />", encoding="utf-8")
            manifest = build_evidence_manifest(evidence)

            report = build_suite_report(
                suite_results, manifest, generated_at_utc="2026-07-21T00:00:00+00:00"
            )

            self.assertEqual(report["case_count"], 3)
            self.assertEqual(report["suite_status"], "COMPLETED")
            self.assertIsNone(report["abort_reason"])
            self.assertEqual(report["classification_counts"]["DETECTED"], 1)
            self.assertEqual(report["classification_counts"]["VALID_BYPASS"], 2)

    def test_render_markdown_report_includes_cases_and_hashes(self) -> None:
        report = {
            "suite_id": "suite-1",
            "suite_status": "COMPLETED",
            "generated_at_utc": "2026-07-21T00:00:00+00:00",
            "case_count": 1,
            "classification_counts": {"DETECTED": 1},
            "cases": [{"case_id": "B0", "classification": "DETECTED"}],
            "evidence_manifest": {
                "files": [
                    {
                        "path": "event.xml",
                        "size_bytes": 9,
                        "sha256": "abc123",
                    }
                ]
            },
        }

        markdown = render_markdown_report(report)

        self.assertIn("# DetFuzz Evidence Report", markdown)
        self.assertIn("`B0`: `DETECTED`", markdown)
        self.assertIn("sha256 `abc123`", markdown)

    def test_write_report_bundle_writes_json_markdown_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            evidence = workspace / "evidence"
            output = workspace / "reports"
            evidence.mkdir()
            (evidence / "event.xml").write_text("<Event />", encoding="utf-8")
            suite_results = workspace / "suite-results.json"
            suite_results.write_text(
                json.dumps(
                    {
                        "suite_id": "suite-1",
                        "cases": [{"case_id": "B0", "classification": "DETECTED"}],
                    }
                ),
                encoding="utf-8",
            )

            paths = write_report_bundle(suite_results, evidence, output)

            self.assertTrue(paths["json_report"].exists())
            self.assertTrue(paths["markdown_report"].exists())
            self.assertTrue(paths["evidence_manifest"].exists())

    def test_write_report_bundle_defaults_missing_suite_status_to_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            evidence = workspace / "evidence"
            evidence.mkdir()
            suite_results = workspace / "suite-results.json"
            suite_results.write_text(
                json.dumps(
                    {
                        "suite_id": "suite-without-status",
                        "cases": [],
                    }
                ),
                encoding="utf-8",
            )

            paths = write_report_bundle(
                suite_results,
                evidence,
                workspace / "reports",
            )
            report = json.loads(paths["json_report"].read_text(encoding="utf-8"))

            self.assertEqual(report["suite_status"], "UNKNOWN")

    def test_load_suite_results_accepts_utf8_bom(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "suite-results.json"
            path.write_text(
                '\ufeff{"suite_id":"suite-1","cases":[]}',
                encoding="utf-8",
            )

            payload = load_suite_results(path)

            self.assertEqual(payload["suite_id"], "suite-1")


if __name__ == "__main__":
    unittest.main()
