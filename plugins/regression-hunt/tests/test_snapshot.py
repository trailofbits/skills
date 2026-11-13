"""Behavioral tests for deterministic, read-only Git snapshot preparation."""

import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from snapshot import _extract_archive, snapshot


class SnapshotTests(unittest.TestCase):
    """Exercise real repositories and malicious archive entries."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.run_git("init", "--quiet", "--initial-branch=main")
        self.run_git("config", "user.name", "Snapshot Tests")
        self.run_git("config", "user.email", "snapshot@example.invalid")
        self.s0 = self.commit("before\n", "Baseline")
        self.s1 = self.commit("after\n", "Candidate")
        self.output = self.root / "result"

    def run_git(self, *arguments: str) -> str:
        """Run fixture setup or inspection commands without relying on helper code."""
        return subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def commit(self, content: str, message: str) -> str:
        """Commit the current fixture files and return the full revision."""
        (self.repository / "source.txt").write_text(content)
        self.run_git("add", ".")
        self.run_git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
        return self.run_git("rev-parse", "HEAD")

    def test_exports_pinned_trees_patch_and_range_messages_without_mutating_source(self) -> None:
        (self.repository / "binary").write_bytes(b"\x00\x01\x02")
        (self.repository / "link").symlink_to("source.txt")
        s1 = self.commit("final\n", "Final candidate")
        (self.repository / "source.txt").write_text("dirty source\n")
        (self.repository / "untracked").write_text("leave alone\n")
        original_status = self.run_git("status", "--porcelain")

        snapshot(self.repository, self.s0[:12], "HEAD", self.output)

        metadata = json.loads((self.output / "source.json").read_text())
        self.assertEqual(metadata["repository"], str(self.repository.resolve()))
        self.assertEqual(metadata["s0"], self.s0)
        self.assertEqual(metadata["s1"], s1)
        self.assertEqual(metadata["tree0"], self.run_git("rev-parse", f"{self.s0}^{{tree}}"))
        self.assertEqual(metadata["tree1"], self.run_git("rev-parse", f"{s1}^{{tree}}"))
        self.assertEqual((self.output / "S0/source.txt").read_text(), "before\n")
        self.assertEqual((self.output / "S1/source.txt").read_text(), "final\n")
        self.assertEqual((self.output / "S1/binary").read_bytes(), b"\x00\x01\x02")
        self.assertTrue((self.output / "S1/link").is_symlink())
        self.assertEqual((self.output / "S1/link").read_text(), "final\n")
        self.assertFalse(list(self.output.rglob(".git")))
        patch = (self.output / "change.patch").read_text()
        self.assertIn("-before\n+final", patch)
        self.assertIn("GIT binary patch", patch)
        messages = (self.output / "change-message.txt").read_text()
        self.assertIn("Candidate", messages)
        self.assertIn("Final candidate", messages)
        self.assertEqual(self.run_git("status", "--porcelain"), original_status)
        self.assertEqual((self.repository / "source.txt").read_text(), "dirty source\n")
        self.assertEqual((self.repository / "untracked").read_text(), "leave alone\n")

    def test_invalid_and_identical_revisions_do_not_create_output(self) -> None:
        for revision in ("missing-ref", "--help", self.s0):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                snapshot(self.repository, self.s0, revision, self.output)
            self.assertFalse(self.output.exists())
            self.assertFalse(list(self.root.glob(".result-*")))

    def test_existing_output_is_preserved(self) -> None:
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_text("preserve\n")
        with self.assertRaisesRegex(ValueError, "already exists"):
            snapshot(self.repository, self.s0, self.s1, self.output)
        self.assertEqual(sentinel.read_text(), "preserve\n")

    def test_dangling_output_symlink_is_rejected(self) -> None:
        self.output.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "already exists"):
            snapshot(self.repository, self.s0, self.s1, self.output)
        self.assertTrue(self.output.is_symlink())

    def test_output_in_source_checkout_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the source checkout"):
            snapshot(self.repository, self.s0, self.s1, self.repository / "result")
        self.assertEqual(self.run_git("status", "--porcelain"), "")

    def test_missing_parent_does_not_create_output(self) -> None:
        with self.assertRaises(FileNotFoundError):
            snapshot(self.repository, self.s0, self.s1, self.root / "absent/result")
        self.assertFalse((self.root / "absent").exists())

    def test_lfs_failure_removes_staged_output(self) -> None:
        pointer = (
            "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 4\n"
        )
        s1 = self.commit(pointer, "LFS pointer")
        with self.assertRaisesRegex(ValueError, "Git LFS pointer"):
            snapshot(self.repository, self.s0, s1, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".result-*")))

    def test_submodules_are_rejected(self) -> None:
        self.run_git("update-index", "--add", "--cacheinfo", f"160000,{self.s0},dependency")
        self.run_git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Submodule")
        with self.assertRaisesRegex(ValueError, "contains submodules"):
            snapshot(self.repository, self.s0, "HEAD", self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".result-*")))

    def test_export_attributes_are_rejected_instead_of_altering_snapshots(self) -> None:
        for attribute in ("export-ignore", "export-subst"):
            with self.subTest(attribute=attribute):
                (self.repository / ".gitattributes").write_text(f"source.txt {attribute}\n")
                revision = self.commit("candidate\n", attribute)
                with self.assertRaisesRegex(ValueError, "Git archive would alter"):
                    snapshot(self.repository, self.s0, revision, self.output)
                self.assertFalse(self.output.exists())
                self.assertFalse(list(self.root.glob(".result-*")))

    def test_reverse_range_retains_candidate_message(self) -> None:
        snapshot(self.repository, self.s1, self.s0, self.output)
        message = (self.output / "change-message.txt").read_text()
        self.assertIn("Selected range has no commits", message)
        self.assertIn("Baseline", message)

    def test_unsafe_archive_paths_and_links_cannot_escape(self) -> None:
        cases = [
            ("../escape", None),
            (str(self.root / "escape"), None),
            (".git/config", None),
            ("link", "../escape"),
            ("link", str(self.root / "escape")),
        ]
        for name, target in cases:
            with self.subTest(name=name, target=target):
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode="w") as contents:
                    member = tarfile.TarInfo(name)
                    if target is not None:
                        member.type = tarfile.SYMTYPE
                        member.linkname = target
                    contents.addfile(member)
                archive.seek(0)
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    _extract_archive(archive, self.root / "extracted")
                self.assertFalse((self.root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
