from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "fuzz_accumulation", ROOT / "tools" / "quality" / "fuzz_accumulation.py"
)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class FuzzAccumulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.targets, self.threshold, self.campaign_sha256 = ledger._campaign()
        self.workers = {
            f"worker-{index:02d}": {
                "active_from": 1,
                "active_until": 4_000_000_000,
            }
            for index in range(len(self.targets))
        }
        self.authority = {
            "campaign_sha256": self.campaign_sha256,
            "workers": self.workers,
        }

    @staticmethod
    def signature_verifier(
        _receipt: dict[str, Any], _signature: dict[str, Any], _worker: dict[str, Any]
    ) -> None:
        return None

    def receipt(
        self,
        label: str,
        *,
        target: str | None = None,
        worker: str = "worker-00",
        started: int = 1_000,
        seconds: int = 86_400,
        outcome: str = "clean",
        defect_kind: str | None = None,
        artifacts: int = 0,
        candidate_revision: str = "1" * 40,
        binary: str | None = None,
        corpus_before: str | None = None,
        corpus_after: str | None = None,
    ) -> dict[str, Any]:
        selected_target = target or self.targets[0]
        receipt = {
            "schema_version": ledger.RECEIPT_SCHEMA,
            "receipt_id": ledger.ZERO_DIGEST,
            "candidate": {
                "revision": candidate_revision,
                "tree": "2" * 40,
                "source_sha256": "3" * 64,
            },
            "target": selected_target,
            "worker_id": worker,
            "started_at": started,
            "finished_at": started + max(seconds, 1),
            "clean_cpu_seconds": seconds if outcome == "clean" else 0,
            "outcome": outcome,
            "defect_kind": defect_kind,
            "crash_artifact_count": artifacts,
            "private_mutable_corpus": True,
            "bindings": {
                "binary_sha256": binary or digest(f"binary:{selected_target}"),
                "toolchain_sha256": digest("toolchain"),
                "sanitizer": "address",
                "target_source_sha256": digest(f"source:{selected_target}"),
                "campaign_sha256": self.campaign_sha256,
                "corpus_before_sha256": corpus_before or digest(f"before:{label}"),
                "corpus_after_sha256": corpus_after or digest(f"after:{label}"),
            },
        }
        receipt["receipt_id"] = ledger._receipt_content_id(receipt)
        return receipt

    def entries(self, receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        previous = ledger.ZERO_DIGEST
        appended = 0
        for sequence, receipt in enumerate(receipts, start=1):
            appended = max(appended, receipt["finished_at"])
            entry = {
                "schema_version": ledger.ENTRY_SCHEMA,
                "sequence": sequence,
                "previous_entry_sha256": previous,
                "appended_at": appended,
                "receipt": receipt,
                "signature": {"signed_at": receipt["finished_at"]},
            }
            entries.append(entry)
            previous = ledger._sha256_bytes(ledger.canonical_json_bytes(entry))
        return entries

    def validate(
        self, receipts: list[dict[str, Any]], *, require_threshold: bool = False
    ) -> dict[str, Any]:
        entries = self.entries(receipts)
        now = max((entry["appended_at"] for entry in entries), default=0)
        return ledger.validate_entries(
            entries,
            self.authority,
            require_threshold=require_threshold,
            signature_verifier=self.signature_verifier,
            now=now,
        )

    def complete_receipts(self) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        previous_corpora: dict[str, str] = {}
        for run in range(7):
            for target_index, target in enumerate(self.targets):
                worker = f"worker-{target_index:02d}"
                label = f"{target}:{run}"
                after = digest(f"after:{label}")
                receipt = self.receipt(
                    label,
                    target=target,
                    worker=worker,
                    started=1_000 + run * 86_400,
                    corpus_before=previous_corpora.get(target),
                    corpus_after=after,
                )
                receipts.append(receipt)
                previous_corpora[target] = after
        return receipts

    def test_exact_nineteen_target_threshold_and_aggregate_reconcile(self) -> None:
        summary = self.validate(self.complete_receipts(), require_threshold=True)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["campaign"]["target_count"], 19)
        self.assertEqual(summary["metrics"]["fuzz.total_seconds"], 19 * self.threshold)
        self.assertEqual(summary["metrics"]["fuzz.unresolved_defect_count"], 0)
        for target in self.targets:
            self.assertEqual(
                summary["metrics"][f"fuzz.target_seconds.{target}"],
                self.threshold,
            )

    def test_missing_or_under_time_target_cannot_qualify(self) -> None:
        receipts = self.complete_receipts()
        receipts.pop()
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "incomplete"):
            self.validate(receipts, require_threshold=True)

    def test_duplicate_receipt_and_mixed_candidate_are_rejected(self) -> None:
        first = self.receipt("first")
        replay = deepcopy(first)
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "duplicate or replayed"):
            self.validate([first, replay])

        reidentified = deepcopy(first)
        reidentified["receipt_id"] = digest("alternate-receipt-id")
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "content digest"):
            self.validate([reidentified])

        mixed = self.receipt("mixed", started=91_000, candidate_revision="4" * 40)
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "mixes release candidates"):
            self.validate([first, mixed])

    def test_untrusted_worker_and_clock_overlap_are_rejected(self) -> None:
        untrusted = self.receipt("untrusted", worker="unknown-worker")
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "untrusted worker"):
            self.validate([untrusted])

        first = self.receipt("one", started=1_000)
        overlapping = self.receipt("two", target=self.targets[1], started=2_000)
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "overlap or reverse"):
            self.validate([first, overlapping])

    def test_stale_binary_and_corrupt_corpus_lineage_are_rejected(self) -> None:
        first_after = digest("first-after")
        first = self.receipt("first", corpus_after=first_after)
        stale_binary = self.receipt(
            "stale",
            started=90_000,
            binary=digest("substituted-binary"),
            corpus_before=first_after,
        )
        with self.assertRaisesRegex(
            ledger.FuzzLedgerError, "binary, toolchain, or source"
        ):
            self.validate([first, stale_binary])

        corrupt = self.receipt(
            "corrupt",
            started=90_000,
            corpus_before=digest("not-the-prior-corpus"),
        )
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "corpus lineage"):
            self.validate([first, corrupt])

    def test_defect_invalidates_target_and_forbids_later_accumulation(self) -> None:
        first_after = digest("first-after")
        first = self.receipt("first", corpus_after=first_after)
        defect_after = digest("defect-after")
        defect = self.receipt(
            "defect",
            started=90_000,
            outcome="defect",
            defect_kind="sanitizer",
            artifacts=1,
            seconds=1,
            corpus_before=first_after,
            corpus_after=defect_after,
        )
        summary = self.validate([first, defect])
        self.assertEqual(summary["defective_targets"], [self.targets[0]])
        self.assertEqual(
            summary["metrics"][f"fuzz.target_seconds.{self.targets[0]}"], 0
        )
        later = self.receipt(
            "later",
            started=180_000,
            corpus_before=defect_after,
        )
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "after a target defect"):
            self.validate([first, defect, later])

    def test_hash_chain_sequence_and_signature_clock_fail_closed(self) -> None:
        entries = self.entries([self.receipt("first")])
        entries[0]["previous_entry_sha256"] = digest("wrong")
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "hash chain"):
            ledger.validate_entries(
                entries,
                self.authority,
                require_threshold=False,
                signature_verifier=self.signature_verifier,
                now=100_000,
            )
        entries = self.entries([self.receipt("first")])
        entries[0]["signature"]["signed_at"] = entries[0]["receipt"]["started_at"]
        with self.assertRaisesRegex(ledger.FuzzLedgerError, "clock order"):
            ledger.validate_entries(
                entries,
                self.authority,
                require_threshold=False,
                signature_verifier=self.signature_verifier,
                now=100_000,
            )

    def test_immutable_entry_writer_is_create_new_and_recovery_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "ledger"
            document = self.entries([self.receipt("immutable-entry")])[0]
            receipt_id = document["receipt"]["receipt_id"]
            destination_name = f"{1:020d}-{receipt_id}.json"
            with ledger._PinnedLedger.open(
                root,
                create=True,
                create_lock=True,
                exclusive=True,
            ) as authority:
                ledger._write_new_immutable(authority, destination_name, document)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "overwrite"):
                    ledger._write_new_immutable(authority, destination_name, document)

            entries = root / "entries"
            destination = entries / destination_name
            self.assertEqual(destination.stat().st_mode & 0o777, 0o400)

            pending = entries / ".pending-entry-interrupted"
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
            linked_pending = entries / ".pending-entry-linked"
            os.link(destination, linked_pending)
            self.assertEqual(destination.stat().st_nlink, 2)
            self.assertEqual(ledger.recover_pending(root), 2)
            self.assertFalse(pending.exists())
            self.assertFalse(linked_pending.exists())
            self.assertTrue(destination.is_file())
            self.assertEqual(destination.stat().st_nlink, 1)

    def _create_test_ledger(self, base: Path) -> tuple[Path, str]:
        root = base / "ledger"
        document = self.entries([self.receipt("filesystem-authority")])[0]
        receipt_id = document["receipt"]["receipt_id"]
        destination_name = f"{1:020d}-{receipt_id}.json"
        with ledger._PinnedLedger.open(
            root,
            create=True,
            create_lock=True,
            exclusive=True,
        ) as authority:
            ledger._write_new_immutable(authority, destination_name, document)
        return root, destination_name

    def _read_test_ledger(
        self,
        root: Path,
        *,
        race_hook: ledger.RaceHook | None = None,
    ) -> list[dict[str, Any]]:
        with ledger._PinnedLedger.open(
            root,
            create=False,
            create_lock=False,
            exclusive=False,
            race_hook=race_hook,
        ) as authority:
            documents, _snapshots = ledger._read_entries(authority)
            return documents

    def test_root_and_parent_rename_substitution_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            parent = base / "parent"
            parent.mkdir(mode=0o700)
            root, _entry_name = self._create_test_ledger(parent)
            displaced_root = parent / "ledger-displaced"
            swapped = False

            def swap_root(label: str) -> None:
                nonlocal swapped
                if label == "before-entry-scan" and not swapped:
                    root.rename(displaced_root)
                    root.mkdir(mode=0o700)
                    (root / "entries").mkdir(mode=0o700)
                    (root / ".append.lock").touch(mode=0o600)
                    swapped = True

            try:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted|renamed"
                ):
                    self._read_test_ledger(root, race_hook=swap_root)
            finally:
                if swapped:
                    shutil.rmtree(root)
                    displaced_root.rename(root)

            moved_parent = base / "parent-displaced"
            swapped = False

            def swap_parent(label: str) -> None:
                nonlocal swapped
                if label == "before-entry-scan" and not swapped:
                    parent.rename(moved_parent)
                    parent.mkdir(mode=0o700)
                    swapped = True

            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "ancestor"):
                    self._read_test_ledger(root, race_hook=swap_parent)
            finally:
                if swapped:
                    parent.rmdir()
                    moved_parent.rename(parent)

    def test_entries_lock_and_entry_substitution_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, entry_name = self._create_test_ledger(Path(raw).resolve())
            entries = root / "entries"
            displaced_entries = root / "entries-displaced"
            swapped = False

            def swap_entries(label: str) -> None:
                nonlocal swapped
                if label == "before-entry-scan" and not swapped:
                    entries.rename(displaced_entries)
                    entries.mkdir(mode=0o700)
                    swapped = True

            try:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted|renamed"
                ):
                    self._read_test_ledger(root, race_hook=swap_entries)
            finally:
                if swapped:
                    entries.rmdir()
                    displaced_entries.rename(entries)

            lock = root / ".append.lock"
            displaced_lock = root / ".append.lock-displaced"
            swapped = False

            def swap_lock(label: str) -> None:
                nonlocal swapped
                if label == "lock-held" and not swapped:
                    lock.rename(displaced_lock)
                    lock.touch(mode=0o600)
                    swapped = True

            try:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted|renamed"
                ):
                    self._read_test_ledger(root, race_hook=swap_lock)
            finally:
                if swapped:
                    lock.unlink()
                    displaced_lock.rename(lock)

            entry = entries / entry_name
            displaced_entry = entries / f"{entry_name}.displaced"
            swapped = False

            def swap_entry(label: str) -> None:
                nonlocal swapped
                if label == f"entry-opened:{entry_name}" and not swapped:
                    payload = entry.read_bytes()
                    entry.rename(displaced_entry)
                    entry.write_bytes(payload)
                    entry.chmod(0o400)
                    swapped = True

            try:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted|renamed"
                ):
                    self._read_test_ledger(root, race_hook=swap_entry)
            finally:
                if swapped:
                    entry.unlink()
                    displaced_entry.rename(entry)

    def test_symlink_fifo_device_and_hardlinked_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root, entry_name = self._create_test_ledger(base)
            entries = root / "entries"
            original = entries / entry_name
            preserved = entries / "preserved"
            original.rename(preserved)
            try:
                original.symlink_to(preserved.name)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
                original.unlink()

                os.mkfifo(original, 0o400)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
                original.unlink()

                external = base / "external-entry"
                external.write_bytes(preserved.read_bytes())
                external.chmod(0o400)
                os.link(external, original)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
                original.unlink()
                external.unlink()

                device_identity = ledger._identity(os.stat("/dev/null"))
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    ledger._validate_regular_file(
                        device_identity,
                        "device entry",
                        mode=0o400,
                        links={1},
                        device=device_identity.device,
                        allow_empty=True,
                    )
            finally:
                if original.exists() or original.is_symlink():
                    original.unlink()
                preserved.rename(original)

    def test_aliases_symlink_ancestors_and_hardlinked_lock_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            alias_root = base / "alias-ledger"
            alias_root.mkdir(mode=0o700)
            (alias_root / "ENTRIES").mkdir(mode=0o700)
            (alias_root / ".append.lock").touch(mode=0o600)
            with self.assertRaisesRegex(ledger.FuzzLedgerError, "alias"):
                self._read_test_ledger(alias_root)

            root, _entry_name = self._create_test_ledger(base)
            linked_lock = base / "linked-lock"
            lock = root / ".append.lock"
            os.link(lock, linked_lock)
            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
            finally:
                linked_lock.unlink()

            symlink_parent = base / "symlink-parent"
            symlink_parent.symlink_to(root.parent, target_is_directory=True)
            through_symlink = symlink_parent / root.name
            with self.assertRaisesRegex(ledger.FuzzLedgerError, "real directory"):
                self._read_test_ledger(through_symlink)

            lock.rename(root / ".APPEND.LOCK")
            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "alias"):
                    self._read_test_ledger(root)
            finally:
                (root / ".APPEND.LOCK").rename(lock)

            preserved_lock = root / ".append.lock-preserved"
            lock.rename(preserved_lock)
            try:
                os.mkfifo(lock, 0o600)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
                lock.unlink()
                lock.symlink_to(preserved_lock.name)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
                lock.unlink()
                lock.write_bytes(b"not-empty")
                lock.chmod(0o600)
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "remain empty"):
                    self._read_test_ledger(root)
            finally:
                if lock.exists() or lock.is_symlink():
                    lock.unlink()
                preserved_lock.rename(lock)

    def test_entry_case_alias_and_private_modes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, entry_name = self._create_test_ledger(Path(raw).resolve())
            entries = root / "entries"
            entry = entries / entry_name
            alias = entries / entry_name.upper()
            alias_created = False
            renamed = False
            try:
                try:
                    descriptor = os.open(
                        alias,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o400,
                    )
                except FileExistsError:
                    entry.rename(alias)
                    renamed = True
                    with self.assertRaisesRegex(ledger.FuzzLedgerError, "unexpected"):
                        self._read_test_ledger(root)
                else:
                    os.close(descriptor)
                    alias_created = True
                    with self.assertRaisesRegex(ledger.FuzzLedgerError, "alias"):
                        self._read_test_ledger(root)
            finally:
                if alias_created:
                    alias.unlink()
                elif renamed:
                    alias.rename(entry)

            entry.chmod(0o600)
            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "unsafe"):
                    self._read_test_ledger(root)
            finally:
                entry.chmod(0o400)

            entries.chmod(0o755)
            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "owner-private"):
                    self._read_test_ledger(root)
            finally:
                entries.chmod(0o700)

            root.chmod(0o755)
            try:
                with self.assertRaisesRegex(ledger.FuzzLedgerError, "owner-private"):
                    self._read_test_ledger(root)
            finally:
                root.chmod(0o700)

    def test_publication_rejects_destination_swap_after_create_new_link(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "ledger"
            document = self.entries([self.receipt("publication-swap")])[0]
            receipt_id = document["receipt"]["receipt_id"]
            destination_name = f"{1:020d}-{receipt_id}.json"
            destination = root / "entries" / destination_name
            displaced = root / "entries" / f"{destination_name}.displaced"
            swapped = False

            def swap_destination(label: str) -> None:
                nonlocal swapped
                if label == "publication-linked" and not swapped:
                    payload = destination.read_bytes()
                    destination.rename(displaced)
                    destination.write_bytes(payload)
                    destination.chmod(0o400)
                    swapped = True

            with ledger._PinnedLedger.open(
                root,
                create=True,
                create_lock=True,
                exclusive=True,
                race_hook=swap_destination,
            ) as authority:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted"
                ):
                    ledger._write_new_immutable(authority, destination_name, document)
            if swapped:
                destination.unlink()
                displaced.rename(destination)

    def test_pending_recovery_rejects_deterministic_name_swap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, _entry_name = self._create_test_ledger(Path(raw).resolve())
            entries = root / "entries"
            pending = entries / ".pending-entry-interrupted"
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
            displaced = entries / ".pending-entry-displaced"
            swapped = False

            def swap_pending(label: str) -> None:
                nonlocal swapped
                if label.endswith(pending.name) and not swapped:
                    pending.rename(displaced)
                    pending.write_bytes(b"partial")
                    pending.chmod(0o600)
                    swapped = True

            try:
                with self.assertRaisesRegex(
                    ledger.FuzzLedgerError, "changed|substituted|renamed"
                ):
                    ledger.recover_pending(root, race_hook=swap_pending)
            finally:
                if swapped:
                    pending.unlink()
                    displaced.rename(pending)


if __name__ == "__main__":
    unittest.main()
