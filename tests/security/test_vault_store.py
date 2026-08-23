"""Vault persistence: the seam, and the one encrypted store behind it.

Grouped by the property rather than the class, because what matters is whether
a token issued before a restart still means the same person after one, and
whether the file that makes that possible fails loudly when it cannot be read.
"""

from __future__ import annotations

import pytest

from guardllm.security.privacy_vault import PrivacyVault
from guardllm.security.types import (
    REDACT,
    Destination,
    PIIClass,
    PrivacyConfig,
)
from guardllm.security.vault_store import (
    VAULT_SNAPSHOT_VERSION,
    EncryptedFileVaultStore,
    MemoryVaultStore,
    VaultEntry,
    VaultSnapshot,
    VaultStore,
    VaultStoreError,
    _from_json,
    _to_json,
    generate_key,
)

EMAIL = "jane.ellsworth@clinic.example.org"
SSN = "078-05-1120"
OTHER_EMAIL = "raymond.okonkwo@bank.example.net"


def _config(**kw) -> PrivacyConfig:
    base = {
        "restore_policy": {
            "gmail_send_email": {
                "/to/*/address": frozenset({PIIClass.EMAIL}),
                "/subject": REDACT,
            }
        },
        "destination_policy": {Destination.USER: frozenset({PIIClass.EMAIL, PIIClass.SSN})},
    }
    base.update(kw)
    return PrivacyConfig(**base)


def _vault(store: VaultStore | None = None, **kw) -> PrivacyVault:
    return PrivacyVault(_config(**kw), store=store)


# ---------------------------------------------------------------------------
# Continuity: the property persistence exists for
# ---------------------------------------------------------------------------


class TestContinuity:
    def test_token_issued_before_restart_still_resolves_after(self):
        store = MemoryVaultStore()
        first = _vault(store)
        tokenized = first.deidentify(f"mail {EMAIL} ssn {SSN}").content
        assert EMAIL not in tokenized
        first.persist()

        second = _vault(store)
        restored = second.reidentify(tokenized, destination=Destination.USER)
        assert EMAIL in restored.content
        assert SSN in restored.content

    def test_same_value_keeps_the_same_token_across_a_restart(self):
        store = MemoryVaultStore()
        first = _vault(store)
        before = first.token_for(PIIClass.EMAIL, EMAIL)
        first.persist()

        after = _vault(store).token_for(PIIClass.EMAIL, EMAIL)
        assert after == before

    def test_without_a_store_a_restart_loses_resolution(self):
        """The behaviour persistence changes, stated as a test.

        A fresh vault does not resolve the old token, and does not resolve it
        to somebody else either: it fails the call.
        """
        tokenized = _vault().deidentify(f"mail {EMAIL}").content
        result = _vault().reidentify(tokenized, destination=Destination.USER)
        assert EMAIL not in result.content

    def test_normalization_survives_so_a_variant_still_co_refers(self):
        store = MemoryVaultStore()
        first = _vault(store)
        token = first.token_for(PIIClass.EMAIL, EMAIL)
        first.persist()
        # Case-folded on the way in, so the upper-case spelling is the same
        # person and must not be issued a second token after the reload.
        assert _vault(store).token_for(PIIClass.EMAIL, EMAIL.upper()) == token

    def test_a_mangled_token_is_still_recovered_after_a_reload(self):
        """Proves the trigram index was rebuilt, not just the payload map."""
        store = MemoryVaultStore()
        first = _vault(store)
        d = first.deidentify(f"mail {EMAIL}")
        first.persist()

        token = d.findings[0].token
        body = token.split(":")[2].rstrip("]")
        mangled = token.replace(body, body[:3] + "Z" + body[4:])
        result = _vault(store).reidentify(mangled, destination=Destination.USER)
        assert EMAIL in result.content

    def test_source_handles_survive(self):
        store = MemoryVaultStore()
        first = _vault(store)
        handle = first.source_handle("email", "billing@vendor.example.com")
        first.persist()
        assert _vault(store).source_handle("email", "billing@vendor.example.com") == handle

    def test_the_source_key_is_carried_not_regenerated(self):
        store = MemoryVaultStore()
        first = _vault(store)
        first.token_for(PIIClass.EMAIL, EMAIL)
        first.persist()
        second = _vault(store)
        assert second.snapshot().source_key == first.snapshot().source_key

    def test_seeded_values_survive(self):
        store = MemoryVaultStore()
        first = _vault(store)
        first.seed({"Marguerite Vasseur": PIIClass.PERSON})
        first.persist()

        second = _vault(store)
        tokenized = second.deidentify("call Marguerite Vasseur back").content
        assert "Marguerite Vasseur" not in tokenized


# ---------------------------------------------------------------------------
# The vault never writes on its own
# ---------------------------------------------------------------------------


class TestWriteDiscipline:
    def test_a_vault_with_no_store_refuses_to_persist(self):
        with pytest.raises(VaultStoreError, match="no store"):
            _vault().persist()

    def test_issuing_a_token_does_not_write(self):
        store = MemoryVaultStore()
        vault = _vault(store)
        vault.token_for(PIIClass.EMAIL, EMAIL)
        assert store.load() is None

    def test_clear_purges_the_store(self):
        """Otherwise the next process resurrects tokens just invalidated."""
        store = MemoryVaultStore()
        vault = _vault(store)
        vault.token_for(PIIClass.EMAIL, EMAIL)
        vault.persist()
        assert store.load() is not None

        vault.clear()
        assert store.load() is None

    def test_loading_into_a_live_vault_is_refused(self):
        store = MemoryVaultStore()
        first = _vault(store)
        first.token_for(PIIClass.EMAIL, EMAIL)
        first.persist()

        live = _vault()
        live.token_for(PIIClass.EMAIL, OTHER_EMAIL)
        with pytest.raises(VaultStoreError, match="live tokens"):
            live.load_snapshot(store.load())

    def test_a_snapshot_over_capacity_is_refused(self):
        store = MemoryVaultStore()
        first = _vault(store)
        first.token_for(PIIClass.EMAIL, EMAIL)
        first.token_for(PIIClass.EMAIL, OTHER_EMAIL)
        first.persist()

        with pytest.raises(VaultStoreError, match="configured for 1"):
            PrivacyVault(PrivacyConfig(vault_max_entries=1), store=store)

    def test_a_short_source_key_is_refused(self):
        snapshot = VaultSnapshot(source_key=b"too short")
        with pytest.raises(VaultStoreError, match="32 bytes"):
            _vault().load_snapshot(snapshot)


# ---------------------------------------------------------------------------
# A snapshot is checked as a whole, not trusted because it authenticated
# ---------------------------------------------------------------------------


def _bodies(*values: str) -> list[str]:
    """Real codeword bodies, taken from a vault that issued them properly."""
    donor = _vault()
    for value in values:
        donor.token_for(PIIClass.EMAIL, value)
    return [e.body for e in donor.snapshot().entries]


class TestMalformedSnapshots:
    """Each case here resolved a token to the wrong person, or could have.

    An AEAD proves who wrote a file. It does not prove the file is coherent,
    and ``VaultStore`` is an interface anyone may implement.
    """

    def test_two_people_under_one_codeword_is_refused(self):
        """The one that resolved Alice's token to Bob."""
        body = _bodies(EMAIL)[0]
        snapshot = VaultSnapshot(
            entries=(
                VaultEntry(PIIClass.EMAIL, EMAIL, body),
                VaultEntry(PIIClass.EMAIL, OTHER_EMAIL, body),
            ),
            source_key=b"\x01" * 32,
        )
        with pytest.raises(VaultStoreError, match="resolve to two people"):
            _vault().load_snapshot(snapshot)

    def test_a_body_that_is_not_a_codeword_is_refused(self):
        """Otherwise render_token emits `[[GL:EMAIL:!!!]]`, which never resolves."""
        snapshot = VaultSnapshot(
            entries=(VaultEntry(PIIClass.EMAIL, EMAIL, "!!!"),), source_key=b"\x01" * 32
        )
        with pytest.raises(VaultStoreError, match="not a codeword"):
            _vault().load_snapshot(snapshot)

    def test_a_merely_correctable_body_is_refused(self):
        """It canonicalizes to a different codeword, so the payload gets two names."""
        body = _bodies(EMAIL)[0]
        mangled = ("Z" if body[0] != "Z" else "Y") + body[1:]
        snapshot = VaultSnapshot(
            entries=(VaultEntry(PIIClass.EMAIL, EMAIL, mangled),), source_key=b"\x01" * 32
        )
        with pytest.raises(VaultStoreError, match="not a codeword"):
            _vault().load_snapshot(snapshot)

    def test_one_value_under_two_codewords_is_refused(self):
        """Which token resolves would otherwise depend on iteration order."""
        first, second = _bodies(EMAIL, OTHER_EMAIL)
        snapshot = VaultSnapshot(
            entries=(
                VaultEntry(PIIClass.EMAIL, EMAIL, first),
                VaultEntry(PIIClass.EMAIL, EMAIL.upper(), second),
            ),
            source_key=b"\x01" * 32,
        )
        with pytest.raises(VaultStoreError, match="repeats an earlier value"):
            _vault().load_snapshot(snapshot)

    def test_a_non_string_value_is_refused(self):
        snapshot = VaultSnapshot(
            entries=(VaultEntry(PIIClass.EMAIL, None, _bodies(EMAIL)[0]),),
            source_key=b"\x01" * 32,
        )
        with pytest.raises(VaultStoreError, match="non-string value"):
            _vault().load_snapshot(snapshot)

    def test_a_duplicate_source_is_refused(self):
        snapshot = VaultSnapshot(
            sources=(("email", "a@b.example", "src-1"), ("email", "a@b.example", "src-2")),
            source_key=b"\x01" * 32,
        )
        with pytest.raises(VaultStoreError, match="repeats an earlier source"):
            _vault().load_snapshot(snapshot)

    def test_a_malformed_source_row_is_refused(self):
        snapshot = VaultSnapshot(sources=(("email", "", "src-1"),), source_key=b"\x01" * 32)
        with pytest.raises(VaultStoreError, match="non-empty strings"):
            _vault().load_snapshot(snapshot)

    def test_a_malformed_seeded_pair_is_refused(self):
        snapshot = VaultSnapshot(seeded=((None, PIIClass.PERSON),), source_key=b"\x01" * 32)
        with pytest.raises(VaultStoreError, match="seeded value 0"):
            _vault().load_snapshot(snapshot)

    def test_a_failed_load_leaves_the_vault_untouched(self):
        """A partial load reads as a working vault and is missing people."""
        good = _bodies(EMAIL)[0]
        snapshot = VaultSnapshot(
            entries=(
                VaultEntry(PIIClass.EMAIL, EMAIL, good),
                VaultEntry(PIIClass.EMAIL, OTHER_EMAIL, "!!!"),
            ),
            source_key=b"\x01" * 32,
        )
        vault = _vault()
        with pytest.raises(VaultStoreError):
            vault.load_snapshot(snapshot)
        assert len(vault) == 0
        assert not vault.contains_issued_token(f"[[GL:EMAIL:{good}]]")

    def test_a_well_formed_snapshot_still_loads(self):
        """The checks must not have made the ordinary path stricter than it was."""
        source = _vault()
        source.deidentify(f"mail {EMAIL} ssn {SSN}")
        source.source_handle("email", "billing@vendor.example.com")
        source.seed({"Marguerite Vasseur": PIIClass.PERSON})
        target = _vault()
        target.load_snapshot(source.snapshot())
        assert len(target) == 2


# ---------------------------------------------------------------------------
# Through the Guard facade, which is how a host actually reaches it
# ---------------------------------------------------------------------------


class TestGuardFacade:
    def test_a_guard_resumes_its_vault(self):
        from guardllm import Guard

        store = MemoryVaultStore()
        first = Guard(privacy=_config(), vault_store=store)
        tokenized = first.deidentify(f"mail {EMAIL}").content
        first.persist_vault()

        second = Guard(privacy=_config(), vault_store=store)
        restored = second.reidentify(tokenized, destination=Destination.USER)
        assert EMAIL in restored.content

    def test_reset_purges_the_store(self):
        """``reset`` starts a new session, so carrying the file forward is wrong.

        Not an accident of clear() sharing a code path: reset already
        invalidates every token in the transcript, and a store that survived it
        would hand the next session the previous one's identities.
        """
        from guardllm import Guard

        store = MemoryVaultStore()
        guard = Guard(privacy=_config(), vault_store=store)
        guard.deidentify(f"mail {EMAIL}")
        guard.persist_vault()
        assert store.load() is not None

        guard.reset()
        assert store.load() is None

    def test_a_guard_without_privacy_refuses_to_persist(self):
        from guardllm import Guard

        with pytest.raises(ValueError, match="without privacy"):
            Guard().persist_vault()

    def test_a_guard_with_privacy_but_no_store_refuses_to_persist(self):
        """Configured-but-never-writing is the failure that looks fine."""
        from guardllm import Guard

        with pytest.raises(VaultStoreError, match="no store"):
            Guard(privacy=_config()).persist_vault()


# ---------------------------------------------------------------------------
# Plaintext does not leak through the snapshot
# ---------------------------------------------------------------------------


class TestSnapshotDiscretion:
    def test_repr_counts_rather_than_quotes(self):
        vault = _vault()
        vault.deidentify(f"mail {EMAIL} ssn {SSN}")
        vault.seed({"Marguerite Vasseur": PIIClass.PERSON})
        text = repr(vault.snapshot())
        assert EMAIL not in text
        assert SSN not in text
        assert "marguerite" not in text.casefold()
        assert "entries=2" in text

    def test_entry_repr_omits_the_value(self):
        vault = _vault()
        vault.token_for(PIIClass.EMAIL, EMAIL)
        assert EMAIL not in repr(vault.snapshot().entries[0])


# ---------------------------------------------------------------------------
# Serialization and versioning
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_round_trip(self):
        vault = _vault()
        vault.deidentify(f"mail {EMAIL} ssn {SSN}")
        vault.source_handle("email", "billing@vendor.example.com")
        vault.seed({"Marguerite Vasseur": PIIClass.PERSON})
        snapshot = vault.snapshot()
        assert _from_json(_to_json(snapshot)) == snapshot

    def test_a_newer_version_says_to_upgrade_not_to_delete(self):
        raw = _to_json(VaultSnapshot(version=VAULT_SNAPSHOT_VERSION + 1))
        with pytest.raises(VaultStoreError, match="newer than this build"):
            _from_json(raw)

    def test_a_non_integer_version_is_refused(self):
        with pytest.raises(VaultStoreError, match="must be an integer"):
            _from_json(b'{"version": "1"}')

    def test_an_unknown_class_is_refused_rather_than_dropped(self):
        raw = b'{"version": 1, "entries": [{"class": "SOULMATE", "value": "x", "body": "y"}]}'
        with pytest.raises(VaultStoreError, match="unknown PII class"):
            _from_json(raw)

    def test_garbage_is_refused(self):
        with pytest.raises(VaultStoreError, match="not readable as JSON"):
            _from_json(b"\x00\x01\x02")


# ---------------------------------------------------------------------------
# The encrypted file
# ---------------------------------------------------------------------------


def test_without_the_extra_the_store_refuses_rather_than_writing_plaintext(monkeypatch, tmp_path):
    """There is no fallback, and the message names the extra to install.

    The failure mode being excluded is a store that notices the dependency is
    missing and writes the snapshot in the clear, which would put a
    re-identification database on disk in a deployment that believed it was
    encrypted.
    """
    import builtins

    real_import = builtins.__import__

    def refuse_cryptography(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("cryptography is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_cryptography)
    store = EncryptedFileVaultStore(tmp_path / "v.bin", key=generate_key())
    with pytest.raises(VaultStoreError, match=r"guardllm\[vault\]"):
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
    assert not store.path.exists()


try:  # the extra is optional; the seam above it is not
    import cryptography  # noqa: F401

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised by an install without the extra
    _HAVE_CRYPTO = False

# Applied per class rather than at module level: without it the tests above,
# which cover the protocol and the snapshot with no file involved, would skip
# as well, and those are the ones that must hold in a core install.
needs_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography is not installed")


@needs_crypto
class TestKeys:
    def test_generate_key_is_256_bits_and_fresh(self):
        import base64

        first, second = generate_key(), generate_key()
        assert len(base64.b64decode(first)) == 32
        assert first != second

    def test_a_short_key_is_refused(self, tmp_path):
        with pytest.raises(VaultStoreError, match="must be 32 bytes"):
            EncryptedFileVaultStore(tmp_path / "v.bin", key=b"\x01" * 16)

    def test_an_all_zero_key_is_refused(self, tmp_path):
        with pytest.raises(VaultStoreError, match="all-zero"):
            EncryptedFileVaultStore(tmp_path / "v.bin", key=b"\x00" * 32)

    def test_bad_base64_is_refused(self, tmp_path):
        with pytest.raises(VaultStoreError, match="base64"):
            EncryptedFileVaultStore(tmp_path / "v.bin", key="not base64 at all!!")

    def test_from_env_refuses_an_unset_variable(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GUARDLLM_VAULT_KEY", raising=False)
        with pytest.raises(VaultStoreError, match="is not set"):
            EncryptedFileVaultStore.from_env(tmp_path / "v.bin")

    def test_from_env_reads_base64(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GUARDLLM_VAULT_KEY", generate_key())
        store = EncryptedFileVaultStore.from_env(tmp_path / "v.bin")
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        assert store.load().source_key == b"\x07" * 32


@needs_crypto
class TestEncryptedFile:
    def _store(self, tmp_path, key=None):
        return EncryptedFileVaultStore(tmp_path / "vault.bin", key=key or generate_key())

    def test_round_trip_through_a_real_file(self, tmp_path):
        """One key, two processes, one file: the whole point of the class."""
        key = generate_key()
        first = _vault(self._store(tmp_path, key=key))
        tokenized = first.deidentify(f"mail {EMAIL} ssn {SSN}").content
        first.persist()

        second = _vault(self._store(tmp_path, key=key))
        restored = second.reidentify(tokenized, destination=Destination.USER)
        assert EMAIL in restored.content

    def test_nothing_before_the_first_save(self, tmp_path):
        assert self._store(tmp_path).load() is None

    def test_the_file_holds_no_plaintext(self, tmp_path):
        store = self._store(tmp_path)
        vault = _vault(store)
        vault.deidentify(f"mail {EMAIL} ssn {SSN}")
        vault.persist()
        blob = store.path.read_bytes()
        assert EMAIL.encode() not in blob
        assert b"078" not in blob

    def test_the_file_is_not_group_or_world_readable(self, tmp_path):
        store = self._store(tmp_path)
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        assert oct(store.path.stat().st_mode & 0o777) == "0o600"

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        store = self._store(tmp_path)
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        assert [p.name for p in tmp_path.iterdir()] == ["vault.bin"]

    def test_a_second_save_replaces_the_first(self, tmp_path):
        store = self._store(tmp_path)
        vault = _vault(store)
        vault.token_for(PIIClass.EMAIL, EMAIL)
        vault.persist()
        vault.token_for(PIIClass.EMAIL, OTHER_EMAIL)
        vault.persist()
        assert len(store.load().entries) == 2

    def test_a_wrong_key_raises_rather_than_reading_as_empty(self, tmp_path):
        store = self._store(tmp_path)
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        other = EncryptedFileVaultStore(store.path, key=generate_key())
        with pytest.raises(VaultStoreError, match="did not authenticate"):
            other.load()

    def test_a_tampered_file_does_not_authenticate(self, tmp_path):
        store = self._store(tmp_path)
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        blob = bytearray(store.path.read_bytes())
        blob[-1] ^= 0x01
        store.path.write_bytes(bytes(blob))
        with pytest.raises(VaultStoreError, match="did not authenticate"):
            store.load()

    def test_a_truncated_file_does_not_open_short(self, tmp_path):
        store = self._store(tmp_path)
        vault = _vault(store)
        vault.deidentify(f"mail {EMAIL} ssn {SSN}")
        vault.persist()
        blob = store.path.read_bytes()
        store.path.write_bytes(blob[: len(blob) // 2])
        with pytest.raises(VaultStoreError):
            store.load()

    def test_a_foreign_file_is_named_as_such(self, tmp_path):
        store = self._store(tmp_path)
        store.path.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
        with pytest.raises(VaultStoreError, match="not a GuardLLM vault file"):
            store.load()

    def test_purge_removes_the_file_and_tolerates_its_absence(self, tmp_path):
        store = self._store(tmp_path)
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        store.purge()
        assert not store.path.exists()
        store.purge()

    def test_clear_removes_the_file(self, tmp_path):
        store = self._store(tmp_path)
        vault = _vault(store)
        vault.token_for(PIIClass.EMAIL, EMAIL)
        vault.persist()
        vault.clear()
        assert not store.path.exists()

    def test_a_missing_parent_directory_is_created(self, tmp_path):
        store = EncryptedFileVaultStore(tmp_path / "deep" / "er" / "v.bin", key=generate_key())
        store.save(VaultSnapshot(source_key=b"\x07" * 32))
        assert store.load() is not None

    def test_two_saves_do_not_repeat_a_nonce(self, tmp_path):
        store = self._store(tmp_path)
        snapshot = VaultSnapshot(source_key=b"\x07" * 32)
        store.save(snapshot)
        first = store.path.read_bytes()
        store.save(snapshot)
        assert store.path.read_bytes() != first


@needs_crypto
class TestProtocolConformance:
    @pytest.mark.parametrize("factory", [MemoryVaultStore, "encrypted"])
    def test_both_stores_satisfy_the_protocol(self, factory, tmp_path):
        store = (
            MemoryVaultStore()
            if factory is MemoryVaultStore
            else EncryptedFileVaultStore(tmp_path / "v.bin", key=generate_key())
        )
        assert isinstance(store, VaultStore)


class TestConstructionErrors:
    def test_a_store_without_a_privacy_config_is_refused(self):
        """Persistence configured but never happening looks healthy until a restart.

        `Guard(vault_store=...)` with no `privacy=` used to build no vault at
        all, store nothing, and raise nothing, then report "constructed without
        privacy" at the first persist_vault, which a host may not call until
        shutdown.
        """
        from guardllm import Guard

        with pytest.raises(ValueError, match="there is no vault to persist"):
            Guard(vault_store=MemoryVaultStore())

    def test_two_sources_sharing_a_handle_are_refused(self):
        """The inverse of the duplicate-source check beside it.

        Distinct sources under one handle present two unrelated documents to
        the model as one, which is the collision `_SOURCE_HANDLE_MAX` exists to
        make improbable.
        """
        snapshot = VaultSnapshot(
            sources=(("mcp_server", "a", "src-X"), ("mcp_server", "b", "src-X")),
            source_key=b"\x01" * 32,
        )
        with pytest.raises(VaultStoreError, match="reuses an earlier handle"):
            _vault().load_snapshot(snapshot)


@needs_crypto
class TestLoadErrorContract:
    """`load` promises None or VaultStoreError, never a raw OSError."""

    def test_an_unreadable_path_raises_a_vault_error(self, tmp_path):
        directory = tmp_path / "vault-as-a-directory"
        directory.mkdir()
        store = EncryptedFileVaultStore(directory, key=generate_key())
        with pytest.raises(VaultStoreError, match="cannot read"):
            store.load()

    def test_a_missing_file_is_still_none(self, tmp_path):
        assert EncryptedFileVaultStore(tmp_path / "absent.bin", key=generate_key()).load() is None
