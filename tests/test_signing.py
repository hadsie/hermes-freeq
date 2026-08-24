"""Signing tests against freeq's frozen chat-signing vectors."""

import json
from pathlib import Path

import pytest

from freeq_plugin.signing import (
    COVERED_COORD_TAGS,
    ChatSigner,
    canonicalize,
    chat_document,
    channel_venue,
    coord_from_tags,
    dm_venue,
    kid_for,
    mint_ulid,
)

VECTORS = json.loads(
    (Path(__file__).parent / "chat-signing-vectors.json").read_text()
)


def document_from_input(inp: dict) -> dict:
    kind = inp["kind"]
    coord = coord_from_tags(inp.get("tags", {})) or None
    return chat_document(
        kind,
        from_did=inp["from"],
        msgid=inp["msgid"],
        target=inp["target"],
        body=inp.get("bodyText"),
        reply=inp.get("reply"),
        edit=inp.get("edit"),
        coord=coord,
        subject=inp.get("subject"),
        emoji=inp.get("emoji"),
        event=inp.get("eventType"),
        payload=inp.get("payload"),
        ref=inp.get("ref"),
        evidence=inp.get("evidence"),
    )


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_vector_canonical_and_signature(vector):
    doc = document_from_input(vector["input"])
    assert canonicalize(doc).decode() == vector["canonical"]

    signer = ChatSigner.from_seed(bytes.fromhex(vector["seed"]))
    assert signer.kid == vector["kid"]
    assert signer.sign_document(doc) == vector["sigTag"]


def test_kid_matches_published_public_key():
    vector = VECTORS["vectors"][0]
    signer = ChatSigner.from_seed(bytes.fromhex(vector["seed"]))
    assert signer.public_b64 == vector["publicKey"]
    assert kid_for(signer.public_bytes) == vector["kid"]


class TestHelpers:

    def test_venues(self):
        assert channel_venue("#General") == "#general"
        assert dm_venue("did:plc:zzz", "did:plc:aaa") == "dm:did:plc:aaa,did:plc:zzz"

    def test_coord_only_covers_closed_set(self):
        tags = {
            "+freeq.at/media-mime": "image/png",
            "+freeq.at/reactions": "x:3",
            "account": "did:plc:x",
            "+freeq.at/media-alt": "a cat",
        }
        assert coord_from_tags(tags) == {"media-mime": "image/png", "media-alt": "a cat"}
        assert "reactions" not in COVERED_COORD_TAGS

    def test_ulid_shape_and_time_ordering(self):
        a = mint_ulid(now_ms=1_000_000)
        b = mint_ulid(now_ms=2_000_000)
        assert len(a) == 26 and len(b) == 26
        assert a[:9] < b[:9]

    def test_key_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "msgsig.key"
        first = ChatSigner.load_or_create(path)
        second = ChatSigner.load_or_create(path)
        assert first.kid == second.kid
