"""Signing for freeq chat events (the ``+freeq.at/sig`` tag).

After SASL login the client registers a session ed25519 key with
``MSGSIG``, then signs each event (message, edit, reaction, delete) as a
JSON document. The signer also picks the event's own id (a ULID in
``+freeq.at/eventid``), which the server adopts as the msgid.

The output matches freeq's published test vectors byte for byte; see
``tests/chat-signing-vectors.json`` and ``freeq-sdk/src/chatsig.rs``.
"""

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIG_TAG = "+freeq.at/sig"
EVENT_ID_TAG = "+freeq.at/eventid"

# Client-authored tags covered by a message signature (wire names get a +freeq.at/ prefix).
COVERED_COORD_TAGS = (
    "event",
    "evidence-type",
    "link-desc",
    "link-image",
    "link-title",
    "link-url",
    "media-alt",
    "media-blurhash",
    "media-duration",
    "media-filename",
    "media-h",
    "media-mime",
    "media-size",
    "media-url",
    "media-w",
    "payload",
    "ref",
    "task-id",
)

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_ulid(now_ms: Optional[int] = None) -> str:
    """Generate a ULID: 48-bit ms timestamp + 80 random bits, Crockford base32."""
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    value = ((ts & ((1 << 48) - 1)) << 80) | int.from_bytes(os.urandom(10), "big")
    return "".join(_CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5))


def body_hash(wire_body: str) -> str:
    """``sha256:<hex>`` over the UTF-8 wire body."""
    return "sha256:" + hashlib.sha256(wire_body.encode("utf-8")).hexdigest()


def kid_for(public_key: bytes) -> str:
    """base64url-nopad(sha256(raw 32-byte ed25519 public key)[0..16])."""
    return _b64url(hashlib.sha256(public_key).digest()[:16])


def channel_venue(channel: str) -> str:
    return channel.lower()


def dm_venue(did_a: str, did_b: str) -> str:
    """``dm:<did_a>,<did_b>`` with the DIDs sorted ascending."""
    return "dm:" + ",".join(sorted((did_a, did_b)))


def coord_from_tags(tags: Dict[str, str]) -> Dict[str, str]:
    """Extract the covered tags as canonical keys, wire values verbatim."""
    coord: Dict[str, str] = {}
    for name in COVERED_COORD_TAGS:
        value = tags.get(f"+freeq.at/{name}")
        if value:
            coord[name] = value
    return coord


def chat_document(
    kind: str,
    *,
    from_did: str,
    msgid: str,
    target: str,
    body: Optional[str] = None,
    reply: Optional[str] = None,
    edit: Optional[str] = None,
    coord: Optional[Dict[str, str]] = None,
    subject: Optional[str] = None,
    emoji: Optional[str] = None,
    event: Optional[str] = None,
    payload: Optional[str] = None,
    ref: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Dict[str, object]:
    """Build the per-kind signing document."""
    doc: Dict[str, object] = {"from": from_did, "msgid": msgid, "target": target}
    if kind == "message":
        doc["body"] = body_hash(body or "")
        if reply:
            doc["reply"] = reply
        if edit:
            doc["edit"] = edit
        if coord:
            doc["coord"] = dict(coord)
    elif kind in ("react", "unreact"):
        doc["kind"] = kind
        doc["subject"] = subject
        doc["emoji"] = emoji
    elif kind == "delete":
        doc["kind"] = "delete"
        doc["subject"] = subject
    elif kind == "coordination":
        doc["kind"] = "coordination"
        doc["event"] = event
        doc["payload"] = body_hash(payload or "")
        if ref:
            doc["ref"] = ref
        if evidence:
            doc["evidence"] = evidence
    else:
        raise ValueError(f"unknown chat document kind: {kind}")
    return doc


def canonicalize(doc: Dict[str, object]) -> bytes:
    """JCS (RFC 8785) serialization.

    The documents contain only string values and plain-ASCII keys, for which
    JCS reduces to sorted keys, no whitespace, and literal UTF-8.
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ChatSigner:
    """Session ed25519 signer producing ``+freeq.at/sig`` tag values."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self.public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.kid = kid_for(self.public_bytes)
        self.public_b64 = _b64url(self.public_bytes)

    @classmethod
    def from_seed(cls, seed: bytes) -> "ChatSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(seed[:32]))

    @classmethod
    def load_or_create(cls, path: Path) -> "ChatSigner":
        """Load the persistent session seed, creating it on first use."""
        if path.exists():
            seed = path.read_bytes()
        else:
            seed = os.urandom(32)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(seed)
            path.chmod(0o600)
        return cls.from_seed(seed)

    def sign_document(self, doc: Dict[str, object]) -> str:
        """Sign a chat document, returning the ``alg:kid:sig`` tag value."""
        signature = self._key.sign(canonicalize(doc))
        return f"ed25519:{self.kid}:{_b64url(signature)}"
