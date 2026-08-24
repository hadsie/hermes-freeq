"""
Freeq platform adapter for Hermes Agent.

Freeq (https://github.com/freeq-irc/freeq) is an IRC server with AT Protocol
identity. The wire protocol is standard IRC, so this adapter subclasses the
bundled IRC platform plugin and adds the three freeq extensions:

- **ATPROTO-CHALLENGE SASL** — authenticates the bot's atproto DID with the
  ``pds-session`` method: the response carries an app-password access JWT
  that the server verifies against the account's PDS via ``getSession``.
- **IRCv3 message tags** — inbound lines may carry a leading ``@tag=value``
  block; ``+freeq.at/media-*`` tags describe rich media attachments.
- **Rich media** — inbound attachments are downloaded into the local media
  cache for vision tools; outbound images and files are uploaded to the
  account's PDS (``com.atproto.repo.uploadBlob`` plus a ``blue.irc.media``
  pin record so the blob survives garbage collection) and sent as tagged
  PRIVMSGs with a plain-text fallback body.

Configuration (env vars, or ``gateway.platforms.freeq.extra`` in config.yaml):

    FREEQ_SERVER=irc.example.org
    FREEQ_PORT=6697
    FREEQ_CHANNEL=#general
    FREEQ_NICKNAME=mybot
    FREEQ_ATPROTO_HANDLE / FREEQ_ATPROTO_APP_PASSWORD / FREEQ_ATPROTO_PDS_URL
"""

import asyncio
import base64
import ipaddress
import json
import logging
import mimetypes
import os
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from gateway.config import Platform
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)
from gateway.platforms.media_cache import cache_media_bytes
from plugins.platforms.irc.adapter import (
    IRCAdapter,
    _extract_nick,
    _get_scoped_secret,
    _parse_irc_message,
)

from .signing import (
    EVENT_ID_TAG,
    SIG_TAG,
    ChatSigner,
    channel_venue,
    chat_document,
    coord_from_tags,
    dm_venue,
    mint_ulid,
)

logger = logging.getLogger(__name__)

_TAG_PREFIX = "+freeq.at/"
_DEFAULT_MEDIA_MAX_BYTES = 32 * 1024 * 1024


# ---------------------------------------------------------------------------
# IRCv3 message-tag helpers
# ---------------------------------------------------------------------------

_TAG_UNESCAPES = {":": ";", "s": " ", "r": "\r", "n": "\n", "\\": "\\"}


def _unescape_tag_value(value: str) -> str:
    """Unescape an IRCv3 tag value (\\: \\s \\r \\n \\\\; lone \\ is dropped)."""
    out: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            if i + 1 < len(value):
                nxt = value[i + 1]
                out.append(_TAG_UNESCAPES.get(nxt, nxt))
                i += 2
            else:
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _escape_tag_value(value: str) -> str:
    """Escape a string for use as an IRCv3 tag value."""
    return (
        value.replace("\\", "\\\\")
        .replace(";", "\\:")
        .replace(" ", "\\s")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _parse_message_tags(segment: str) -> Dict[str, str]:
    """Parse the ``key=value;key2=value2`` block after a leading ``@``."""
    tags: Dict[str, str] = {}
    for item in segment.split(";"):
        if not item:
            continue
        key, sep, value = item.partition("=")
        tags[key] = _unescape_tag_value(value) if sep else ""
    return tags


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Media attachment model
# ---------------------------------------------------------------------------

@dataclass
class _MediaAttachment:
    """A freeq rich-media attachment parsed from ``+freeq.at/media-*`` tags."""

    url: str
    mime: str
    alt: Optional[str]
    filename: Optional[str]
    size: Optional[int]


def _media_from_tags(tags: Dict[str, str]) -> Optional[_MediaAttachment]:
    """Extract a media attachment from message tags.

    Link previews also carry a URL but announce themselves with
    ``link-url`` — those stay plain text.
    """
    if _TAG_PREFIX + "link-url" in tags:
        return None
    url = tags.get(_TAG_PREFIX + "media-url")
    if not url:
        return None
    size_raw = tags.get(_TAG_PREFIX + "media-size", "")
    return _MediaAttachment(
        url=url,
        mime=tags.get(_TAG_PREFIX + "media-mime", ""),
        alt=tags.get(_TAG_PREFIX + "media-alt"),
        filename=tags.get(_TAG_PREFIX + "media-filename"),
        size=int(size_raw) if size_raw.isdigit() else None,
    )


def _message_type_for_mime(mime: str) -> MessageType:
    if mime.startswith("image/"):
        return MessageType.PHOTO
    if mime.startswith("video/"):
        return MessageType.VIDEO
    if mime.startswith("audio/"):
        return MessageType.AUDIO
    return MessageType.DOCUMENT


def _parse_server_time(value: str) -> Optional[float]:
    """Parse an IRCv3 server-time tag (ISO 8601, Z-suffixed) to a unix epoch."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _url_is_fetchable(url: str) -> bool:
    """Returns True if we're allowed to auto-download this media."""
    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        return False
    if host == "localhost" or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return ip.is_global


def _chunk_wire_text(text: str, budget: int) -> List[str]:
    """Byte-aware chunking preferring paragraph, then line, then space breaks."""
    chunks: List[str] = []
    while text:
        if len(text.encode("utf-8")) <= budget:
            chunks.append(text)
            break
        low, high, best = 1, len(text), 1
        while low <= high:
            mid = (low + high) // 2
            if len(text[:mid].encode("utf-8")) <= budget:
                best = mid
                low = mid + 1
            else:
                high = mid - 1
        cut = best
        window = text[:cut]
        for sep in ("\n\n", "\n", " "):
            pos = window.rfind(sep)
            if pos > cut // 3:
                cut = pos + len(sep)
                break
        chunks.append(text[:cut].rstrip("\n "))
        text = text[cut:].lstrip("\n ")
    return [c for c in chunks if c] or [""]


def _read_local_media(path: str, default_mime: str) -> Tuple[bytes, str, str]:
    """Read a local file and return ``(bytes, mime, basename)``."""
    mime = mimetypes.guess_type(path)[0] or default_mime
    with open(path, "rb") as f:
        return f.read(), mime, os.path.basename(path)


# ---------------------------------------------------------------------------
# atproto app-password session
# ---------------------------------------------------------------------------

class _AtprotoSession:
    """Minimal app-password session for SASL login and PDS blob uploads.

    Logs in with ``com.atproto.server.createSession``, caches the tokens and
    DID, refreshes via ``refreshSession`` when the access token ages out,
    and retries an XRPC call once on ``ExpiredToken``.
    """

    _ACCESS_TTL_SECONDS = 2700

    def __init__(self, handle: str, app_password: str, pds_url: str) -> None:
        self.handle = handle
        self.app_password = app_password
        self.pds_url = (pds_url or "https://bsky.social").rstrip("/")
        self._did: Optional[str] = None
        self._access: Optional[str] = None
        self._refresh_jwt: Optional[str] = None
        self._issued = 0.0
        self._lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.handle and self.app_password)

    @property
    def did(self) -> Optional[str]:
        return self._did

    async def session(self) -> Tuple[str, str, str]:
        """Return ``(did, access_jwt, pds_url)``, logging in or refreshing as needed."""
        async with self._lock:
            if not self._access or time.time() - self._issued > self._ACCESS_TTL_SECONDS:
                await self._login_or_refresh()
            return self._did, self._access, self.pds_url

    def invalidate(self) -> None:
        self._access = None

    async def _login_or_refresh(self) -> None:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if self._refresh_jwt:
                resp = await client.post(
                    f"{self.pds_url}/xrpc/com.atproto.server.refreshSession",
                    headers={"Authorization": f"Bearer {self._refresh_jwt}"},
                )
                if resp.status_code == 200:
                    self._store(resp.json())
                    return
                logger.info("freeq: atproto refresh rejected (%s); re-logging in", resp.status_code)
                self._refresh_jwt = None
            resp = await client.post(
                f"{self.pds_url}/xrpc/com.atproto.server.createSession",
                json={"identifier": self.handle, "password": self.app_password},
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"atproto createSession failed ({resp.status_code}) for {self.handle}"
                )
            self._store(resp.json())

    def _store(self, data: dict) -> None:
        self._did = data["did"]
        self._access = data["accessJwt"]
        self._refresh_jwt = data["refreshJwt"]
        self._issued = time.time()

    async def xrpc_post(
        self,
        nsid: str,
        *,
        json_body: Optional[dict] = None,
        content: Optional[bytes] = None,
        content_type: Optional[str] = None,
    ) -> dict:
        """Authenticated XRPC POST; retries once on an expired access token."""
        for attempt in (0, 1):
            _, access, _ = await self.session()
            headers = {"Authorization": f"Bearer {access}"}
            if content_type:
                headers["Content-Type"] = content_type
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self.pds_url}/xrpc/{nsid}",
                    headers=headers,
                    json=json_body,
                    content=content,
                )
            if resp.status_code == 400 and attempt == 0 and "ExpiredToken" in resp.text:
                self.invalidate()
                continue
            if resp.status_code != 200:
                raise RuntimeError(f"atproto {nsid} failed ({resp.status_code}): {resp.text[:200]}")
            return resp.json()
        raise RuntimeError(f"atproto {nsid} failed after token refresh retry")


# ---------------------------------------------------------------------------
# Freeq Adapter
# ---------------------------------------------------------------------------

class FreeqAdapter(IRCAdapter):
    """Freeq adapter: IRC wire protocol + ATPROTO SASL + freeq media tags.

    Reuses the bundled IRC adapter's send path, message splitting, receive
    loop, and PRIVMSG dispatch; overrides registration (CAP/SASL), line
    handling (message tags), and the media send/receive surface.
    """

    def __init__(self, config, **kwargs):
        BasePlatformAdapter.__init__(self, config=config, platform=Platform("freeq"))

        extra = getattr(config, "extra", {}) or {}

        self.server = os.getenv("FREEQ_SERVER") or extra.get("server", "")
        try:
            self.port = int(os.getenv("FREEQ_PORT") or extra.get("port", 6697))
        except (ValueError, TypeError):
            self.port = 6697
        self.nickname = os.getenv("FREEQ_NICKNAME") or extra.get("nickname", "hermes")
        self.channel = os.getenv("FREEQ_CHANNEL") or extra.get("channel", "")
        self.use_tls = (
            os.getenv("FREEQ_USE_TLS", "").lower() in {"1", "true", "yes"}
            if os.getenv("FREEQ_USE_TLS")
            else extra.get("use_tls", True)
        )
        # TLS SNI / verification hostname when it differs from the connect
        # address (e.g. connecting to a private VPN IP while the server's
        # certificate names the public hostname).
        self.tls_server_name = os.getenv("FREEQ_TLS_SERVER_NAME") or extra.get("tls_server_name", "")
        # The IRC adapter expects these, but they're not used by freeq.
        self.server_password = ""
        self.nickserv_password = ""

        self.allowed_users: list = extra.get("allowed_users", [])
        self._allowed_users_lower = {u.lower() for u in self.allowed_users if isinstance(u, str)}

        # freeq handles long messages itself, so no need for classic IRC's tiny 450 limit.
        self.max_message_length = int(extra.get("max_message_length") or 4000)

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._recv_task: Optional[asyncio.Task] = None
        self._current_nick = self.nickname
        self._registered = False
        self._registration_event = asyncio.Event()

        self._atproto = _AtprotoSession(
            os.getenv("FREEQ_ATPROTO_HANDLE") or extra.get("atproto_handle", ""),
            _get_scoped_secret("FREEQ_ATPROTO_APP_PASSWORD")
            or extra.get("atproto_app_password", ""),
            os.getenv("FREEQ_ATPROTO_PDS_URL") or extra.get("atproto_pds_url", ""),
        )
        self._server_caps: set = set()
        self._sasl_failed: Optional[str] = None
        self._sasl_authenticated = False
        self._pending_media: Optional[Tuple[str, str, _MediaAttachment]] = None
        self._pending_account: Optional[str] = None
        self._connected_at: Optional[float] = None
        self._last_rx: float = 0.0
        self._keepalive_task: Optional[asyncio.Task] = None
        self._echo_enabled = False
        self._echo_waiters: List[Tuple[str, str, asyncio.Future]] = []
        self._pending_msgid: Optional[str] = None
        self._own_reactions: Dict[Tuple[str, str], str] = {}
        reactions_env = os.getenv("FREEQ_REACTIONS", "").lower()
        self._reactions_flag = (
            reactions_env in {"1", "true", "yes"}
            if reactions_env
            else bool(extra.get("reactions", True))
        )
        sign_env = os.getenv("FREEQ_SIGN_MESSAGES", "").lower()
        self._signing_flag = (
            sign_env in {"1", "true", "yes"}
            if sign_env
            else bool(extra.get("sign_messages", True))
        )
        self._signer: Optional[ChatSigner] = None
        self._msgsig_ready = False
        self._msgsig_event = asyncio.Event()
        self._caps_acked: set = set()
        self._nick_dids: Dict[str, str] = {}
        try:
            self._media_max_bytes = int(
                os.getenv("FREEQ_MEDIA_MAX_BYTES")
                or extra.get("media_max_bytes", _DEFAULT_MEDIA_MAX_BYTES)
            )
        except (ValueError, TypeError):
            self._media_max_bytes = _DEFAULT_MEDIA_MAX_BYTES
        self._media_uploads = (
            os.getenv("FREEQ_MEDIA_UPLOADS") or str(extra.get("media_uploads", "pds"))
        ).lower()

    @property
    def name(self) -> str:
        return "Freeq"

    # ── Connection lifecycle ──────────────────────────────────────────────

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Connect, negotiate CAP + ATPROTO-CHALLENGE SASL, join channels."""
        if not self.server or not self.channel:
            logger.error("freeq: server and channel must be configured")
            self._set_fatal_error(
                "config_missing",
                "FREEQ_SERVER and FREEQ_CHANNEL must be set",
                retryable=False,
            )
            return False

        try:
            from gateway.status import acquire_scoped_lock
            lock_key = f"{self.server}:{self.nickname}"
            if not acquire_scoped_lock("freeq", lock_key):
                logger.error("freeq: %s@%s already in use by another profile", self.nickname, self.server)
                self._set_fatal_error("lock_conflict", "Freeq identity in use by another profile", retryable=False)
                return False
            self._lock_key = lock_key
        except ImportError:
            self._lock_key = None

        self._server_caps.clear()
        self._sasl_failed = None
        self._sasl_authenticated = False
        self._registered = False
        self._registration_event.clear()

        try:
            ssl_ctx = ssl.create_default_context() if self.use_tls else None
            connect_kwargs = {"ssl": ssl_ctx}
            if ssl_ctx and self.tls_server_name:
                connect_kwargs["server_hostname"] = self.tls_server_name
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.server, self.port, **connect_kwargs),
                timeout=30.0,
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
            logger.error("freeq: failed to connect to %s:%s — %s", self.server, self.port, e)
            self._set_fatal_error("connect_failed", str(e), retryable=True)
            return False

        await self._send_raw("CAP LS 302")
        await self._send_raw(f"NICK {self.nickname}")
        await self._send_raw(f"USER {self.nickname} 0 * :Hermes Agent (freeq)")

        self._recv_task = asyncio.create_task(self._receive_loop())

        # Registration completes after CAP END; SASL adds PDS round trips.
        try:
            await asyncio.wait_for(self._registration_event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            logger.error("freeq: registration timed out")
            await self.disconnect()
            self._set_fatal_error("registration_timeout", "freeq server did not complete registration", retryable=True)
            return False

        if self._sasl_failed:
            await self.disconnect()
            self._set_fatal_error("sasl_failed", self._sasl_failed, retryable=True)
            return False

        await self._register_signing_key()

        self._connected_at = time.time()
        self._last_rx = time.time()
        await self._send_raw(f"JOIN {self.channel}")
        self._mark_connected()
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        logger.info(
            "freeq: connected to %s:%s as %s (did=%s), joined %s",
            self.server, self.port, self._current_nick,
            self._atproto.did if self._sasl_authenticated else "guest",
            self.channel,
        )
        return True

    async def disconnect(self) -> None:
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
        self._keepalive_task = None
        await super().disconnect()

    # ── Keepalive ─────────────────────────────────────────────────────────
    #
    # A hard server stop (restart, host reboot) can kill the TCP session
    # without a FIN, leaving the adapter "connected" forever with a dead
    # socket. The keepalive probes with PING when the line goes quiet and
    # closes the transport after prolonged silence, which lets the normal
    # receive-loop failure path notify the gateway's reconnection watcher.

    _KEEPALIVE_CHECK_S = 30.0
    _KEEPALIVE_PING_S = 60.0
    _KEEPALIVE_DEAD_S = 150.0

    async def _keepalive_tick(self) -> bool:
        """One keepalive check. Returns False once the link is declared dead."""
        idle = time.time() - self._last_rx
        if idle > self._KEEPALIVE_DEAD_S:
            logger.error("freeq: no server traffic for %.0fs — closing dead connection", idle)
            if self._writer and not self._writer.is_closing():
                self._writer.close()
            return False
        if idle > self._KEEPALIVE_PING_S:
            try:
                await self._send_raw("PING :keepalive")
            except (OSError, ConnectionError) as e:
                logger.warning("freeq: keepalive PING failed: %s", e)
        return True

    async def _keepalive_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._KEEPALIVE_CHECK_S)
                if not await self._keepalive_tick():
                    return
        except asyncio.CancelledError:
            pass

    # ── Message signing ───────────────────────────────────────────────────

    async def _register_signing_key(self) -> None:
        """Register the session signing key (MSGSIG) after SASL, before JOIN."""
        if not (
            self._signing_flag
            and self._sasl_authenticated
            and "freeq.at/msgsig" in self._caps_acked
        ):
            return
        if self._signer is None:
            try:
                from plugins.plugin_storage import plugin_data_dir
                self._signer = ChatSigner.load_or_create(plugin_data_dir("freeq") / "msgsig.key")
            except (OSError, ImportError, ValueError) as e:
                logger.warning("freeq: signing key unavailable, sending unsigned: %s", e)
                return
        self._msgsig_ready = False
        self._msgsig_event.clear()
        await self._send_raw(f"MSGSIG {self._signer.public_b64}")
        try:
            await asyncio.wait_for(self._msgsig_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("freeq: MSGSIG registration not acknowledged; sending unsigned")
        if self._msgsig_ready:
            logger.info("freeq: message signing enabled (kid=%s)", self._signer.kid)

    def _venue_for(self, target: str) -> Optional[str]:
        """Where the signature says this message was sent: the lowercased
        channel name, or the sorted-DID pair for a DM.

        Returns None when the DM peer's DID is unknown; the caller then sends unsigned rather than
        signing over a guessed venue.
        """
        if target.startswith(("#", "&")):
            return channel_venue(target)
        own = self._atproto.did
        peer = target if target.startswith("did:") else self._nick_dids.get(target.lower())
        if own and peer:
            return dm_venue(own, peer)
        return None

    def _signature_tags(
        self, target: str, wire_body: str, tags: Dict[str, str]
    ) -> Optional[Tuple[str, Dict[str, str]]]:
        """Generate an event id and sign the message document for this send.

        Returns ``(eventid, {eventid tag, sig tag})`` or None when signing is
        unavailable. The server adopts the eventid as the message's msgid.
        """
        if not (self._signer and self._msgsig_ready and self._atproto.did):
            return None
        venue = self._venue_for(target)
        if venue is None:
            return None
        eventid = mint_ulid()
        reply = tags.get("+reply")
        edit = tags.get("+draft/edit")
        doc = chat_document(
            "message",
            from_did=self._atproto.did,
            msgid=eventid,
            target=venue,
            body=wire_body,
            reply=reply,
            edit=edit,
            coord=coord_from_tags(tags) or None,
        )
        return eventid, {EVENT_ID_TAG: eventid, SIG_TAG: self._signer.sign_document(doc)}

    def _reaction_signature_tags(
        self, target: str, kind: str, subject: str, emoji: str
    ) -> Dict[str, str]:
        """Signature tags for a react/unreact TAGMSG (empty when unsigned)."""
        if not (self._signer and self._msgsig_ready and self._atproto.did):
            return {}
        venue = self._venue_for(target)
        if venue is None:
            return {}
        eventid = mint_ulid()
        doc = chat_document(
            kind,
            from_did=self._atproto.did,
            msgid=eventid,
            target=venue,
            subject=subject,
            emoji=emoji,
        )
        return {EVENT_ID_TAG: eventid, SIG_TAG: self._signer.sign_document(doc)}

    # ── Line handling ─────────────────────────────────────────────────────

    async def _handle_line(self, raw: str) -> None:
        """Handle CAP/SASL and message tags, then defer to the IRC adapter."""
        self._last_rx = time.time()
        tags: Dict[str, str] = {}
        if raw.startswith("@"):
            head, _, raw = raw.partition(" ")
            tags = _parse_message_tags(head[1:])

        msg = _parse_irc_message(raw)
        command = msg["command"]
        params = msg["params"]

        if command == "CAP":
            await self._handle_cap(params)
            return
        if command == "TAGMSG" and tags and params:
            await self._handle_tagmsg(msg, tags, params[0])
            return
        if command == "AUTHENTICATE":
            await self._handle_sasl_challenge(params)
            return
        if command == "903":  # RPL_SASLSUCCESS
            self._sasl_authenticated = True
            logger.info("freeq: SASL authenticated as %s", self._atproto.did)
            await self._send_raw("CAP END")
            return
        if command in {"902", "904", "905", "906", "908"}:  # SASL failures
            detail = params[-1] if params else ""
            self._sasl_failed = f"SASL authentication failed ({command}: {detail})"
            logger.error("freeq: %s", self._sasl_failed)
            # Unblock connect() so it fails instead of silently timing out.
            self._registration_event.set()
            return
        if command == "MSGSIG":
            self._msgsig_ready = bool(params) and params[-1].upper() == "OK"
            self._msgsig_event.set()
            return
        if command == "FAIL" and params and params[0] == "MSGSIG":
            logger.warning("freeq: MSGSIG rejected: %s", params[-1] if params else "")
            self._msgsig_event.set()
            return

        if command == "PRIVMSG" and len(params) >= 2:
            target, text = params[0], params[1]
            is_channel = target.startswith(("#", "&"))

            # Our own echo: grab the msgid for edits, never re-process ourselves.
            sender = _extract_nick(msg["prefix"])
            if sender.lower() == self._current_nick.lower():
                self._resolve_echo(target, text, tags.get("msgid"))
                return
            # Remember the sender's DID so DM signatures can name both parties.
            if tags.get("account"):
                self._nick_dids[sender.lower()] = tags["account"]

            # Ignore channel history replayed on JOIN, so reconnects don't re-answer.
            if is_channel and self._connected_at:
                ts = _parse_server_time(tags.get("time", ""))
                if ts is not None and ts < self._connected_at:
                    return

            # Rewrite "@nick ..." to "nick ..." so the base addressing check matches.
            if is_channel and text.lower().startswith(f"@{self._current_nick.lower()}"):
                raw = f":{msg['prefix']} PRIVMSG {target} :{text[1:]}"

            # Stash sender DID, msgid, and any media attachment for dispatch.
            if tags:
                self._pending_account = tags.get("account") or None
                self._pending_msgid = tags.get("msgid") or None
                attachment = _media_from_tags(tags)
                if attachment:
                    self._pending_media = await self._cache_inbound_media(attachment)

        try:
            await super()._handle_line(raw)
        finally:
            self._pending_media = None
            self._pending_account = None
            self._pending_msgid = None

    async def _handle_cap(self, params: List[str]) -> None:
        """CAP negotiation: request sasl + message tags, then authenticate."""
        sub = params[1].upper() if len(params) > 1 else ""
        if sub == "LS":
            # CAP LS 302 may span multiple lines; "*" before the list marks
            # a continuation. Cap tokens may carry =values.
            more = len(params) >= 4 and params[2] == "*"
            caps = params[-1].split() if params else []
            self._server_caps.update(c.split("=", 1)[0] for c in caps)
            if more:
                return
            want = [
                c
                for c in (
                    "sasl",
                    "message-tags",
                    "server-time",
                    "account-tag",
                    "echo-message",
                    "freeq.at/msgsig",
                )
                if c in self._server_caps
            ]
            if not want:
                await self._send_raw("CAP END")
                return
            if "sasl" not in want or not self._atproto.configured:
                logger.warning(
                    "freeq: connecting as guest (sasl offered: %s, atproto creds configured: %s)",
                    "sasl" in want, self._atproto.configured,
                )
            await self._send_raw("CAP REQ :" + " ".join(want))
        elif sub == "ACK":
            acked = {c.lstrip("-") for c in (params[-1].split() if params else [])}
            self._caps_acked.update(acked)
            if "echo-message" in acked:
                self._echo_enabled = True
            if "sasl" in acked and self._atproto.configured:
                await self._send_raw("AUTHENTICATE ATPROTO-CHALLENGE")
            else:
                await self._send_raw("CAP END")
        elif sub == "NAK":
            await self._send_raw("CAP END")

    async def _handle_sasl_challenge(self, params: List[str]) -> None:
        """Answer the server's ATPROTO-CHALLENGE with a pds-session response."""
        payload = params[-1] if params else ""
        if not payload or payload == "+":
            self._sasl_failed = "server sent an empty SASL challenge"
            self._registration_event.set()
            return
        try:
            challenge = json.loads(_b64url_decode(payload))
        except (ValueError, json.JSONDecodeError) as e:
            self._sasl_failed = f"could not decode SASL challenge: {e}"
            await self._send_raw("AUTHENTICATE *")
            self._registration_event.set()
            return
        try:
            did, access_jwt, pds_url = await self._atproto.session()
        except (httpx.HTTPError, RuntimeError, KeyError) as e:
            logger.error("freeq: atproto login failed: %s", e)
            self._sasl_failed = f"atproto login failed: {e}"
            await self._send_raw("AUTHENTICATE *")
            self._registration_event.set()
            return
        response = {
            "did": did,
            "signature": access_jwt,
            "method": "pds-session",
            "pds_url": pds_url,
            # PDS methods must echo the nonce to bind the response to this
            # connection's challenge (anti-replay).
            "challenge_nonce": challenge.get("nonce", ""),
        }
        await self._send_raw("AUTHENTICATE " + _b64url_encode(json.dumps(response).encode()))

    # ── Sending ───────────────────────────────────────────────────────────

    # Per-PRIVMSG byte budget for message bodies. The freeq server accepts
    # 8192-byte lines; 6400 matches the freeq SDK's own per-chunk budget,
    # leaving headroom for tags and the relay-added sender prefix.
    _WIRE_BYTE_BUDGET = 6400

    def _resolve_echo(self, target: str, text: str, msgid: Optional[str]) -> None:
        """Match our own echoed message to a waiting send() and hand it the msgid."""
        for i, (waiter_target, waiter_text, fut) in enumerate(self._echo_waiters):
            if waiter_target == target and waiter_text == text:
                if not fut.done():
                    if msgid:
                        fut.set_result(msgid)
                    else:
                        fut.cancel()
                del self._echo_waiters[i]
                return

    def _discard_echo_waiter(self, fut: asyncio.Future) -> None:
        self._echo_waiters = [(t, x, f) for (t, x, f) in self._echo_waiters if f is not fut]

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a message as a single tagged PRIVMSG.

        freeq clients render ``+freeq.at/mime=text/markdown`` and unescape
        ``\\n`` when ``+freeq.at/multiline`` is set, so a whole multi-line
        markdown reply travels as a single message. With the echo-message
        cap the server's echo hands back the real msgid, which
        edit_message needs.
        """
        if not self._writer or self._writer.is_closing():
            return SendResult(success=False, error="Not connected")
        chunks = _chunk_wire_text(content or "", self._WIRE_BYTE_BUDGET)
        message_id = str(int(time.time() * 1000))
        for index, chunk in enumerate(chunks):
            tags: Dict[str, str] = {"+freeq.at/mime": "text/markdown"}
            if "\n" in chunk:
                tags["+freeq.at/multiline"] = ""
            # Only attach +reply when reply_to is a real server msgid. When echo
            # capture misses, we fall back to a made-up timestamp id (all digits),
            # and replying to an id the server never issued would break threading.
            if reply_to and index == 0 and not str(reply_to).isdigit():
                tags["+reply"] = str(reply_to)
            wire_text = chunk.replace("\n", "\\n")
            signed = self._signature_tags(chat_id, wire_text, tags)
            if signed:
                # Signed messages pick their own msgid, so we already know it
                # and don't have to wait for the server's echo.
                eventid, sig_tags = signed
                tags.update(sig_tags)
                if index == 0:
                    message_id = eventid
                result = await self._send_tagged(chat_id, tags, wire_text)
                if not result.success:
                    return result
                if len(chunks) > 1:
                    await asyncio.sleep(0.3)
                continue
            fut: Optional[asyncio.Future] = None
            if self._echo_enabled and index == 0:
                fut = asyncio.get_running_loop().create_future()
                self._echo_waiters.append((chat_id, wire_text, fut))
            result = await self._send_tagged(chat_id, tags, wire_text)
            if not result.success:
                if fut:
                    self._discard_echo_waiter(fut)
                return result
            if fut:
                try:
                    message_id = await asyncio.wait_for(fut, timeout=3.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    self._discard_echo_waiter(fut)
            if len(chunks) > 1:
                await asyncio.sleep(0.3)
        return SendResult(success=True, message_id=message_id)

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Edit a previously sent message in place via ``+draft/edit``."""
        if not self._writer or self._writer.is_closing():
            return SendResult(success=False, error="Not connected")
        if not message_id or str(message_id).isdigit():
            # Synthetic timestamp id (echo capture missed): report failure so
            # the caller falls back to sending a new message.
            return SendResult(success=False, error="no server msgid for original message")
        # Edits can't overflow to more messages so clip oversized content.
        chunk = _chunk_wire_text(content or "", self._WIRE_BYTE_BUDGET)[0]
        tags = {"+freeq.at/mime": "text/markdown", "+draft/edit": str(message_id)}
        if "\n" in chunk:
            tags["+freeq.at/multiline"] = ""
        wire_text = chunk.replace("\n", "\\n")
        signed = self._signature_tags(chat_id, wire_text, tags)
        if signed:
            tags.update(signed[1])
        result = await self._send_tagged(chat_id, tags, wire_text)
        if not result.success:
            return result
        return SendResult(success=True, message_id=str(message_id))

    async def _send_tagmsg(self, target: str, tags: Dict[str, str]) -> bool:
        """Send a body-less TAGMSG (typing, reactions, other ephemera)."""
        if not self._writer or self._writer.is_closing():
            return False
        tag_block = ";".join(
            f"{k}={_escape_tag_value(v)}" if v else k for k, v in tags.items()
        )
        try:
            await self._send_raw(f"@{tag_block} TAGMSG {target}")
        except (OSError, ConnectionError) as e:
            logger.debug("freeq: TAGMSG failed: %s", e)
            return False
        return True

    async def send_typing(self, chat_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Send an ephemeral IRCv3 typing indicator (TAGMSG ``+typing=active``)."""
        await self._send_tagmsg(chat_id, {"+typing": "active"})

    async def stop_typing(self, chat_id: str) -> None:
        """Clear the typing indicator (TAGMSG ``+typing=done``)."""
        await self._send_tagmsg(chat_id, {"+typing": "done"})

    # ── Reactions ─────────────────────────────────────────────────────────
    #
    # freeq reactions are TAGMSGs: ``+react=<emoji>;+reply=<msgid>`` adds,
    # ``+freeq.at/unreact=<emoji>;+reply=<msgid>`` removes. The lifecycle
    # flow (in-progress and success/failure marks on the triggering message)
    # rides the base adapter's shared reaction-ack contract via the
    # ``_add_reaction`` / ``_remove_reaction`` primitives below.

    _ACK_EMOJI = "\U0001f440"
    _OK_EMOJI = "✅"
    _FAIL_EMOJI = "❌"

    def _reactions_enabled(self) -> bool:
        return self._reactions_flag

    async def _add_reaction(self, chat_id: str, message_id: str, emoji: str) -> bool:
        # Reactions name messages by server msgid.
        if not message_id or str(message_id).isdigit():
            return False
        tags = {"+react": emoji, "+reply": str(message_id)}
        tags.update(self._reaction_signature_tags(chat_id, "react", str(message_id), emoji))
        ok = await self._send_tagmsg(chat_id, tags)
        if ok:
            self._own_reactions[(chat_id, str(message_id))] = emoji
        return ok

    async def _remove_reaction(self, chat_id: str, message_id: str) -> bool:
        emoji = self._own_reactions.pop((chat_id, str(message_id)), None)
        if not emoji:
            return False
        tags = {"+freeq.at/unreact": emoji, "+reply": str(message_id)}
        tags.update(self._reaction_signature_tags(chat_id, "unreact", str(message_id), emoji))
        return await self._send_tagmsg(chat_id, tags)

    async def on_processing_start(self, event: MessageEvent) -> None:
        """Mark the triggering message with the in-progress reaction."""
        if not self._reactions_flag:
            return
        chat_id = getattr(event.source, "chat_id", None)
        message_id = getattr(event, "message_id", None)
        if chat_id and message_id:
            await self._add_reaction(chat_id, message_id, self._ACK_EMOJI)

    async def _handle_tagmsg(self, msg: dict, tags: Dict[str, str], target: str) -> None:
        """Forward inbound reaction TAGMSGs to the gateway's reaction hook.

        Typing and other ephemera are ignored; so are our own reactions.
        """
        sender = _extract_nick(msg["prefix"])
        if sender.lower() == self._current_nick.lower():
            return
        reaction = tags.get("+react")
        unreact = tags.get("+freeq.at/unreact")
        emoji = reaction or unreact
        if not emoji:
            return
        handler = getattr(self, "_reaction_handler", None)
        if handler is None:
            return
        is_channel = target.startswith(("#", "&"))
        await handler(
            {
                "platform": "freeq",
                "event_name": "reaction:added" if reaction else "reaction:removed",
                "reaction": emoji,
                "user_id": tags.get("account") or sender,
                "user_name": sender,
                "chat_id": target if is_channel else sender,
                "message_id": tags.get("+reply"),
                "raw_tags": tags,
            }
        )

    # ── Inbound media ─────────────────────────────────────────────────────

    async def _cache_inbound_media(
        self, attachment: _MediaAttachment
    ) -> Optional[Tuple[str, str, _MediaAttachment]]:
        """Download an attachment into the local media cache.

        Returns ``(local_path, mime, attachment)`` or ``None`` when the
        download is skipped or fails; the message then dispatches as text.
        """
        if not _url_is_fetchable(attachment.url):
            logger.warning("freeq: skipping media with unfetchable URL: %s", attachment.url)
            return None
        if attachment.size and attachment.size > self._media_max_bytes:
            logger.warning("freeq: skipping media over size limit (%s bytes)", attachment.size)
            return None
        try:
            async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
                async with client.stream("GET", attachment.url) as resp:
                    resp.raise_for_status()
                    chunks: List[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > self._media_max_bytes:
                            logger.warning("freeq: media download exceeded %s bytes, aborting", self._media_max_bytes)
                            return None
                        chunks.append(chunk)
                    header_mime = resp.headers.get("content-type", "").split(";")[0].strip()
        except httpx.HTTPError as e:
            logger.warning("freeq: media download failed for %s: %s", attachment.url, e)
            return None
        data = b"".join(chunks)
        mime = attachment.mime or header_mime or "application/octet-stream"
        path = cache_media_bytes(data, mime, filename_hint=attachment.filename or "")
        return path, mime, attachment

    async def _dispatch_message(
        self,
        text: str,
        chat_id: str,
        chat_type: str,
        user_id: str,
        user_name: str,
    ) -> None:
        """Build a MessageEvent (with any pending media) and dispatch it.

        ``user_id`` is the sender's DID when the account tag is present.
        Unauthenticated guests fall back to the nick.
        """
        media = self._pending_media
        account = self._pending_account
        msgid = self._pending_msgid
        self._pending_media = None
        self._pending_account = None
        self._pending_msgid = None
        if not self._message_handler:
            return
        if account:
            user_id = account
        # Legacy single-PRIVMSG multiline form: newlines arrive escaped.
        text = text.replace("\\n", "\n")

        media_urls: List[str] = []
        media_types: List[str] = []
        message_type = MessageType.TEXT
        if media:
            path, mime, attachment = media
            media_urls = [path]
            media_types = [mime]
            message_type = _message_type_for_mime(mime)
            # The body is the plain-text fallback ("<alt> <url>"); strip the
            # blob URL so the agent sees the caption.
            text = text.replace(attachment.url, "").strip() or (attachment.alt or "")

        source = self.build_source(
            chat_id=chat_id,
            chat_name=chat_id,
            chat_type=chat_type,
            user_id=user_id,
            user_name=user_name,
        )
        event = MessageEvent(
            text=text,
            message_type=message_type,
            source=source,
            message_id=msgid or str(int(time.time() * 1000)),
            media_urls=media_urls,
            media_types=media_types,
            user_id=user_id,
            user_name=user_name,
            timestamp=datetime.now(),
        )
        await self.handle_message(event)

    # ── Outbound media ────────────────────────────────────────────────────

    async def _upload_to_pds(
        self,
        data: bytes,
        mime: str,
        alt: Optional[str],
        channel: Optional[str],
    ) -> Dict[str, Any]:
        """Upload a blob, pin it with a blue.irc.media record, return its URL."""
        blob_json = await self._atproto.xrpc_post(
            "com.atproto.repo.uploadBlob", content=data, content_type=mime
        )
        blob = blob_json["blob"]
        cid = blob["ref"]["$link"]
        size = int(blob.get("size", len(data)))
        mime = blob.get("mimeType", mime)
        did, _, pds_url = await self._atproto.session()

        # The pin record stops the PDS from garbage-collecting the blob.
        record = {
            "$type": "blue.irc.media",
            "blob": blob,
            "mimeType": mime,
            "alt": alt or "",
            "channel": channel,
            "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        await self._atproto.xrpc_post(
            "com.atproto.repo.createRecord",
            json_body={"repo": did, "collection": "blue.irc.media", "record": record},
        )

        # The image CDN only serves images; other blobs use the raw PDS URL.
        if mime.startswith("image/"):
            ext = {"image/png": "png", "image/webp": "webp", "image/gif": "gif"}.get(mime, "jpeg")
            url = f"https://cdn.bsky.app/img/feed_fullsize/plain/{did}/{cid}@{ext}"
        else:
            url = f"{pds_url}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
        return {"url": url, "cid": cid, "size": size, "mime": mime}

    async def _send_tagged(self, target: str, tags: Dict[str, str], body: str) -> SendResult:
        """Send a single PRIVMSG with an IRCv3 tag block."""
        if not self._writer or self._writer.is_closing():
            return SendResult(success=False, error="Not connected")
        tag_block = ";".join(f"{k}={_escape_tag_value(v)}" for k, v in tags.items())
        body = body.replace("\r", " ").replace("\n", " ")
        try:
            await self._send_raw(f"@{tag_block} PRIVMSG {target} :{body}")
        except (OSError, ConnectionError) as e:
            return SendResult(success=False, error=str(e))
        return SendResult(success=True, message_id=str(int(time.time() * 1000)))

    async def _send_media(
        self,
        chat_id: str,
        data: bytes,
        mime: str,
        caption: Optional[str],
        filename: Optional[str] = None,
    ) -> SendResult:
        """Upload media to the PDS and deliver it as a tagged PRIVMSG."""
        if self._media_uploads == "off":
            notice = "[attachment withheld: media uploads are disabled on this platform]"
            if caption:
                notice = f"{caption}\n{notice}"
            return await self.send(chat_id, notice)
        if not self._atproto.configured:
            return SendResult(
                success=False,
                error="Freeq media requires atproto credentials (FREEQ_ATPROTO_HANDLE / FREEQ_ATPROTO_APP_PASSWORD)",
            )
        if len(data) > self._media_max_bytes:
            return SendResult(success=False, error=f"file exceeds media size limit ({self._media_max_bytes} bytes)")
        try:
            upload = await self._upload_to_pds(data, mime, caption, chat_id)
        except (httpx.HTTPError, RuntimeError, KeyError, ValueError) as e:
            logger.error("freeq: PDS media upload failed: %s", e)
            return SendResult(success=False, error=f"PDS upload failed: {e}")

        tags = {
            _TAG_PREFIX + "media-mime": upload["mime"],
            _TAG_PREFIX + "media-url": upload["url"],
            _TAG_PREFIX + "media-size": str(upload["size"]),
        }
        if caption:
            tags[_TAG_PREFIX + "media-alt"] = caption
        if filename:
            tags[_TAG_PREFIX + "media-filename"] = filename
        fallback = f"{caption} {upload['url']}" if caption else upload["url"]
        signed = self._signature_tags(chat_id, fallback, tags)
        if signed:
            tags.update(signed[1])
        result = await self._send_tagged(chat_id, tags, fallback)
        if result.success and signed:
            return SendResult(success=True, message_id=signed[0])
        return result

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        try:
            if image_url.startswith(("http://", "https://")):
                async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
                    resp = await client.get(image_url)
                    resp.raise_for_status()
                data = resp.content
                mime = resp.headers.get("content-type", "").split(";")[0].strip() or "image/jpeg"
                filename = os.path.basename(urlparse(image_url).path) or None
            else:
                data, mime, filename = _read_local_media(image_url, "image/jpeg")
        except (httpx.HTTPError, OSError) as e:
            return SendResult(success=False, error=f"could not read image: {e}")
        return await self._send_media(chat_id, data, mime, caption, filename)

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        try:
            data, mime, filename = _read_local_media(image_path, "image/jpeg")
        except OSError as e:
            return SendResult(success=False, error=f"could not read image: {e}")
        return await self._send_media(chat_id, data, mime, caption, filename)

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        try:
            data, mime, filename = _read_local_media(file_path, "application/octet-stream")
        except OSError as e:
            return SendResult(success=False, error=f"could not read file: {e}")
        return await self._send_media(chat_id, data, mime, caption, file_name or filename)

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        try:
            data, mime, filename = _read_local_media(video_path, "video/mp4")
        except OSError as e:
            return SendResult(success=False, error=f"could not read video: {e}")
        return await self._send_media(chat_id, data, mime, caption, filename)

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        try:
            data, mime, filename = _read_local_media(audio_path, "audio/ogg")
        except OSError as e:
            return SendResult(success=False, error=f"could not read audio: {e}")
        return await self._send_media(chat_id, data, mime, caption, filename)


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def check_requirements() -> bool:
    """Check if freeq is configured via env vars."""
    return bool(os.getenv("FREEQ_SERVER", "") and os.getenv("FREEQ_CHANNEL", ""))


def validate_config(config) -> bool:
    """Validate that the platform config has enough info to connect."""
    extra = getattr(config, "extra", {}) or {}
    server = os.getenv("FREEQ_SERVER") or extra.get("server", "")
    channel = os.getenv("FREEQ_CHANNEL") or extra.get("channel", "")
    return bool(server and channel)


def is_connected(config) -> bool:
    """Check whether freeq is configured (env or config.yaml)."""
    return validate_config(config)


def _env_enablement() -> Optional[dict]:
    """Seed ``PlatformConfig.extra`` from env vars during gateway config load."""
    server = os.getenv("FREEQ_SERVER", "").strip()
    channel = os.getenv("FREEQ_CHANNEL", "").strip()
    if not (server and channel):
        return None
    seed: dict = {"server": server, "channel": channel}
    port = os.getenv("FREEQ_PORT", "").strip()
    if port:
        try:
            seed["port"] = int(port)
        except ValueError:
            pass
    nickname = os.getenv("FREEQ_NICKNAME", "").strip()
    if nickname:
        seed["nickname"] = nickname
    use_tls = os.getenv("FREEQ_USE_TLS", "").strip().lower()
    if use_tls:
        seed["use_tls"] = use_tls in {"1", "true", "yes"}
    home = os.getenv("FREEQ_HOME_CHANNEL") or channel
    seed["home_channel"] = {
        "chat_id": home,
        "name": os.getenv("FREEQ_HOME_CHANNEL_NAME", home),
    }
    return seed


def register(ctx):
    """Plugin entry point: called by the Hermes plugin system."""
    ctx.register_platform(
        name="freeq",
        label="Freeq",
        adapter_factory=lambda cfg: FreeqAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["FREEQ_SERVER", "FREEQ_CHANNEL", "FREEQ_NICKNAME"],
        install_hint="No extra packages needed (httpx ships with hermes)",
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="FREEQ_HOME_CHANNEL",
        allowed_users_env="FREEQ_ALLOWED_USERS",
        allow_all_env="FREEQ_ALLOW_ALL_USERS",
        max_message_length=4000,
        emoji="📡",
        pii_safe=False,
        allow_update_command=True,
        platform_hint=(
            "You are chatting via Freeq, an IRC network with AT Protocol "
            "identity. Markdown is rendered by freeq clients, and a "
            "multi-line reply is delivered as a single message. You can "
            "send images and files: they are uploaded to your atproto PDS "
            "and delivered as rich media attachments. In channels, users "
            "address you by prefixing your nick. Keep responses concise "
            "and conversational."
        ),
    )
