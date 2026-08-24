"""Tests for the freeq platform adapter."""

import asyncio
import base64
import json
from datetime import datetime, timezone

import httpx
import pytest

from freeq_plugin import adapter as freeq
from freeq_plugin.adapter import (
    FreeqAdapter,
    _b64url_decode,
    _b64url_encode,
    _escape_tag_value,
    _media_from_tags,
    _message_type_for_mime,
    _parse_message_tags,
    _unescape_tag_value,
    _url_is_fetchable,
    _AtprotoSession,
)

from gateway.config import PlatformConfig
from gateway.platforms.base import MessageEvent, MessageType


def make_adapter(**extra_overrides) -> FreeqAdapter:
    extra = {
        "server": "irc.example.org",
        "port": 6697,
        "nickname": "testbot",
        "channel": "#general",
        "use_tls": True,
        "atproto_handle": "bot.example.com",
        "atproto_app_password": "app-pass",
        "atproto_pds_url": "https://pds.example.com",
    }
    extra.update(extra_overrides)
    return FreeqAdapter(PlatformConfig(enabled=True, extra=extra))


class CaptureRaw:
    """Async _send_raw replacement that records sent lines."""

    def __init__(self):
        self.lines = []

    async def __call__(self, line: str) -> None:
        self.lines.append(line)


# ── Tag helpers ──────────────────────────────────────────────────────────


class TestTagHelpers:

    def test_escape_roundtrip(self):
        value = "a cat; with\\stuff and spaces\r\n"
        assert _unescape_tag_value(_escape_tag_value(value)) == value

    def test_unescape_lone_trailing_backslash_dropped(self):
        assert _unescape_tag_value("abc\\") == "abc"

    def test_parse_message_tags(self):
        tags = _parse_message_tags("+freeq.at/media-alt=a\\scat;+freeq.at/media-size=42;flag")
        assert tags["+freeq.at/media-alt"] == "a cat"
        assert tags["+freeq.at/media-size"] == "42"
        assert tags["flag"] == ""

    def test_b64url_roundtrip_no_padding(self):
        data = b'{"nonce":"abc"}'
        encoded = _b64url_encode(data)
        assert "=" not in encoded
        assert _b64url_decode(encoded) == data


# ── Media tag parsing ────────────────────────────────────────────────────


class TestMediaFromTags:

    def test_attachment_parsed(self):
        att = _media_from_tags({
            "+freeq.at/media-url": "https://cdn.bsky.app/img/x.jpeg",
            "+freeq.at/media-mime": "image/jpeg",
            "+freeq.at/media-alt": "a cat",
            "+freeq.at/media-size": "1024",
            "+freeq.at/media-filename": "cat.jpg",
        })
        assert att.url == "https://cdn.bsky.app/img/x.jpeg"
        assert att.mime == "image/jpeg"
        assert att.alt == "a cat"
        assert att.size == 1024
        assert att.filename == "cat.jpg"

    def test_link_preview_is_not_an_attachment(self):
        assert _media_from_tags({
            "+freeq.at/link-url": "https://example.com",
            "+freeq.at/media-url": "https://example.com/og.png",
        }) is None

    def test_returns_none_without_url(self):
        assert _media_from_tags({"+freeq.at/media-mime": "image/png"}) is None

    def test_message_type_for_mime(self):
        assert _message_type_for_mime("image/png") == MessageType.PHOTO
        assert _message_type_for_mime("video/mp4") == MessageType.VIDEO
        assert _message_type_for_mime("audio/ogg") == MessageType.AUDIO
        assert _message_type_for_mime("application/pdf") == MessageType.DOCUMENT


class TestUrlIsFetchable:

    def test_public_https_ok(self):
        assert _url_is_fetchable("https://cdn.bsky.app/img/x.jpeg") is True

    def test_http_rejected(self):
        assert _url_is_fetchable("http://cdn.bsky.app/img/x.jpeg") is False

    def test_localhost_rejected(self):
        assert _url_is_fetchable("https://localhost/blob") is False

    def test_private_ip_rejected(self):
        assert _url_is_fetchable("https://192.168.10.16/blob") is False


# ── CAP / SASL negotiation ───────────────────────────────────────────────


class TestCapSasl:

    @pytest.fixture
    def adapter(self):
        a = make_adapter()
        a._send_raw = CaptureRaw()
        return a

    async def test_cap_ls_requests_wanted_caps(self, adapter):
        await adapter._handle_line(
            ":srv CAP * LS :sasl=ATPROTO-CHALLENGE message-tags server-time account-tag batch"
        )
        assert adapter._send_raw.lines == ["CAP REQ :sasl message-tags server-time account-tag"]

    async def test_cap_ls_multiline_defers_req(self, adapter):
        await adapter._handle_line(":srv CAP * LS * :sasl message-tags")
        assert adapter._send_raw.lines == []
        await adapter._handle_line(":srv CAP * LS :server-time")
        assert adapter._send_raw.lines == ["CAP REQ :sasl message-tags server-time"]

    async def test_cap_ack_starts_sasl(self, adapter):
        await adapter._handle_line(":srv CAP testbot ACK :sasl message-tags server-time")
        assert adapter._send_raw.lines == ["AUTHENTICATE ATPROTO-CHALLENGE"]

    async def test_cap_ack_without_creds_ends_negotiation(self):
        a = make_adapter(atproto_handle="", atproto_app_password="")
        a._send_raw = CaptureRaw()
        await a._handle_line(":srv CAP testbot ACK :sasl message-tags")
        assert a._send_raw.lines == ["CAP END"]

    def test_no_fallback_to_generic_atproto_env(self, monkeypatch):
        monkeypatch.setenv("ATPROTO_HANDLE", "someone-else.example.com")
        monkeypatch.setenv("ATPROTO_APP_PASSWORD", "someone-elses-password")
        adapter = make_adapter(atproto_handle="", atproto_app_password="")
        assert adapter._atproto.configured is False

    async def test_challenge_answered_with_pds_session(self, adapter):
        async def fake_session():
            return "did:plc:abc123", "jwt-token", "https://pds.example.com"

        adapter._atproto.session = fake_session
        challenge = _b64url_encode(json.dumps(
            {"session_id": "s1", "nonce": "n0nce", "timestamp": 1700000000}
        ).encode())
        await adapter._handle_line(f"AUTHENTICATE {challenge}")

        assert len(adapter._send_raw.lines) == 1
        cmd, payload = adapter._send_raw.lines[0].split(" ", 1)
        assert cmd == "AUTHENTICATE"
        response = json.loads(_b64url_decode(payload))
        assert response == {
            "did": "did:plc:abc123",
            "signature": "jwt-token",
            "method": "pds-session",
            "pds_url": "https://pds.example.com",
            "challenge_nonce": "n0nce",
        }

    async def test_sasl_success_ends_cap(self, adapter):
        await adapter._handle_line(":srv 903 testbot :SASL authentication successful")
        assert adapter._sasl_authenticated is True
        assert adapter._send_raw.lines == ["CAP END"]

    async def test_sasl_failure_unblocks_registration_and_fails(self, adapter):
        await adapter._handle_line(":srv 904 testbot :SASL authentication failed")
        assert adapter._sasl_failed is not None
        assert adapter._registration_event.is_set()

    async def test_atproto_login_error_aborts_sasl(self, adapter):
        async def fake_session():
            raise RuntimeError("createSession failed (401)")

        adapter._atproto.session = fake_session
        challenge = _b64url_encode(json.dumps({"nonce": "x"}).encode())
        await adapter._handle_line(f"AUTHENTICATE {challenge}")
        assert adapter._send_raw.lines == ["AUTHENTICATE *"]
        assert "atproto login failed" in adapter._sasl_failed
        assert adapter._registration_event.is_set()


# ── Inbound media dispatch ───────────────────────────────────────────────


class TestInboundMedia:

    async def test_tagged_privmsg_dispatches_media(self, monkeypatch, tmp_path):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._message_handler = object()

        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture

        local = tmp_path / "cat.jpg"
        local.write_bytes(b"jpegdata")

        async def fake_cache(attachment):
            return str(local), "image/jpeg", attachment

        adapter._cache_inbound_media = fake_cache

        line = (
            "@account=did:plc:alice;+freeq.at/media-url=https://cdn.bsky.app/img/x.jpeg;"
            "+freeq.at/media-mime=image/jpeg;+freeq.at/media-alt=a\\scat "
            ":alice!a@host PRIVMSG testbot :a cat https://cdn.bsky.app/img/x.jpeg"
        )
        await adapter._handle_line(line)

        assert len(events) == 1
        event = events[0]
        assert event.media_urls == [str(local)]
        assert event.media_types == ["image/jpeg"]
        assert event.message_type == MessageType.PHOTO
        assert event.text == "a cat"
        assert event.user_id == "did:plc:alice"
        assert event.user_name == "alice"
        assert adapter._pending_media is None
        assert adapter._pending_account is None

    async def test_untagged_privmsg_dispatches_plain_text(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line(":alice!a@host PRIVMSG testbot :hello there")

        assert len(events) == 1
        assert events[0].text == "hello there"
        assert events[0].media_urls == []
        assert events[0].message_type == MessageType.TEXT
        assert events[0].user_id == "alice"

    async def test_at_nick_addressing_dispatches_in_channel(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line(":alice!a@host PRIVMSG #general :@testbot what time is it")

        assert len(events) == 1
        assert events[0].text == "what time is it"
        assert events[0].source.chat_id == "#general"

    async def test_unaddressed_channel_message_ignored(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line(":alice!a@host PRIVMSG #general :hi testbot")

        assert events == []

    async def test_history_replay_dropped_in_channel(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        adapter._connected_at = 1_800_000_000.0
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        old = datetime.fromtimestamp(adapter._connected_at - 600, tz=timezone.utc)
        fresh = datetime.fromtimestamp(adapter._connected_at + 60, tz=timezone.utc)

        stamp = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        await adapter._handle_line(
            f"@time={stamp(old)} :alice!a@host PRIVMSG #general :testbot: old replayed"
        )
        assert events == []
        await adapter._handle_line(
            f"@time={stamp(fresh)} :alice!a@host PRIVMSG #general :testbot: fresh message"
        )
        assert len(events) == 1
        assert events[0].text == "fresh message"

    async def test_replayed_dm_still_dispatches(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        adapter._connected_at = 1_800_000_000.0
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        old = datetime.fromtimestamp(adapter._connected_at - 600, tz=timezone.utc)
        await adapter._handle_line(
            f"@time={old.strftime('%Y-%m-%dT%H:%M:%S.000Z')} "
            ":alice!a@host PRIVMSG testbot :offline dm"
        )
        assert len(events) == 1

    async def test_account_tag_becomes_user_id_without_media(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line(
            "@account=did:plc:alicetestdid;msgid=m1 "
            ":alice!a@host PRIVMSG testbot :hey testbot"
        )

        assert len(events) == 1
        assert events[0].user_id == "did:plc:alicetestdid"
        assert events[0].user_name == "alice"
        assert events[0].source.chat_id == "alice"


class TestSendAndEdit:

    def _connected(self, adapter):
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        return adapter

    async def test_multiline_markdown_sends_as_one_privmsg(self):
        adapter = self._connected(make_adapter())
        result = await adapter.send("#general", "**bold**\nline two")
        assert result.success is True
        assert len(adapter._send_raw.lines) == 1
        line = adapter._send_raw.lines[0]
        tag_block, rest = line[1:].split(" ", 1)
        tags = _parse_message_tags(tag_block)
        assert tags["+freeq.at/mime"] == "text/markdown"
        assert "+freeq.at/multiline" in tags
        assert rest == "PRIVMSG #general :**bold**\\nline two"

    async def test_send_captures_msgid_from_echo(self):
        adapter = self._connected(make_adapter())
        adapter._echo_enabled = True
        adapter._current_nick = "testbot"

        send_task = asyncio.create_task(adapter.send("#general", "hello there"))
        await asyncio.sleep(0.05)
        await adapter._handle_line("@msgid=srv-abc123 :testbot!t@host PRIVMSG #general :hello there")
        result = await send_task
        assert result.message_id == "srv-abc123"

    async def test_own_echo_never_dispatches(self):
        adapter = self._connected(make_adapter())
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line("@msgid=m9 :testbot!t@host PRIVMSG alice :i am testbot")
        assert events == []

    async def test_edit_message_emits_draft_edit(self):
        adapter = self._connected(make_adapter())
        result = await adapter.edit_message("#general", "srv-abc123", "updated\ntext")
        assert result.success is True
        line = adapter._send_raw.lines[0]
        tags = _parse_message_tags(line[1:].split(" ", 1)[0])
        assert tags["+draft/edit"] == "srv-abc123"
        assert "+freeq.at/multiline" in tags

    async def test_edit_refuses_synthetic_timestamp_id(self):
        adapter = self._connected(make_adapter())
        result = await adapter.edit_message("#general", "1755990000000", "text")
        assert result.success is False

    async def test_reply_tag_only_for_server_msgids(self):
        adapter = self._connected(make_adapter())
        await adapter.send("#general", "hi", reply_to="srv-xyz")
        tags = _parse_message_tags(adapter._send_raw.lines[0][1:].split(" ", 1)[0])
        assert tags["+reply"] == "srv-xyz"

        adapter._send_raw.lines.clear()
        await adapter.send("#general", "hi", reply_to="1755990000000")
        tags = _parse_message_tags(adapter._send_raw.lines[0][1:].split(" ", 1)[0])
        assert "+reply" not in tags

    async def test_inbound_msgid_becomes_event_message_id(self):
        adapter = make_adapter()
        adapter._message_handler = object()
        events = []

        async def capture(event):
            events.append(event)

        adapter.handle_message = capture
        await adapter._handle_line("@msgid=in-42 :alice!a@host PRIVMSG testbot :hi\\nthere")
        assert events[0].message_id == "in-42"
        assert events[0].text == "hi\nthere"

    def test_chunker_prefers_paragraph_breaks(self):
        from freeq_plugin.adapter import _chunk_wire_text
        text = ("a" * 50 + "\n\n" + "b" * 50 + "\n\n" + "c" * 50)
        chunks = _chunk_wire_text(text, 120)
        assert len(chunks) == 2
        assert chunks[0].endswith("b" * 50)
        assert chunks[1] == "c" * 50
        assert all(len(c.encode()) <= 120 for c in chunks)


class TestReactions:

    def _connected(self, adapter):
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        return adapter

    async def test_add_reaction_emits_tagmsg_and_records(self):
        adapter = self._connected(make_adapter())
        assert await adapter._add_reaction("#general", "srv-1", "\U0001f440") is True
        assert adapter._send_raw.lines == ["@+react=\U0001f440;+reply=srv-1 TAGMSG #general"]
        assert adapter._own_reactions[("#general", "srv-1")] == "\U0001f440"

    async def test_add_reaction_refuses_synthetic_id(self):
        adapter = self._connected(make_adapter())
        assert await adapter._add_reaction("#general", "1755990000000", "x") is False
        assert adapter._send_raw.lines == []

    async def test_remove_reaction_unreacts_recorded_emoji(self):
        adapter = self._connected(make_adapter())
        await adapter._add_reaction("#general", "srv-1", "\U0001f440")
        adapter._send_raw.lines.clear()
        assert await adapter._remove_reaction("#general", "srv-1") is True
        assert adapter._send_raw.lines == [
            "@+freeq.at/unreact=\U0001f440;+reply=srv-1 TAGMSG #general"
        ]
        assert ("#general", "srv-1") not in adapter._own_reactions

    async def test_processing_start_acks_triggering_message(self):
        adapter = self._connected(make_adapter())
        source = adapter.build_source(
            chat_id="#general", chat_name="#general", chat_type="group",
            user_id="did:plc:x", user_name="alice",
        )
        event = MessageEvent(text="hi", source=source, message_id="srv-7")
        await adapter.on_processing_start(event)
        assert adapter._send_raw.lines == [
            "@+react=\U0001f440;+reply=srv-7 TAGMSG #general",
            "PRESENCE :state=executing",
        ]

    async def test_inbound_reaction_reaches_handler(self):
        adapter = self._connected(make_adapter())
        seen = []

        async def handler(payload):
            seen.append(payload)

        adapter._reaction_handler = handler
        await adapter._handle_line(
            "@+react=\U0001f525;+reply=srv-9;account=did:plc:alice "
            ":alice!a@host TAGMSG #general"
        )
        assert len(seen) == 1
        assert seen[0]["event_name"] == "reaction:added"
        assert seen[0]["reaction"] == "\U0001f525"
        assert seen[0]["user_id"] == "did:plc:alice"
        assert seen[0]["message_id"] == "srv-9"

    async def test_own_and_typing_tagmsgs_ignored(self):
        adapter = self._connected(make_adapter())
        seen = []

        async def handler(payload):
            seen.append(payload)

        adapter._reaction_handler = handler
        await adapter._handle_line("@+react=x;+reply=m1 :testbot!t@host TAGMSG #general")
        await adapter._handle_line("@+typing=active :alice!a@host TAGMSG #general")
        assert seen == []


class TestMessageSigning:

    def _signed_adapter(self):
        from freeq_plugin.signing import ChatSigner
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        adapter._atproto._did = "did:plc:botdid"
        adapter._signer = ChatSigner.from_seed(b"\x01" * 32)
        adapter._msgsig_ready = True
        return adapter

    def _verify_line(self, adapter, line, expected_target, *, body=None, coord=None, edit=None):
        """Reconstruct the signed document from the wire line and verify it."""
        from freeq_plugin.signing import canonicalize, chat_document
        tag_block, rest = line[1:].split(" ", 1)
        tags = _parse_message_tags(tag_block)
        eventid = tags["+freeq.at/eventid"]
        alg, kid, sig = tags["+freeq.at/sig"].split(":")
        assert alg == "ed25519" and kid == adapter._signer.kid
        wire_body = rest.split(" :", 1)[1] if " :" in rest else ""
        doc = chat_document(
            "message",
            from_did="did:plc:botdid",
            msgid=eventid,
            target=expected_target,
            body=body if body is not None else wire_body,
            edit=edit,
            coord=coord,
        )
        public = adapter._signer._key.public_key()
        public.verify(_b64url_decode(sig), canonicalize(doc))
        return tags

    async def test_channel_send_is_signed_and_verifiable(self):
        adapter = self._signed_adapter()
        result = await adapter.send("#General", "**bold**\nline two")
        line = adapter._send_raw.lines[0]
        tags = self._verify_line(adapter, line, "#general")
        assert result.message_id == tags["+freeq.at/eventid"]

    async def test_media_send_signature_covers_coord_tags(self):
        adapter = self._signed_adapter()

        async def fake_upload(data, mime, alt, channel):
            return {"url": "https://cdn.bsky.app/img/z.png", "cid": "c", "size": 4, "mime": mime}

        adapter._upload_to_pds = fake_upload
        result = await adapter._send_media("#general", b"data", "image/png", "a cat", "cat.png")
        assert result.success is True
        line = adapter._send_raw.lines[0]
        coord = {
            "media-mime": "image/png",
            "media-url": "https://cdn.bsky.app/img/z.png",
            "media-size": "4",
            "media-alt": "a cat",
            "media-filename": "cat.png",
        }
        tags = self._verify_line(adapter, line, "#general", coord=coord)
        assert result.message_id == tags["+freeq.at/eventid"]

    async def test_edit_signature_names_root(self):
        adapter = self._signed_adapter()
        await adapter.edit_message("#general", "01ROOT0000000000000000000000", "new text")
        line = adapter._send_raw.lines[0]
        self._verify_line(adapter, line, "#general", edit="01ROOT0000000000000000000000")

    async def test_dm_signed_only_with_known_peer_did(self):
        adapter = self._signed_adapter()
        await adapter.send("alice", "hello")
        assert "+freeq.at/sig" not in adapter._send_raw.lines[0]

        adapter._send_raw.lines.clear()
        adapter._nick_dids["alice"] = "did:plc:alicedid"
        await adapter.send("alice", "hello")
        self._verify_line(
            adapter, adapter._send_raw.lines[0], "dm:did:plc:alicedid,did:plc:botdid"
        )

    async def test_reaction_is_signed(self):
        adapter = self._signed_adapter()
        await adapter._add_reaction("#general", "01ROOT0000000000000000000000", "\U0001f440")
        line = adapter._send_raw.lines[0]
        tags = _parse_message_tags(line[1:].split(" ", 1)[0])
        assert "+freeq.at/eventid" in tags
        assert tags["+freeq.at/sig"].startswith("ed25519:")

    async def test_msgsig_ok_line_arms_signing(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        await adapter._handle_line(":irc.example.org MSGSIG OK")
        assert adapter._msgsig_ready is True
        assert adapter._msgsig_event.is_set()

    async def test_msgsig_fail_leaves_unsigned(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        await adapter._handle_line(
            ":irc.example.org FAIL MSGSIG NOT_AUTHENTICATED :Must be DID-authenticated"
        )
        assert adapter._msgsig_ready is False
        assert adapter._msgsig_event.is_set()


class TestAgentPresence:

    def _connected(self, adapter):
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        return adapter

    async def test_send_presence_format(self):
        adapter = self._connected(make_adapter())
        await adapter._send_presence("executing", status="running tests")
        assert adapter._send_raw.lines == ["PRESENCE :state=executing;status=running tests"]

    async def test_presence_disabled_when_agent_register_off(self):
        adapter = self._connected(make_adapter(agent_register=False))
        await adapter._send_presence("online")
        assert adapter._send_raw.lines == []

    async def test_processing_lifecycle_updates_presence(self):
        adapter = self._connected(make_adapter(reactions=False))
        source = adapter.build_source(
            chat_id="#general", chat_name="#general", chat_type="group",
            user_id="did:plc:x", user_name="alice",
        )
        event = MessageEvent(text="hi", source=source, message_id="srv-1")
        await adapter.on_processing_start(event)
        assert adapter._send_raw.lines == ["PRESENCE :state=executing"]

    async def test_typing_pause_maps_to_waiting_for_input(self):
        adapter = self._connected(make_adapter())
        adapter._loop = asyncio.get_running_loop()
        adapter.pause_typing_for_chat("#general")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert adapter._send_raw.lines == ["PRESENCE :state=waiting_for_input"]
        assert "#general" in adapter._typing_paused


class TestKeepalive:

    def _writer(self, closing=False):
        return type("W", (), {"is_closing": lambda self: closing, "close": lambda self: setattr(self, "closed", True)})()

    async def test_fresh_connection_stays_quiet(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = self._writer()
        adapter._last_rx = __import__("time").time()
        assert await adapter._keepalive_tick() is True
        assert adapter._send_raw.lines == []

    async def test_idle_connection_pings(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = self._writer()
        adapter._last_rx = __import__("time").time() - 90
        assert await adapter._keepalive_tick() is True
        assert adapter._send_raw.lines == ["PING :keepalive"]

    async def test_dead_connection_closed(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        writer = self._writer()
        adapter._writer = writer
        adapter._last_rx = __import__("time").time() - 300
        assert await adapter._keepalive_tick() is False
        assert getattr(writer, "closed", False) is True

    async def test_handle_line_refreshes_last_rx(self):
        adapter = make_adapter()
        adapter._last_rx = 0.0
        await adapter._handle_line("PING :srv")
        assert adapter._last_rx > 0.0


class TestTypingIndicator:

    async def test_send_typing_emits_tagmsg(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        await adapter.send_typing("#general")
        assert adapter._send_raw.lines == ["@+typing=active TAGMSG #general"]

    async def test_stop_typing_emits_done(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()
        await adapter.stop_typing("#general")
        assert adapter._send_raw.lines == ["@+typing=done TAGMSG #general"]

    async def test_send_typing_noop_when_disconnected(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = None
        await adapter.send_typing("#general")
        assert adapter._send_raw.lines == []


# ── Outbound media ───────────────────────────────────────────────────────


class TestOutboundMedia:

    async def test_send_media_builds_tagged_privmsg(self):
        adapter = make_adapter()
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()

        async def fake_upload(data, mime, alt, channel):
            assert channel == "#general"
            return {"url": "https://cdn.bsky.app/img/y.jpeg", "cid": "c1", "size": len(data), "mime": mime}

        adapter._upload_to_pds = fake_upload
        result = await adapter._send_media("#general", b"jpegdata", "image/jpeg", "a cat", "cat.jpg")

        assert result.success is True
        line = adapter._send_raw.lines[0]
        assert line.startswith("@")
        tag_block, rest = line[1:].split(" ", 1)
        tags = _parse_message_tags(tag_block)
        assert tags["+freeq.at/media-url"] == "https://cdn.bsky.app/img/y.jpeg"
        assert tags["+freeq.at/media-mime"] == "image/jpeg"
        assert tags["+freeq.at/media-alt"] == "a cat"
        assert tags["+freeq.at/media-filename"] == "cat.jpg"
        assert rest == "PRIVMSG #general :a cat https://cdn.bsky.app/img/y.jpeg"

    async def test_media_uploads_off_withholds_attachment(self):
        adapter = make_adapter(media_uploads="off")
        adapter._send_raw = CaptureRaw()
        adapter._writer = type("W", (), {"is_closing": lambda self: False})()

        called = []

        async def fake_upload(*args, **kwargs):
            called.append(args)

        adapter._upload_to_pds = fake_upload
        result = await adapter._send_media("#general", b"secret", "application/pdf", "q3 report")

        assert result.success is True
        assert called == []
        line = adapter._send_raw.lines[0]
        assert "attachment withheld" in line
        assert "q3 report" in line
        assert "media-url" not in line

    async def test_send_media_without_creds_fails(self):
        adapter = make_adapter(atproto_handle="", atproto_app_password="")
        result = await adapter._send_media("#general", b"data", "image/png", None)
        assert result.success is False
        assert "atproto credentials" in result.error

    async def test_send_media_over_size_limit_fails(self):
        adapter = make_adapter(media_max_bytes=4)
        result = await adapter._send_media("#general", b"too big", "image/png", None)
        assert result.success is False
        assert "size limit" in result.error


# ── atproto session ──────────────────────────────────────────────────────


_RealAsyncClient = httpx.AsyncClient


def _mock_async_client(handler):
    """Return an httpx.AsyncClient factory bound to a MockTransport handler."""

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    return factory


class TestAtprotoSession:

    async def test_login_and_upload_url_shapes(self, monkeypatch):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path.endswith("createSession"):
                return httpx.Response(200, json={
                    "did": "did:plc:abc",
                    "accessJwt": "access1",
                    "refreshJwt": "refresh1",
                })
            if request.url.path.endswith("uploadBlob"):
                return httpx.Response(200, json={
                    "blob": {"$type": "blob", "ref": {"$link": "cid123"},
                             "mimeType": "image/png", "size": 8},
                })
            if request.url.path.endswith("createRecord"):
                return httpx.Response(200, json={"uri": "at://x", "cid": "rc1"})
            return httpx.Response(404)

        monkeypatch.setattr(freeq.httpx, "AsyncClient", _mock_async_client(handler))

        adapter = make_adapter()
        upload = await adapter._upload_to_pds(b"pngdata!", "image/png", "alt", "#general")

        assert upload["cid"] == "cid123"
        assert upload["url"] == "https://cdn.bsky.app/img/feed_fullsize/plain/did:plc:abc/cid123@png"
        assert any(p.endswith("createRecord") for p in calls)

    async def test_non_image_uses_raw_blob_url(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("createSession"):
                return httpx.Response(200, json={
                    "did": "did:plc:abc", "accessJwt": "a", "refreshJwt": "r",
                })
            if request.url.path.endswith("uploadBlob"):
                return httpx.Response(200, json={
                    "blob": {"$type": "blob", "ref": {"$link": "cid9"},
                             "mimeType": "application/pdf", "size": 3},
                })
            return httpx.Response(200, json={})

        monkeypatch.setattr(freeq.httpx, "AsyncClient", _mock_async_client(handler))

        adapter = make_adapter()
        upload = await adapter._upload_to_pds(b"pdf", "application/pdf", None, None)
        assert upload["url"] == (
            "https://pds.example.com/xrpc/com.atproto.sync.getBlob?did=did:plc:abc&cid=cid9"
        )

    async def test_expired_token_retried_once(self, monkeypatch):
        state = {"logins": 0, "uploads": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("createSession"):
                state["logins"] += 1
                return httpx.Response(200, json={
                    "did": "did:plc:abc",
                    "accessJwt": f"access{state['logins']}",
                    "refreshJwt": "r",
                })
            if request.url.path.endswith("refreshSession"):
                return httpx.Response(400, json={"error": "ExpiredToken"})
            state["uploads"] += 1
            if state["uploads"] == 1:
                return httpx.Response(400, json={"error": "ExpiredToken", "message": "ExpiredToken"})
            return httpx.Response(200, json={"blob": {}})

        monkeypatch.setattr(freeq.httpx, "AsyncClient", _mock_async_client(handler))

        session = _AtprotoSession("h", "p", "https://pds.example.com")
        result = await session.xrpc_post("com.atproto.repo.uploadBlob", content=b"x", content_type="image/png")
        assert result == {"blob": {}}
        assert state["uploads"] == 2
        assert state["logins"] == 2

    async def test_create_session_failure_raises(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "AuthenticationRequired"})

        monkeypatch.setattr(freeq.httpx, "AsyncClient", _mock_async_client(handler))

        session = _AtprotoSession("h", "bad", "https://pds.example.com")
        with pytest.raises(RuntimeError, match="createSession failed"):
            await session.session()
