# hermes-freeq

Connects your [Hermes Agent](https://github.com/NousResearch/hermes-agent) to a [freeq](https://github.com/freeq-irc/freeq) server (IRC with atproto identity) as a first-class messaging platform. Authenticate with the agent's own atproto account or a guest mode fallback.

## Features

- User authorization by atproto DID: use an allowlist to control which accounts can interact with the agent.
- Markdown-rendered messages.
- Message signing with a persistent session ed25519 key.
- Media support
  - Attachments are downloaded for vision.
  - Uploads default to the freeq server's private media store.
  - Set `FREEQ_MEDIA_UPLOADS=pds` to upload to the account's PDS instead.
- Hermes slash commands are typed with `!` (`!help`, `!status`), since IRC clients reserve `/` for their own commands.
- Tool progress / working status output are consolidated in a single message using edits.
- Support for reactions, outbound (in progress, success, failure) and inbound (forwarded to the gateway's reaction hooks).
- Typing indicators.
- Reply threading on outbound messages.
- Channel addressing by `nick:`, `nick`, or `@nick` with history replay suppression when the gateway reconnects (preventing re-answering old messages).

## Not yet implemented

Compared to the more mature Hermes gateway integrations (Matrix, Discord, Slack):

- Offline DM catch-up: the server persists DMs sent while the agent is offline, but the adapter does not yet pull them via CHATHISTORY on reconnect.
- Inbound reply context: replies don't get the quoted-message text, so some context is assumed.
- Out-of-process cron delivery: cron jobs require the gateway process to be running.
- End-to-end encrypted chat: message text is plaintext PRIVMSG on the wire.
- Native interactive prompts: approvals and clarify questions render as text rather than reaction-driven pickers.
- Message deletion.

## Attribution

- Builds on hermes-agent's bundled IRC platform plugin (MIT, Copyright 2025 Nous Research).
- `tests/chat-signing-vectors.json` is vendored verbatim from freeq's `spec/` (MIT, Copyright 2025 Chad Fowler).
