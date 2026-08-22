# proton-mail-mcp

A personal [MCP](https://modelcontextprotocol.io) server for a ProtonMail account, talking to **Proton Mail Bridge** over local IMAP/SMTP. Single file, stdlib-only — no third-party dependencies, so the whole thing can be read and audited in a few minutes. That matters here: this handles your mail credentials.

## Why local-only

This is designed to run on your own machine and nowhere else — no server, no shared secrets manager, no network listener. The Bridge password lives only in a local config file with `600` permissions; it is never committed, never sent to a remote service, never shared with anyone else who might administer infrastructure you also use. If you don't run it, it can't be read; if someone doesn't have a shell on your machine, they can't reach it. That's a much stronger and simpler guarantee than any amount of access-policy engineering on a shared/hosted setup would give you.

## Requirements

- [Proton Mail Bridge](https://proton.me/mail/bridge), installed and logged in. Bridge (and therefore IMAP/SMTP access) requires a **paid Proton plan** (Mail Plus or higher) — it is not available on the free tier.
- Python 3.9+ (stdlib only — nothing to `pip install`).
- Claude Desktop and/or Claude Code.

## Setup

1. Open Proton Mail Bridge and make sure your account is logged in.
2. In Bridge, get the **Bridge-specific password** for a mail client (this is different from your normal Proton account password).
3. Clone this repo somewhere on your machine.
4. Create the config file (kept outside the repo, on purpose):
   ```sh
   mkdir -p ~/.config/proton-mcp
   cp config.example.json ~/.config/proton-mcp/config.json
   chmod 600 ~/.config/proton-mcp/config.json
   ```
   Edit `~/.config/proton-mcp/config.json` and fill in `email` and `bridge_password`. Leave `imap_port`/`smtp_port` as-is unless you changed them in Bridge's settings.
5. Register the server with your Claude client(s):

   **Claude Code:**
   ```sh
   claude mcp add -s user proton-mail-personal -- python3 /path/to/proton-mail-mcp/server.py
   ```

   **Claude Desktop** — add to `claude_desktop_config.json` (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS) under `mcpServers`, then restart the app:
   ```json
   "proton-mail-personal": {
     "command": "python3",
     "args": ["/path/to/proton-mail-mcp/server.py"]
   }
   ```

## Multiple accounts

Proton Mail Bridge supports logging in more than one account at once, each getting its own local IMAP/SMTP port pair (visible in Bridge's account settings). This server takes its config path as an optional first argument (or the `PROTON_MCP_CONFIG` env var) instead of always defaulting to `~/.config/proton-mcp/config.json`, so run one process per account and register each as its own MCP server:

```sh
# second account
cp config.example.json ~/.config/proton-mcp/config-work.json
chmod 600 ~/.config/proton-mcp/config-work.json
# edit it with the second account's email + its own Bridge password + the IMAP/SMTP ports Bridge assigned it

claude mcp add -s user proton-mail-work -- python3 /path/to/proton-mail-mcp/server.py ~/.config/proton-mcp/config-work.json
```

Claude Desktop: same idea, add a second `mcpServers` entry with its own name and `"args": ["/path/to/server.py", "/Users/you/.config/proton-mcp/config-work.json"]`.

Each account gets its own config file (so its own file permissions and blast radius) and its own set of tool names (`mcp__proton-mail-work__search_emails` vs. `mcp__proton-mail-personal__search_emails`) — no shared state between them, and no extra "which account" parameter to pass on every call.

## Tools

| Tool | Read-only | Notes |
|---|---|---|
| `list_folders` | yes | folders/labels available |
| `search_emails` | yes | see below |
| `get_email` | yes | full body by UID, truncated past `max_chars` |
| `get_unread_count` | yes | |
| `mark_read` | no | toggles `\Seen`, reversible |
| `move_email` | no | to an existing folder/label |
| `reply_to_email` | no | threads via In-Reply-To/References, quotes the original |
| `create_draft` | no | saves without sending |
| `send_email` | no | |

Every non-read-only tool is annotated as such (`readOnlyHint: false`), so MCP clients will ask for confirmation before running it.

### `search_emails`

Searches the whole account by default (Proton Bridge exposes a virtual `All Mail` folder, like Gmail's), not just one folder — pass `folder` to scope it. Filters (`text`, `from_addr`, `to_addr`, `cc_addr`, `subject`, `unread_only`, `since`/`before`, `has_attachment`) are ANDed together and support full UTF-8 (accented text works — see [Implementation notes](#implementation-notes)).

Results are ranked by the message's actual `Date` header, not IMAP UID — Bridge's `All Mail` UIDs are **not** chronological (verified: a same-day message can have a lower UID than one over a year old), and Bridge doesn't support the `SORT` extension, so real recency requires reading the date. Each result includes a short `snippet` of the body, so you often won't need a follow-up `get_email` call at all. `total_matched` + `offset` support pagination.

`has_attachment` has no native IMAP search key to lean on, so it scans messages newest-first (real-date order) up to `scan_cap` (default 300, raise it if `scan_capped` comes back `true` and you need older matches) — unbounded scanning over a large mailbox with no other filter would be slow, so this is a deliberate, visible cap rather than a silent one. It fetches the full message (not just `BODYSTRUCTURE`) to check for attachments, trading some bandwidth for reusing Python's own well-tested MIME parser instead of hand-rolling an IMAP `BODYSTRUCTURE` parser (the stdlib has none) — fine over loopback, but worth knowing if you raise `scan_cap` a lot.

## Security model

- The server only ever talks to Bridge on `127.0.0.1` — no other network activity.
- The Bridge password lives only in `~/.config/proton-mcp/config.json` (mode `600`), read once at startup. It is never logged, never included in error messages, never written anywhere else.
- TLS to Bridge's loopback IMAP/SMTP is left unverified by default (Bridge issues a fresh self-signed cert per install; there's no network path for a MITM on loopback, so this is a deliberate, scoped exception, not a blanket bypass). If you want strict verification anyway, export Bridge's cert (Bridge → Settings → Export TLS certificate) and set `tls_cert_path` in the config.

## Implementation notes

- `imaplib` encodes normal command arguments as ASCII and raises `UnicodeEncodeError` on anything else — so any user-supplied search text is sent as an IMAP *literal* (`{n}\r\n<utf-8 bytes>`) with `CHARSET UTF-8` declared, which is the only way through `imaplib` to search for non-ASCII text correctly. Each literal-bearing keyword (`FROM`/`TO`/`CC`/`SUBJECT`/`TEXT`) is searched separately and the resulting UID sets are intersected client-side, because `imaplib` only supports one literal per command.
- Date ranking batches a header-only `UID FETCH` (comma-joined UID set, chunked) across every matched message — cheap since it skips message bodies — rather than fetching one message at a time.

## License

MIT — see [LICENSE](LICENSE).
