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
| `download_attachment` | no | saves to disk under `downloads_dir` (default `~/Downloads/proton-mail-mcp`), one subfolder per folder/UID |
| `get_unread_count` | yes | |
| `mark_read` | no | toggles `\Seen`, reversible |
| `move_email` | no | to an existing folder/label |
| `reply_to_email` | no | threads via In-Reply-To/References, quotes the original; optional local attachments |
| `create_draft` | no | saves without sending (to/cc/bcc, optional local attachments), returns the new draft's UID |
| `create_reply_draft` | no | like `reply_to_email` but saved to Drafts instead of sent — see [Drafts](#drafts) for the threading caveat |
| `update_draft` | no | edits a draft: only the fields passed change, the rest (incl. HTML body and attachments) is carried over; returns the draft's **new** UID |
| `send_draft` | no | sends a saved draft exactly as reviewed (recipients, From, body, attachments, reply threading all from the draft); Drafts folder only, refuses anything not flagged `\Draft`; afterwards moves the draft to Trash unless `keep_draft` |
| `delete_draft` | no | Drafts folder only, refuses anything not flagged `\Draft`; moves to Trash (recoverable) instead of expunging, since Bridge turns an expunge from Drafts into a permanent delete |
| `send_email` | no | optional local attachments (same path rules and 25 MB total as drafts); Bcc goes only in the envelope |

Every non-read-only tool is annotated as such (`readOnlyHint: false`), so MCP clients will ask for confirmation before running it.

### `search_emails`

Searches the whole account by default (Proton Bridge exposes a virtual `All Mail` folder, like Gmail's), not just one folder — pass `folder` to scope it. Filters (`text`, `from_addr`, `to_addr`, `cc_addr`, `subject`, `unread_only`, `since`/`before`, `has_attachment`) are ANDed together and support full UTF-8 (accented text works — see [Implementation notes](#implementation-notes)).

Results are ranked by the message's actual `Date` header, not IMAP UID — Bridge's `All Mail` UIDs are **not** chronological (verified: a same-day message can have a lower UID than one over a year old), and Bridge doesn't support the `SORT` extension, so real recency requires reading the date. Each result includes a short `snippet` of the body, so you often won't need a follow-up `get_email` call at all. `total_matched` + `offset` support pagination.

`has_attachment` has no native IMAP search key to lean on, so it scans messages newest-first (real-date order) up to `scan_cap` (default 300, raise it if `scan_capped` comes back `true` and you need older matches) — unbounded scanning over a large mailbox with no other filter would be slow, so this is a deliberate, visible cap rather than a silent one. It fetches the full message (not just `BODYSTRUCTURE`) to check for attachments, trading some bandwidth for reusing Python's own well-tested MIME parser instead of hand-rolling an IMAP `BODYSTRUCTURE` parser (the stdlib has none) — fine over loopback, but worth knowing if you raise `scan_cap` a lot.

### Drafts

How Proton Bridge treats drafts shapes these tools (read in `proton-bridge` `internal/services/imapservice/connector.go`, then verified live):

- An IMAP `APPEND` into `Drafts` becomes a real Proton draft: Bridge calls Proton's CreateDraft API (subject, body, To/Cc/**Bcc**) and uploads every attachment part. So attaching a file = putting it in the appended MIME message.
- Messages in IMAP are immutable, so `update_draft` saves a new version and moves the old one to Trash — the draft's UID changes on every edit (the new one is returned). The old version is never expunged: Bridge turns an expunge out of Drafts/Trash into a permanent server-side delete. The new version is built from scratch, never by re-appending fetched bytes: Bridge stamps fetched messages with `X-Pm-Internal-Id`, which it uses to recognize a re-`APPEND`ed copy of an existing message.
- Bridge creates drafts with **no `ParentID`** and drops `In-Reply-To`/`References`, so a draft from `create_reply_draft` is not linked to the original conversation: in Proton it sits in its own thread, and if sent from the Proton app it may not thread for the recipient. There is no way around this over IMAP. `reply_to_email` (SMTP) doesn't have the problem: Bridge's SMTP path does resolve the parent from those headers. For the same reason, editing a draft that was started as a reply in the Proton app unlinks it.
- Bridge serves non-ASCII attachment names as RFC 2047 encoded-words inside the `filename` parameter (`=?utf-8?q?fattura_citt=C3=A0.txt?=`), which Python's `get_filename()` leaves encoded; names are decoded before being listed or matched.

Attachments are read from local paths given by the model, which may be acting on attacker-written mail, so paths must be absolute, and hidden files/directories (dotfiles, `~/.ssh`, `~/.config` — including this server's own config) and `~/Library` are refused after resolving symlinks. Total attachment size is capped at Proton's 25 MB per message. It's a guard against the obvious prompt-injection ("attach ~/.ssh/id_ed25519"), not a sandbox.

## Security model

- The server only ever talks to Bridge on `127.0.0.1` — no other network activity.
- The Bridge password lives only in `~/.config/proton-mcp/config.json` (mode `600`), read once at startup. It is never logged, never included in error messages, never written anywhere else.
- Draft attachments can only be read from absolute, non-hidden paths outside `~/Library` (see [Drafts](#drafts)); attaching is only offered on drafts, so a file never leaves the account without first sitting in Drafts.
- TLS to Bridge's loopback IMAP/SMTP is left unverified by default (Bridge issues a fresh self-signed cert per install; there's no network path for a MITM on loopback, so this is a deliberate, scoped exception, not a blanket bypass). If you want strict verification anyway, export Bridge's cert (Bridge → Settings → Export TLS certificate) and set `tls_cert_path` in the config.

## Implementation notes

- `imaplib` encodes normal command arguments as ASCII and raises `UnicodeEncodeError` on anything else — so any user-supplied search text is sent as an IMAP *literal* (`{n}\r\n<utf-8 bytes>`) with `CHARSET UTF-8` declared, which is the only way through `imaplib` to search for non-ASCII text correctly. Each literal-bearing keyword (`FROM`/`TO`/`CC`/`SUBJECT`/`TEXT`) is searched separately and the resulting UID sets are intersected client-side, because `imaplib` only supports one literal per command.
- Date ranking batches a header-only `UID FETCH` (comma-joined UID set, chunked) across every matched message — cheap since it skips message bodies — rather than fetching one message at a time.
- `download_attachment`'s filename comes from the email itself, which is untrusted content — a message could name its attachment `../../.ssh/authorized_keys` (or bare `..`) to try to write outside the intended folder. The filename is reduced to its basename and a bare `.`/`..` is rejected outright before it ever reaches a path.

## License

MIT — see [LICENSE](LICENSE).
