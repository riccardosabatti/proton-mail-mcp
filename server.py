#!/usr/bin/env python3
"""Personal ProtonMail MCP server — stdio transport, stdlib-only.

Talks to Proton Mail Bridge over local IMAP/SMTP. Never leaves this machine:
no network listener, no shared credential store. Config (incl. the Bridge
password) lives in ~/.config/proton-mcp/config.json by default, mode 600,
read once at startup.

Multiple accounts: Bridge itself supports logging in more than one account,
each on its own local IMAP/SMTP port pair. Point separate invocations of this
same script at separate config files (one per account) — pass the path as the
first CLI arg, or set PROTON_MCP_CONFIG — and register each as its own MCP
server (e.g. "proton-mail-personal", "proton-mail-work"). Tool names then
naturally disambiguate accounts (mcp__proton-mail-work__search_emails vs.
mcp__proton-mail-personal__search_emails) with no extra "account" parameter
needed on every call.
"""
import sys
import os
import json
import ssl
import re
import html
import imaplib
import smtplib
import datetime
import base64
import copy
import mimetypes
import subprocess
import tempfile
import shutil
import time
import urllib.parse
import urllib.request
from email import encoders, message_from_bytes
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr, getaddresses, parsedate_to_datetime, formatdate, make_msgid

CONFIG_PATH = os.path.expanduser(
    sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PROTON_MCP_CONFIG", "~/.config/proton-mcp/config.json")
)
SERVER_NAME = "proton-mail-personal"
SERVER_VERSION = "1.0.0"
MAX_SEARCH_LIMIT = 100
DEFAULT_SEARCH_LIMIT = 20
DEFAULT_SEARCH_FOLDER = "All Mail"
DRAFTS_FOLDER = "Drafts"
TRASH_FOLDER = "Trash"
DEFAULT_MAX_BODY_CHARS = 6000
SNIPPET_CHARS = 200
HAS_ATTACHMENT_SCAN_CAP = 300
DEFAULT_DOWNLOADS_DIR = "~/Downloads/proton-mail-mcp"
VIEW_ATTACHMENT_MAX_BYTES = 8 * 1024 * 1024  # inline preview cap — above this, use download_attachment
# Claude's image content block only accepts these four; anything else sent as an "image" media_type
# is rejected by the API schema, and MCP's alternative "resource" content type was verified live to
# not work either — the claude.ai/Desktop client coerces it into an image block anyway and hits the
# same media_type rejection instead of falling back gracefully. So a PDF can't be sent as-is; it has
# to be rasterized to actual PNG pages first (see _render_pdf_to_png_pages) to go through this path.
ALLOWED_IMAGE_MEDIA_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
PDF_MAX_PAGES = 5  # cap on how many rendered pages one view_attachment call will return
PDF_RENDER_DPI = 150  # legible for text-heavy documents (e.g. invoices) without ballooning PNG size
MAX_ATTACHMENTS_TOTAL_BYTES = 25 * 1024 * 1024  # Proton's per-message attachment limit


def log(msg):
    # MCP stdio reserves stdout for protocol frames — all diagnostics go to stderr.
    print(f"[proton-mcp] {msg}", file=sys.stderr, flush=True)


def load_config():
    global SERVER_NAME, DEFAULT_SEARCH_FOLDER, DRAFTS_FOLDER, TRASH_FOLDER
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    # auth "xoauth2" (Gmail / Google Workspace): an OAuth refresh token instead of a
    # Bridge password. The token's account must be `email`.
    secret = ("oauth_client_id", "oauth_client_secret", "oauth_refresh_token") if cfg.get("auth") == "xoauth2" \
        else ("bridge_password",)
    missing = [k for k in ("email",) + secret if not cfg.get(k)]
    if missing:
        raise RuntimeError(
            f"config missing {missing} — fill in {CONFIG_PATH} (chmod 600) before connecting a client"
        )
    # Folder names differ per server (Gmail: "[Gmail]/Tutti i messaggi", "[Gmail]/Bozze"
    # ... in the account's language): `folders` in the config overrides Bridge's.
    folders = cfg.get("folders") or {}
    DEFAULT_SEARCH_FOLDER = folders.get("all", DEFAULT_SEARCH_FOLDER)
    DRAFTS_FOLDER = folders.get("drafts", DRAFTS_FOLDER)
    TRASH_FOLDER = folders.get("trash", TRASH_FOLDER)
    SERVER_NAME = cfg.get("server_name", SERVER_NAME)
    return cfg


_oauth = {"token": None, "expires": 0.0}


def _oauth_token(cfg):
    """Access token from the refresh token, cached until a minute before it expires."""
    if _oauth["token"] and time.time() < _oauth["expires"] - 60:
        return _oauth["token"]
    body = urllib.parse.urlencode({
        "client_id": cfg["oauth_client_id"], "client_secret": cfg["oauth_client_secret"],
        "refresh_token": cfg["oauth_refresh_token"], "grant_type": "refresh_token",
    }).encode()
    with urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/token", data=body),
                                timeout=CONNECT_TIMEOUT) as r:
        j = json.load(r)
    _oauth["token"], _oauth["expires"] = j["access_token"], time.time() + int(j.get("expires_in", 3600))
    return _oauth["token"]


def _xoauth2(cfg):
    return f"user={cfg['email']}\x01auth=Bearer {_oauth_token(cfg)}\x01\x01"


def make_ssl_context(cfg):
    ctx = ssl.create_default_context()
    if cfg.get("tls_verify"):  # a real server (Gmail): normal certificate checks
        return ctx
    cert_path = cfg.get("tls_cert_path")
    if cert_path:
        ctx.load_verify_locations(cafile=cert_path)
    else:
        # Bridge issues a self-signed cert for its loopback-only IMAP/SMTP.
        # No network path exists for a MITM on 127.0.0.1, so skipping verification
        # here is a deliberate, scoped exception — not a general TLS bypass.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


CONNECT_TIMEOUT = 15


def imap_connect(cfg):
    ctx = make_ssl_context(cfg)
    if cfg.get("imap_ssl"):  # implicit TLS (imap.gmail.com:993)
        conn = imaplib.IMAP4_SSL(cfg["imap_host"], cfg["imap_port"], ssl_context=ctx, timeout=CONNECT_TIMEOUT)
    else:
        conn = imaplib.IMAP4(cfg["imap_host"], cfg["imap_port"], timeout=CONNECT_TIMEOUT)
        conn.starttls(ssl_context=ctx)
    if cfg.get("auth") == "xoauth2":
        conn.authenticate("XOAUTH2", lambda _: _xoauth2(cfg).encode())
    else:
        conn.login(cfg["email"], cfg["bridge_password"])
    # imaplib caches CAPABILITY from before login and never refreshes it, but Bridge
    # only advertises MOVE/UIDPLUS once authenticated (verified) — without this
    # re-read every `"MOVE" in conn.capabilities` check silently takes the fallback.
    status, data = conn.capability()
    if status == "OK" and data and data[-1]:
        conn.capabilities = tuple(data[-1].decode().upper().split())
    return conn


def imap_folder_list(cfg):
    conn = imap_connect(cfg)
    try:
        status, data = conn.list()
        if status != "OK":
            raise RuntimeError(f"IMAP LIST failed: {data}")
        folders = []
        pat = re.compile(r'^\(([^)]*)\)\s+"([^"]*)"\s+(.*)$')
        for line in data:
            line = line.decode(errors="replace") if isinstance(line, bytes) else line
            m = pat.match(line)
            if not m:
                continue
            flags, _delim, name = m.groups()
            name = name.strip()
            if name.startswith('"') and name.endswith('"'):
                name = name[1:-1]
            folders.append({"name": name, "flags": flags})
        return folders
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _imap_date(s):
    d = datetime.datetime.strptime(s, "%Y-%m-%d")
    return d.strftime("%d-%b-%Y")


def _imap_quote(s):
    # IMAP quoted-string: backslash-escape backslashes and double quotes, or an
    # embedded '"' (e.g. a subject like `She said "hi"`) breaks the command syntax.
    # A raw CR/LF is worse than a syntax error: imaplib appends exactly one CRLF
    # at the end of the whole command line and does no per-arg sanitization, so
    # an embedded one here would terminate the current IMAP command early and
    # inject a second, attacker-chosen command into the authenticated session.
    if "\r" in s or "\n" in s:
        raise ValueError("value must not contain CR/LF")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _validate_uid(uid):
    # A UID tool argument must name exactly one message. Without this, a value
    # like "1:*" is a syntactically valid IMAP sequence-set (not a single UID),
    # so e.g. mark_read(uid="1:*") would silently apply to the entire folder.
    s = str(uid)
    if not re.fullmatch(r"\d+", s):
        raise ValueError(f"invalid uid {uid!r} — must be a single numeric UID, not a range or set")
    return s


def _reject_crlf(value, field):
    if value and ("\r" in value or "\n" in value):
        raise ValueError(f"{field} must not contain newlines")
    return value


def _decode_header_value(raw):
    if raw is None:
        return ""
    from email.header import decode_header

    parts = decode_header(raw)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _uid_search_plain(conn, criteria):
    # ASCII-only keywords/dates — no literal needed.
    if not criteria:
        return None
    status, data = conn.uid("SEARCH", None, *criteria)
    if status != "OK":
        raise RuntimeError(f"IMAP SEARCH failed: {data}")
    return {u.decode() for u in data[0].split()}


def _uid_search_literal(conn, keyword, value):
    # imaplib encodes normal args as ASCII (crashes on e.g. "città"), so any
    # user-supplied text goes as an IMAP literal instead — the only way through
    # imaplib to send arbitrary UTF-8 octets, declared via CHARSET UTF-8.
    conn.literal = value.encode("utf-8")
    status, data = conn.uid("SEARCH", "CHARSET", "UTF-8", keyword)
    if status != "OK":
        raise RuntimeError(f"IMAP SEARCH {keyword} failed: {data}")
    return {u.decode() for u in data[0].split()}


def _addr_list(*values):
    # email.utils.getaddresses has a real footgun: with >=2 empty strings in
    # its input list it silently collapses to a single bogus ('', '') result
    # instead of parsing the non-empty ones (verified: getaddresses(['a@b.com',
    # '', '']) == [('', '')], dropping 'a@b.com' entirely) — so always filter
    # blanks out before calling it, never pass optional cc/bcc through as "".
    return getaddresses([v for v in values if v])


def _snippet(body, n=SNIPPET_CHARS):
    flat = " ".join(body.split())
    return flat if len(flat) <= n else flat[:n] + "…"


def _fetch_full(conn, uid):
    status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[] FLAGS)")
    if status != "OK" or not msg_data or msg_data[0] is None:
        return None, None
    flags_raw = msg_data[0][0]
    flags_blob = flags_raw.decode(errors="replace") if isinstance(flags_raw, bytes) else str(flags_raw)
    return message_from_bytes(msg_data[0][1]), flags_blob


def _result_from_msg(uid, msg, flags_blob):
    return {
        "uid": uid,
        "from": _decode_header_value(msg.get("From")),
        "to": _decode_header_value(msg.get("To")),
        "subject": _decode_header_value(msg.get("Subject")),
        "date": msg.get("Date", ""),
        "unread": "\\Seen" not in flags_blob,
        "attachments": _attachment_list(msg),
        "snippet": _snippet(_extract_body(msg)),
    }


_EPOCH_MIN = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def _parse_date(date_str):
    try:
        dt = parsedate_to_datetime(date_str or "")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return _EPOCH_MIN


def _uid_fetch_dates(conn, uids, chunk_size=500):
    # Proton Bridge's virtual "All Mail" folder assigns UIDs with NO correlation
    # to message date (verified live: a same-day message can have a lower UID
    # than one a year old), and Bridge doesn't support the SORT extension —
    # so "most recent" requires actually reading Date, not trusting UID order.
    # Batching many UIDs into one FETCH (comma-joined) keeps this to a handful
    # of round trips instead of one per message.
    uids = list(uids)
    dates = {}
    uid_re = re.compile(rb"UID (\d+)")
    for i in range(0, len(uids), chunk_size):
        chunk = uids[i : i + chunk_size]
        status, msg_data = conn.uid("FETCH", ",".join(chunk), "(BODY.PEEK[HEADER.FIELDS (DATE)])")
        if status != "OK":
            continue
        pending_header = None
        for item in msg_data:
            if isinstance(item, tuple):
                # Gmail puts the UID before the literal ("1 (UID 13 BODY[...] {40}"),
                # Bridge after it (the next b" UID 13)" item).
                m = uid_re.search(item[0])
                if m:
                    dates[m.group(1).decode()] = _parse_date(message_from_bytes(item[1]).get("Date", ""))
                    pending_header = None
                else:
                    pending_header = item[1]
                continue
            m = uid_re.search(item) if isinstance(item, bytes) else None
            if m and pending_header is not None:
                msg = message_from_bytes(pending_header)
                dates[m.group(1).decode()] = _parse_date(msg.get("Date", ""))
            pending_header = None
    return dates


def imap_search(
    cfg,
    folder,
    text,
    from_addr,
    to_addr,
    cc_addr,
    subject,
    unread_only,
    since,
    before,
    has_attachment,
    scan_cap,
    limit,
    offset,
):
    limit = max(1, min(limit or DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT))
    offset = max(0, offset or 0)
    scan_cap = max(1, min(scan_cap or HAS_ATTACHMENT_SCAN_CAP, 2000))
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r} (check the name via list_folders)")

        constraint_sets = []
        plain = []
        if unread_only:
            plain.append("UNSEEN")
        if since:
            plain += ["SINCE", _imap_date(since)]
        if before:
            plain += ["BEFORE", _imap_date(before)]
        plain_set = _uid_search_plain(conn, plain)
        if plain_set is not None:
            constraint_sets.append(plain_set)
        if from_addr:
            constraint_sets.append(_uid_search_literal(conn, "FROM", from_addr))
        if to_addr:
            constraint_sets.append(_uid_search_literal(conn, "TO", to_addr))
        if cc_addr:
            constraint_sets.append(_uid_search_literal(conn, "CC", cc_addr))
        if subject:
            constraint_sets.append(_uid_search_literal(conn, "SUBJECT", subject))
        if text:
            constraint_sets.append(_uid_search_literal(conn, "TEXT", text))

        uids = set.intersection(*constraint_sets) if constraint_sets else _uid_search_plain(conn, ["ALL"])
        dated = _uid_fetch_dates(conn, uids)
        ranked = sorted(uids, key=lambda u: dated.get(u, _EPOCH_MIN), reverse=True)  # true newest-first

        results = []
        scan_capped = False
        total_matched = None
        if has_attachment:
            skipped = 0
            for i, uid in enumerate(ranked):
                if i >= scan_cap:
                    scan_capped = True
                    break
                msg, flags_blob = _fetch_full(conn, uid)
                if msg is None or not _attachment_list(msg):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                results.append(_result_from_msg(uid, msg, flags_blob))
                if len(results) >= limit:
                    break
        else:
            total_matched = len(ranked)
            for uid in ranked[offset : offset + limit]:
                msg, flags_blob = _fetch_full(conn, uid)
                if msg is not None:
                    results.append(_result_from_msg(uid, msg, flags_blob))

        return {
            "folder": folder,
            "results": results,
            "total_matched": total_matched,  # None when has_attachment: true (no full-mailbox scan is done)
            "scan_capped": scan_capped,  # true => has_attachment hit scan_cap before filling the page; raise scan_cap or narrow other filters
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _strip_html(h):
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", h)
    text = re.sub(r"(?s)<br\s*/?>", "\n", text)
    text = re.sub(r"(?s)</p>", "\n\n", text)
    text = re.sub(r"(?s)<[^>]+>", "", text)
    return html.unescape(text).strip()


def _extract_body(msg):
    if msg.is_multipart():
        plain, html_part = None, None
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if ctype == "text/plain" and plain is None:
                plain = part.get_payload(decode=True)
                plain_charset = part.get_content_charset() or "utf-8"
            elif ctype == "text/html" and html_part is None:
                html_part = part.get_payload(decode=True)
                html_charset = part.get_content_charset() or "utf-8"
        if plain is not None:
            return plain.decode(plain_charset, errors="replace")
        if html_part is not None:
            return _strip_html(html_part.decode(html_charset, errors="replace"))
        return ""
    else:
        payload = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if msg.get_content_type() == "text/html":
            text = _strip_html(text)
        return text


def _part_filename(part):
    name = " ".join((part.get_filename() or "").split())  # un-fold a wrapped RFC 2231 filename header
    # Bridge rebuilds non-ASCII attachment names as RFC 2047 encoded-words inside the filename
    # parameter (verified: "fattura città.txt" comes back as "=?utf-8?q?fattura_citt=C3=A0.txt?="),
    # which get_filename() leaves encoded.
    if "=?" in name:
        try:
            return _decode_header_value(name)
        except Exception:
            pass
    return name


def _attachment_list(msg):
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                names.append(_part_filename(part) or "(unnamed)")
    return names


def imap_get_email(cfg, folder, uid, max_chars):
    uid = _validate_uid(uid)
    max_chars = max_chars or DEFAULT_MAX_BODY_CHARS
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or msg_data[0] is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")
        raw = msg_data[0][1]
        msg = message_from_bytes(raw)
        body = _extract_body(msg)
        truncated = len(body) > max_chars
        if truncated:
            body = body[:max_chars] + f"\n\n[...truncated, {len(body) - max_chars} more characters]"
        return {
            "uid": str(uid),
            "from": _decode_header_value(msg.get("From")),
            "to": _decode_header_value(msg.get("To")),
            "cc": _decode_header_value(msg.get("Cc")),
            "bcc": _decode_header_value(msg.get("Bcc")),  # only ever present on drafts
            "subject": _decode_header_value(msg.get("Subject")),
            "date": msg.get("Date", ""),
            "body": body,
            "truncated": truncated,
            "attachments": _attachment_list(msg),
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_download_attachment(cfg, folder, uid, filename):
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or msg_data[0] is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")
        msg = message_from_bytes(msg_data[0][1])

        match = None
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                name = _part_filename(part)
                if name == filename:
                    match = part
                    break
        if match is None:
            raise RuntimeError(f"no attachment named {filename!r} on uid {uid} — available: {_attachment_list(msg)}")

        # The filename comes from the email itself (untrusted) — an
        # attachment could claim a name like "../../.ssh/authorized_keys" to
        # escape the intended directory. basename() strips any path
        # components, but a bare "." or ".." has none to strip and would
        # resolve to the containing directory itself, so reject those too.
        safe_name = os.path.basename(filename)
        if not safe_name or safe_name in (".", ".."):
            safe_name = "attachment"
        out_dir = os.path.join(
            os.path.expanduser(cfg.get("downloads_dir") or DEFAULT_DOWNLOADS_DIR),
            folder.replace("/", "_"),
            uid,
        )
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, safe_name)
        payload = match.get_payload(decode=True) or b""
        with open(out_path, "wb") as f:
            f.write(payload)

        return {
            "path": out_path,
            "filename": safe_name,
            "size_bytes": len(payload),
            "content_type": match.get_content_type(),
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_fetch_attachment_bytes(cfg, folder, uid, filename):
    # Raw fetch only — no size gating, no base64. Callers (view_attachment_content)
    # decide what cap makes sense for the content_type they got back (a source PDF
    # gets rasterized before its real output size is known, so gating here would be
    # gating the wrong number).
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or msg_data[0] is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")
        msg = message_from_bytes(msg_data[0][1])

        match = None
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                name = _part_filename(part)
                if name == filename:
                    match = part
                    break
        if match is None:
            raise RuntimeError(f"no attachment named {filename!r} on uid {uid} — available: {_attachment_list(msg)}")

        payload = match.get_payload(decode=True) or b""
        return payload, match.get_content_type() or "application/octet-stream"
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _render_pdf_to_png_pages(payload):
    # Shells out to poppler's pdftoppm rather than adding a PDF-parsing dependency —
    # keeps the server stdlib-only on the Python side; poppler is a system package
    # (`brew install poppler`), not a pip dependency of this project.
    pdftoppm = shutil.which("pdftoppm")
    if not pdftoppm:
        raise RuntimeError(
            "pdftoppm (poppler) not found on this machine — install it (`brew install poppler`) to "
            "enable inline PDF preview, or use download_attachment instead"
        )
    with tempfile.TemporaryDirectory(prefix="proton-mcp-pdf-") as tmpdir:
        src_path = os.path.join(tmpdir, "in.pdf")
        with open(src_path, "wb") as f:
            f.write(payload)
        out_prefix = os.path.join(tmpdir, "page")
        proc = subprocess.run(
            [pdftoppm, "-png", "-r", str(PDF_RENDER_DPI), "-f", "1", "-l", str(PDF_MAX_PAGES), src_path, out_prefix],
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"pdftoppm failed: {proc.stderr.decode(errors='replace')[:500]}")
        page_files = sorted(f for f in os.listdir(tmpdir) if f.startswith("page") and f.endswith(".png"))
        if not page_files:
            raise RuntimeError("pdftoppm produced no pages — the PDF may be empty, encrypted, or corrupted")
        pages = []
        for f in page_files:
            with open(os.path.join(tmpdir, f), "rb") as fh:
                pages.append(fh.read())
        return pages


def imap_unread_count(cfg, folder):
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r} (check the name via list_folders)")
        status, data = conn.uid("SEARCH", None, "UNSEEN")
        if status != "OK":
            raise RuntimeError(f"IMAP SEARCH failed: {data}")
        return {"folder": folder, "unread": len(data[0].split())}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_mark_read(cfg, folder, uid, read):
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        op = "+FLAGS" if read else "-FLAGS"
        status, data = conn.uid("STORE", uid, op, "(\\Seen)")
        if status != "OK":
            raise RuntimeError(f"IMAP STORE failed: {data}")
        return {"uid": uid, "folder": folder, "read": read}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _uid_move(conn, uid, target_folder):
    # Prefer RFC 6851 MOVE (atomic); fall back to COPY+\Deleted+EXPUNGE for
    # servers that don't advertise it. imaplib.capabilities is always a
    # tuple of str (see IMAP4._get_capabilities), never bytes.
    if "MOVE" in conn.capabilities:
        status, data = conn.uid("MOVE", uid, _imap_quote(target_folder))
        if status != "OK":
            raise RuntimeError(f"IMAP MOVE failed: {data}")
    else:
        status, data = conn.uid("COPY", uid, _imap_quote(target_folder))
        if status != "OK":
            raise RuntimeError(f"IMAP COPY failed: {data}")
        conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        conn.expunge()


def imap_move(cfg, folder, uid, target_folder):
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        _uid_move(conn, uid, target_folder)
        return {"uid": uid, "from": folder, "to": target_folder}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _unfold(raw):
    # A header value carried over from a fetched message (To/Cc/Subject of a draft being
    # edited) can be folded across lines; collapse it so no CR/LF reaches the new header.
    return " ".join((raw or "").split())


def _load_local_attachment(path):
    # Attachment paths come from the model, which may be acting on attacker-written mail — a
    # prompt-injected "attach ~/.ssh/id_ed25519 to a draft" is the case to defend against. Drafts
    # sync to Proton's servers and are one click from being sent, so refuse hidden files/dirs
    # (dotfiles, ~/.ssh, ~/.aws, ~/.config — which holds this server's own Bridge password) and
    # ~/Library (keychains, browser profiles). Checked after resolving symlinks, so a link planted
    # in ~/Downloads can't point back into them. A guard against the obvious, not a sandbox.
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        raise ValueError(f"attachment path {path!r} must be absolute")
    real = os.path.realpath(expanded)
    if any(part.startswith(".") for part in real.split(os.sep)):
        raise ValueError(f"refusing to attach {path!r}: hidden files and directories are off-limits")
    library = os.path.realpath(os.path.expanduser("~/Library"))
    if real == library or real.startswith(library + os.sep):
        raise ValueError(f"refusing to attach {path!r}: ~/Library is off-limits")
    if not os.path.isfile(real):
        raise ValueError(f"attachment {path!r} is not an existing regular file")
    size = os.path.getsize(real)
    if size > MAX_ATTACHMENTS_TOTAL_BYTES:
        raise ValueError(f"attachment {path!r} is {size} bytes, over Proton's {MAX_ATTACHMENTS_TOTAL_BYTES}-byte limit")
    with open(real, "rb") as f:
        data = f.read()
    ctype, encoding = mimetypes.guess_type(real)
    if ctype is None or encoding is not None:  # e.g. .tar.gz guesses as tar + gzip encoding — send the bytes as-is
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)
    part = MIMEBase(maintype, subtype)
    part.set_payload(data)
    encoders.encode_base64(part)
    # Name it after the path as given, not the symlink target. Non-ASCII names are RFC 2231-encoded by the stdlib.
    part.add_header("Content-Disposition", "attachment", filename=os.path.basename(expanded))
    return part, len(data)


def _attachment_parts(paths, already_bytes=0):
    if isinstance(paths, str):
        paths = [paths]
    parts, total = [], already_bytes
    for p in paths or []:
        part, size = _load_local_attachment(p)
        total += size
        if total > MAX_ATTACHMENTS_TOTAL_BYTES:
            raise ValueError(f"attachments total {total} bytes, over Proton's {MAX_ATTACHMENTS_TOTAL_BYTES}-byte per-message limit")
        parts.append(part)
    return parts


def _from_addr(cfg):
    return parseaddr(cfg.get("from") or cfg["email"])[1] or cfg["email"]


_send_as = {"addrs": None, "expires": 0.0}


def _gmail_send_as(cfg):
    """Addresses Gmail will put in From: as given (primary + accepted send-as), cached 5 min.
    Any other From is silently rewritten to the primary address by Gmail."""
    if _send_as["addrs"] is not None and time.time() < _send_as["expires"]:
        return _send_as["addrs"]
    req = urllib.request.Request(
        "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs",
        headers={"Authorization": f"Bearer {_oauth_token(cfg)}"},
    )
    with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT) as r:
        rows = json.load(r).get("sendAs", [])
    addrs = {s["sendAsEmail"].lower() for s in rows if s.get("isPrimary") or s.get("verificationStatus") == "accepted"}
    _send_as["addrs"], _send_as["expires"] = addrs, time.time() + 300
    return addrs


def _pick_from(cfg, requested=None, orig=None):
    """The From address for an outgoing message, and a note when it had to fall back.

    `requested` must be one of the account's own addresses (login or `aliases`). With
    none, a reply goes out from the own address the original was sent to (so mail to
    info@ is answered from info@), anything else from the config's `from`. On Gmail an
    address that is not an accepted send-as would be rewritten to the login: a requested
    one is refused, an implicit one falls back to the login and says so."""
    own = [cfg["email"]] + list(cfg.get("aliases", []))
    by_lower = {a.lower(): a for a in own}
    if requested:
        _reject_crlf(requested, "from")
        addr = parseaddr(requested)[1].lower()
        if addr not in by_lower:
            raise RuntimeError(f"from {requested!r} is not an address of this account — use one of {own}")
        chosen, explicit = by_lower[addr], True
    else:
        chosen, explicit = None, False
        if orig is not None:
            for header in ("To", "Cc", "Delivered-To", "X-Original-To"):
                hit = next((by_lower[a.lower()] for _, a in getaddresses(orig.get_all(header, [])) if a.lower() in by_lower), None)
                if hit:
                    chosen = hit
                    break
        chosen = chosen or _from_addr(cfg)
    if cfg.get("auth") != "xoauth2" or chosen.lower() == cfg["email"].lower():
        return chosen, None
    if chosen.lower() in _gmail_send_as(cfg):
        return chosen, None
    hint = f"{chosen} is not a Gmail send-as address of {cfg['email']} yet (Gmail would rewrite From to {cfg['email']})"
    if explicit:
        raise RuntimeError(hint)
    return cfg["email"], hint + f" — sent from {cfg['email']}"


def _compose(cfg, to, subject, body_parts, cc=None, bcc=None, attachments=(), extra_headers=(), from_header=None):
    parts = list(body_parts) + list(attachments)
    if not parts:
        parts = [MIMEText("", "plain", "utf-8")]
    if len(parts) == 1:
        msg = parts[0]
    else:
        msg = MIMEMultipart("mixed")
        for p in parts:
            msg.attach(p)
    if "MIME-Version" not in msg:  # a body part carried over from a multipart draft has none of its own
        msg["MIME-Version"] = "1.0"
    msg["Subject"] = subject
    msg["From"] = from_header or cfg.get("from") or cfg["email"]
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    if bcc:  # only ever set on drafts — Bridge reads it to fill the draft's BCC list
        msg["Bcc"] = bcc
    for name, value in extra_headers:
        if value:
            msg[name] = value
    return msg


def _append_draft(conn, msg):
    # Bridge turns an APPEND into Drafts into a real Proton draft (CreateDraft + one
    # UploadAttachment per attachment part — proton-bridge imapservice/connector.go,
    # createDraftWithParser). as_bytes(), not as_string(): a body part carried over from a
    # fetched draft can hold raw 8-bit bytes that only round-trip through the bytes generator.
    status, data = conn.append(_imap_quote(DRAFTS_FOLDER), "(\\Draft)", None, msg.as_bytes())
    if status != "OK":
        raise RuntimeError(f"IMAP APPEND failed: {data}")
    # UIDPLUS (RFC 4315) reports the new message's UID as `[APPENDUID <validity> <uid>]` —
    # hand it back so the caller can edit/delete the draft without a search round trip.
    m = re.search(rb"APPENDUID \d+ (\d+)", data[0] or b"") if data else None
    return m.group(1).decode() if m else None


def _draft_result(uid, msg):
    result = {
        "folder": DRAFTS_FOLDER,
        "from": _decode_header_value(msg.get("From")),
        "to": _decode_header_value(msg.get("To")),
        "cc": _decode_header_value(msg.get("Cc")),
        "bcc": _decode_header_value(msg.get("Bcc")),
        "subject": _decode_header_value(msg.get("Subject")),
        "attachments": _attachment_list(msg),
    }
    if uid:
        result["uid"] = uid
    return result


def _fetch_draft(conn, uid, section):
    # The Drafts folder must already be selected. Refuses anything not flagged \Draft, so a
    # draft tool can never be turned on real mail that ended up in Drafts.
    status, data = conn.uid("FETCH", uid, f"(FLAGS {section})")
    if status != "OK" or not data or not isinstance(data[0], tuple):
        raise RuntimeError(f"no draft with uid {uid} in {DRAFTS_FOLDER!r} (find it via search_emails with folder='Drafts')")
    # FLAGS can come before or after the literal depending on the server.
    meta = b" ".join([data[0][0]] + [x for x in data[1:] if isinstance(x, bytes)]).decode(errors="replace")
    if "\\Draft" not in meta:
        raise RuntimeError(f"uid {uid} in {DRAFTS_FOLDER!r} is not flagged \\Draft — refusing to touch it")
    return message_from_bytes(data[0][1])


def _smtp_deliver(cfg, msg, all_recipients):
    # Unlike Bridge's IMAP (plaintext + STARTTLS), its SMTP port expects TLS
    # from the first byte (implicit TLS, like SMTPS) — STARTTLS here just hangs
    # waiting for a plaintext greeting that never comes, until it times out.
    ctx = make_ssl_context(cfg)
    if cfg.get("auth") == "xoauth2":  # Gmail: STARTTLS on 587, then XOAUTH2
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=CONNECT_TIMEOUT) as server:
            server.starttls(context=ctx)
            server.ehlo()
            code, resp = server.docmd("AUTH", "XOAUTH2 " + base64.b64encode(_xoauth2(cfg).encode()).decode())
            if code != 235:
                raise RuntimeError(f"SMTP XOAUTH2 failed: {code} {resp[:200]!r}")
            server.sendmail(parseaddr(msg["From"])[1] or _from_addr(cfg), all_recipients, msg.as_string())
        return
    with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=ctx, timeout=CONNECT_TIMEOUT) as server:
        server.login(cfg["email"], cfg["bridge_password"])
        server.sendmail(cfg["email"], all_recipients, msg.as_string())


def smtp_send(cfg, to, subject, body, cc, bcc, from_addr=None, attachments=None):
    for field, value in (("to", to), ("subject", subject), ("cc", cc), ("bcc", bcc)):
        _reject_crlf(value, field)
    sender, note = _pick_from(cfg, from_addr)
    files = _attachment_parts(attachments)  # validated before anything goes out
    # Bcc stays out of the headers: the recipients get it only through the envelope.
    msg = _compose(cfg, to, subject, [MIMEText(body, "plain", "utf-8")], cc, None, files, from_header=sender)
    all_recipients = [addr for _, addr in _addr_list(to, cc, bcc) if addr]
    _smtp_deliver(cfg, msg, all_recipients)
    result = {"from": sender, "sent_to": all_recipients, "subject": subject}
    if files:
        result["attachments"] = _attachment_list(msg)
    if note:
        result["note"] = note
    return result


def _reply_fields(cfg, orig, body, reply_all):
    orig_subject = _decode_header_value(orig.get("Subject"))
    orig_subject = orig_subject.replace("\r", " ").replace("\n", " ")  # a malformed inbound header must not carry into our outgoing one
    reply_subject = orig_subject if orig_subject.lower().startswith("re:") else f"Re: {orig_subject}"

    orig_from = orig.get("From", "")
    to_addrs = [orig_from] if orig_from else []
    cc_addrs = []
    if reply_all:
        # Our own addresses never get the reply: the account, its `from`, its `aliases`.
        selves = {cfg["email"].lower(), _from_addr(cfg).lower()} | {a.lower() for a in cfg.get("aliases", [])}
        orig_from_addr = parseaddr(orig_from)[1].lower()
        already = {parseaddr(orig_from)[1].lower()}
        for n, a in getaddresses([orig.get("To", "")]):
            if a and a.lower() not in selves | {orig_from_addr} and a.lower() not in already:
                to_addrs.append(formataddr((n, a)))
                already.add(a.lower())
        for n, a in getaddresses([orig.get("Cc", "")]):
            if a and a.lower() not in selves | {orig_from_addr} and a.lower() not in already:
                cc_addrs.append(formataddr((n, a)))
                already.add(a.lower())

    orig_msgid = orig.get("Message-ID", "")
    orig_refs = orig.get("References", "")
    references = f"{orig_refs} {orig_msgid}".strip() if orig_refs else orig_msgid

    orig_body = _extract_body(orig)
    quoted = "\n".join(f"> {line}" for line in orig_body.splitlines())
    return {
        "subject": reply_subject,
        "to": ", ".join(to_addrs),
        "cc": ", ".join(cc_addrs),
        "body": f"{body}\n\nOn {orig.get('Date', '')}, {orig_from} wrote:\n{quoted}",
        "threading": (("In-Reply-To", orig_msgid), ("References", references)),
        "in_reply_to": orig_msgid,
    }


def imap_reply(cfg, folder, uid, body, reply_all, from_addr=None, attachments=None):
    uid = _validate_uid(uid)
    files = _attachment_parts(attachments)  # validated before anything goes out
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        orig, _flags = _fetch_full(conn, uid)
        if orig is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")

        sender, note = _pick_from(cfg, from_addr, orig)
        r = _reply_fields(cfg, orig, body, reply_all)
        msg = _compose(
            cfg, r["to"], r["subject"], [MIMEText(r["body"], "plain", "utf-8")], r["cc"],
            attachments=files, extra_headers=r["threading"], from_header=sender,
        )

        all_recipients = [addr for _, addr in _addr_list(r["to"], r["cc"]) if addr]
        _smtp_deliver(cfg, msg, all_recipients)

        try:
            conn.uid("STORE", uid, "+FLAGS", "(\\Answered)")
        except Exception:
            pass  # best-effort — the reply already went out, don't fail the tool over a flag

        result = {"from": sender, "sent_to": all_recipients, "subject": r["subject"], "in_reply_to": r["in_reply_to"]}
        if files:
            result["attachments"] = _attachment_list(msg)
        if note:
            result["note"] = note
        return result
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_create_draft(cfg, to, subject, body, cc, bcc, attachments, from_addr=None):
    for field, value in (("to", to), ("subject", subject), ("cc", cc), ("bcc", bcc)):
        _reject_crlf(value, field)
    sender, note = _pick_from(cfg, from_addr)
    msg = _compose(cfg, to, subject, [MIMEText(body, "plain", "utf-8")], cc, bcc, _attachment_parts(attachments), from_header=sender)
    conn = imap_connect(cfg)
    try:
        result = _draft_result(_append_draft(conn, msg), msg)
        if note:
            result["note"] = note
        return result
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_create_reply_draft(cfg, folder, uid, body, reply_all, attachments, from_addr=None):
    uid = _validate_uid(uid)
    att_parts = _attachment_parts(attachments)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        orig, _flags = _fetch_full(conn, uid)
        if orig is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")
        sender, note = _pick_from(cfg, from_addr, orig)
        r = _reply_fields(cfg, orig, body, reply_all)
        # Bridge drops In-Reply-To/References here: it creates the draft through Proton's API
        # with no ParentID (verified live and in createDraftWithParser), so the draft is not
        # linked to the original conversation. Set anyway — it's what a mail client would send.
        msg = _compose(
            cfg, r["to"], r["subject"], [MIMEText(r["body"], "plain", "utf-8")], r["cc"],
            attachments=att_parts, extra_headers=r["threading"], from_header=sender,
        )
        result = _draft_result(_append_draft(conn, msg), msg)
        result["in_reply_to"] = r["in_reply_to"]
        if note:
            result["note"] = note
        return result
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _content_only(part):
    # A part carried over into an edited draft keeps only its Content-* headers. When the
    # draft is single-part the "part" is the whole fetched message, whose headers include
    # Bridge's X-Pm-Internal-Id — which Bridge uses to recognize an APPEND as a copy of an
    # existing message. The new version has to look like a brand-new message.
    part = copy.deepcopy(part)
    for k in set(part.keys()):
        if not k.lower().startswith("content-") and k.lower() != "mime-version":
            del part[k]
    return part


def imap_update_draft(cfg, uid, to, subject, body, cc, bcc, attachments, remove_attachments, from_addr=None):
    # IMAP messages are immutable, so "edit in place" = APPEND the new version, then move
    # the old one to Trash (recoverable, same as delete_draft). APPEND first, so a failure
    # in between leaves two drafts rather than none.
    uid = _validate_uid(uid)
    for field, value in (("to", to), ("subject", subject), ("cc", cc), ("bcc", bcc)):
        _reject_crlf(value, field)
    if isinstance(remove_attachments, str):
        remove_attachments = [remove_attachments]
    new_from = _pick_from(cfg, from_addr)[0] if from_addr else None
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(DRAFTS_FOLDER), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {DRAFTS_FOLDER!r}")
        old = _fetch_draft(conn, uid, "BODY.PEEK[]")

        # Bridge serves drafts flat: a single body part, or multipart/mixed of body part(s)
        # followed by attachments (verified on live drafts, incl. HTML ones from the web app).
        children = old.get_payload() if old.get_content_type() == "multipart/mixed" else [old]
        body_parts = [p for p in children if p.get_content_disposition() != "attachment"]
        kept = [p for p in children if p.get_content_disposition() == "attachment"]
        names = [_part_filename(p) or "(unnamed)" for p in kept]
        drop = {" ".join(n.split()) for n in (remove_attachments or [])}
        if drop - set(names):
            raise RuntimeError(f"no attachment(s) {sorted(drop - set(names))} on draft uid {uid} — available: {names}")
        body_parts = [MIMEText(body, "plain", "utf-8")] if body is not None else [_content_only(p) for p in body_parts]
        carried = []
        for p, n in zip(kept, names):
            if n in drop:
                continue
            p = _content_only(p)
            if p.get_filename():
                # Re-state the decoded name rather than hand Bridge back its own RFC 2047-in-a-parameter
                # form, which isn't standard and would risk the literal "=?utf-8?q?…?=" becoming the name.
                del p["Content-Disposition"]
                p.add_header("Content-Disposition", "attachment", filename=n)
                p.del_param("name")
            carried.append(p)
        kept = carried
        kept_bytes = sum(len(p.get_payload(decode=True) or b"") for p in kept)
        new_parts = _attachment_parts(attachments, kept_bytes)

        msg = _compose(
            cfg,
            to if to is not None else _unfold(old.get("To")),
            subject if subject is not None else _unfold(old.get("Subject")),
            body_parts,
            cc if cc is not None else _unfold(old.get("Cc")),
            bcc if bcc is not None else _unfold(old.get("Bcc")),
            kept + new_parts,
            extra_headers=(("In-Reply-To", _unfold(old.get("In-Reply-To"))), ("References", _unfold(old.get("References")))),
            from_header=new_from or _unfold(old.get("From")) or None,  # else keep the address/alias the draft already had
        )
        new_uid = _append_draft(conn, msg)
        try:
            _uid_move(conn, uid, TRASH_FOLDER)
        except Exception as e:
            raise RuntimeError(
                f"saved the edited draft as uid {new_uid}, but could not move the old version (uid {uid}) "
                f"to {TRASH_FOLDER}: {e} — both versions are now in {DRAFTS_FOLDER}"
            )
        result = _draft_result(new_uid, msg)
        result["previous_uid"] = uid
        result["previous_moved_to"] = TRASH_FOLDER
        return result
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _mark_answered(conn, msgid):
    """Best effort: flag the message a sent draft replied to as \\Answered, wherever INBOX has it."""
    if not msgid:
        return
    try:
        conn.select(_imap_quote("INBOX"), readonly=False)
        uids = _uid_search_literal(conn, "HEADER Message-ID", msgid)
        for u in sorted(uids)[:5]:
            conn.uid("STORE", u, "+FLAGS", "(\\Answered)")
    except Exception:
        pass


def imap_send_draft(cfg, uid, keep_draft=False):
    """Send a saved draft exactly as it is: recipients, subject, body, attachments, From and
    the reply threading (In-Reply-To/References) all come from the draft itself, so what was
    reviewed is what goes out. Like Send in a mail client, the draft then leaves Drafts (moved
    to Trash, recoverable) unless keep_draft; the provider files the sent copy in Sent."""
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(DRAFTS_FOLDER), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {DRAFTS_FOLDER!r}")
        msg = _fetch_draft(conn, uid, "BODY.PEEK[]")

        to, cc, bcc = (_unfold(msg.get(h)) for h in ("To", "Cc", "Bcc"))
        for field, value in (("to", to), ("cc", cc), ("bcc", bcc)):
            _reject_crlf(value, field)
        recipients = [a for _, a in _addr_list(to, cc, bcc) if a]
        if not recipients:
            raise RuntimeError(f"draft uid {uid} has no recipients (To/Cc/Bcc) — set them with update_draft first")
        # The draft's From must still be an address this account may send as (same rule as
        # send_email's `from`); none = the account's default.
        draft_from = parseaddr(_unfold(msg.get("From")) or "")[1]
        sender, note = _pick_from(cfg, draft_from or None)

        out = copy.deepcopy(msg)
        for h in ("Bcc", "From", "Date", "Message-ID"):
            del out[h]
        out["From"] = sender
        out["Date"] = formatdate(localtime=True)
        out["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
        _smtp_deliver(cfg, out, recipients)

        result = {
            "sent": True,
            "from": sender,
            "sent_to": recipients,
            "subject": _decode_header_value(out.get("Subject")),
            "attachments": _attachment_list(out),
            "message_id": out["Message-ID"],
        }
        if _unfold(out.get("In-Reply-To")):
            result["in_reply_to"] = _unfold(out.get("In-Reply-To"))
        if note:
            result["note"] = note
        if keep_draft:
            result["draft_kept"] = uid
        else:
            try:
                _uid_move(conn, uid, TRASH_FOLDER)
                result["draft_moved_to"] = TRASH_FOLDER
            except Exception as e:  # it went out already: report, don't fail
                result["warning"] = f"sent, but the draft (uid {uid}) could not be moved to {TRASH_FOLDER}: {e} — delete it so it is not sent twice"
        _mark_answered(conn, _unfold(out.get("In-Reply-To")))
        return result
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_delete_draft(cfg, uid):
    # Scoped to Drafts on purpose: no folder argument, so this can never be pointed
    # at real mail. It moves to Trash rather than expunging, because Bridge turns an
    # EXPUNGE out of Drafts into a permanent server-side delete (proton-bridge
    # imapservice/connector.go, RemoveMessagesFromMailbox) — Trash keeps it
    # recoverable, same as "delete" on a draft in the Proton web app.
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(DRAFTS_FOLDER), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {DRAFTS_FOLDER!r}")
        hdr = _fetch_draft(conn, uid, "BODY.PEEK[HEADER.FIELDS (TO SUBJECT DATE)]")
        _uid_move(conn, uid, TRASH_FOLDER)
        return {
            "uid": uid,
            "to": _decode_header_value(hdr.get("To")),
            "subject": _decode_header_value(hdr.get("Subject")),
            "date": hdr.get("Date", ""),
            "moved_to": TRASH_FOLDER,
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


FROM_SCHEMA = {
    "type": "string",
    "description": (
        "sending address: the account login or one of its aliases (config `aliases`). Omit it and a "
        "reply goes out from the address the original was sent to, anything else from the default"
    ),
}

ATTACHMENTS_SCHEMA = {
    "type": "array",
    "items": {"type": "string"},
    "description": (
        "absolute paths of local files to attach; hidden files/directories and ~/Library are refused, "
        f"and attachments may total at most {MAX_ATTACHMENTS_TOTAL_BYTES // (1024 * 1024)} MB"
    ),
}

TOOLS = [
    {
        "name": "list_folders",
        "description": "List mailbox folders/labels available in the Proton account.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "search_emails",
        "description": (
            "Search emails, by default across the whole account (the 'All Mail' folder). "
            "All filters are ANDed together (case-insensitive substring match, full UTF-8 support); "
            "omit all for the most recent messages. Returns total_matched for pagination via offset, "
            "and a snippet of each match's body so you often won't need get_email at all."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "folder": {"type": "string", "default": DEFAULT_SEARCH_FOLDER, "description": "e.g. INBOX, Sent, Archive, or a label name from list_folders"},
                "text": {"type": "string", "description": "full-text search (subject + body)"},
                "from_addr": {"type": "string"},
                "to_addr": {"type": "string"},
                "cc_addr": {"type": "string"},
                "subject": {"type": "string"},
                "unread_only": {"type": "boolean", "default": False},
                "since": {"type": "string", "description": "YYYY-MM-DD, inclusive lower bound"},
                "before": {"type": "string", "description": "YYYY-MM-DD, exclusive upper bound"},
                "has_attachment": {"type": "boolean", "default": False, "description": "only messages with at least one attachment (scans newest-first, up to scan_cap)"},
                "scan_cap": {
                    "type": "integer",
                    "default": HAS_ATTACHMENT_SCAN_CAP,
                    "maximum": 2000,
                    "description": "only used with has_attachment: max messages to inspect before giving up (raise if scan_capped comes back true and you need older matches)",
                },
                "limit": {"type": "integer", "default": DEFAULT_SEARCH_LIMIT, "maximum": MAX_SEARCH_LIMIT},
                "offset": {"type": "integer", "default": 0, "description": "skip this many of the newest matches (pagination)"},
            },
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_email",
        "description": "Fetch the full content of one email by UID (from search_emails results).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "max_chars": {"type": "integer", "default": DEFAULT_MAX_BODY_CHARS},
            },
            "required": ["uid"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "download_attachment",
        "description": "Download one email attachment to local disk. Get its exact filename from get_email's `attachments` list first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "filename": {"type": "string", "description": "must match a name from get_email's attachments list"},
            },
            "required": ["uid", "filename"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "view_attachment",
        "description": (
            "Show an email attachment inline instead of saving it to disk. Images (jpeg/png/gif/webp) are "
            f"returned directly; PDFs are rasterized to one PNG per page (up to {PDF_MAX_PAGES} pages, "
            "requires poppler's pdftoppm on this machine). Other file types aren't supported here — use "
            f"download_attachment for those, or if the file is over {VIEW_ATTACHMENT_MAX_BYTES // (1024 * 1024)} MB. "
            "Get the exact filename from get_email's `attachments` list first."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "filename": {"type": "string", "description": "must match a name from get_email's attachments list"},
            },
            "required": ["uid", "filename"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "send_email",
        "description": "Send an email from this account (or one of its aliases, see `from`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "comma-separated recipients"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "cc": {"type": "string"},
                "bcc": {"type": "string"},
                "from": FROM_SCHEMA,
                "attachments": ATTACHMENTS_SCHEMA,
            },
            "required": ["to", "subject", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "get_unread_count",
        "description": "Count unread messages in a folder.",
        "inputSchema": {"type": "object", "properties": {"folder": {"type": "string", "default": "INBOX"}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "mark_read",
        "description": "Mark an email as read or unread.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "read": {"type": "boolean", "default": True},
            },
            "required": ["uid"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "move_email",
        "description": "Move an email from one folder/label to another existing one (e.g. INBOX -> Archive).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "target_folder": {"type": "string"},
            },
            "required": ["uid", "target_folder"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "reply_to_email",
        "description": "Reply to an email, preserving threading (In-Reply-To/References) and quoting the original below your message.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "folder": {"type": "string", "default": "INBOX"},
                "body": {"type": "string"},
                "reply_all": {"type": "boolean", "default": False},
                "from": FROM_SCHEMA,
                "attachments": ATTACHMENTS_SCHEMA,
            },
            "required": ["uid", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "create_draft",
        "description": "Save an email as a draft in the Drafts folder without sending it, optionally with local files attached. Returns the new draft's uid.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "cc": {"type": "string"},
                "bcc": {"type": "string"},
                "attachments": ATTACHMENTS_SCHEMA,
                "from": FROM_SCHEMA,
            },
            "required": ["to", "subject", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "create_reply_draft",
        "description": (
            "Save a reply to an email as a draft instead of sending it: 'Re:' subject, addressed to the sender "
            "(or everyone with reply_all), original quoted below — same as reply_to_email, but into Drafts. "
            "Returns the draft's uid. Caveat: Proton Bridge does not link drafts saved over IMAP to the original "
            "conversation (it drops In-Reply-To/References), so in Proton the draft sits in its own thread and, "
            "if sent from the Proton app, may not thread for the recipient. Use reply_to_email when the reply "
            "should go out now, properly threaded."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string", "description": "UID of the message being replied to"},
                "folder": {"type": "string", "default": "INBOX"},
                "body": {"type": "string"},
                "reply_all": {"type": "boolean", "default": False},
                "attachments": ATTACHMENTS_SCHEMA,
                "from": FROM_SCHEMA,
            },
            "required": ["uid", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "update_draft",
        "description": (
            "Edit an existing draft (uid from create_draft/create_reply_draft, or search_emails with folder='Drafts'; "
            "read it first with get_email folder='Drafts'). Only the fields you pass change — recipients, subject, "
            "body (incl. HTML formatting) and attachments are otherwise carried over. `body` replaces the whole body "
            "as plain text; `attachments` adds files, `remove_attachments` drops existing ones by name. IMAP messages "
            "are immutable, so this saves a new version and moves the old one to Trash: the draft gets a NEW uid "
            "(returned) — use it for any further edit. A draft started as a reply in the Proton app loses its link "
            "to that conversation (Bridge limitation)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string", "description": "UID within the Drafts folder"},
                "to": {"type": "string", "description": "replaces the To list"},
                "cc": {"type": "string", "description": "replaces the Cc list (empty string clears it)"},
                "bcc": {"type": "string", "description": "replaces the Bcc list (empty string clears it)"},
                "subject": {"type": "string"},
                "from": FROM_SCHEMA,
                "body": {"type": "string", "description": "replaces the whole body, as plain text"},
                "attachments": ATTACHMENTS_SCHEMA,
                "remove_attachments": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "filenames to drop, exactly as in get_email's attachments list",
                },
            },
            "required": ["uid"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
    {
        "name": "send_draft",
        "description": (
            "Send a saved draft as it is (uid from create_draft/create_reply_draft/update_draft, or "
            "search_emails with folder='Drafts'): its recipients, subject, body, attachments, From and reply "
            "threading all come from the draft, so what was reviewed is what goes out. Only acts on the Drafts "
            "folder and refuses anything not flagged as a draft. Afterwards the draft is moved to Trash "
            "(recoverable) unless keep_draft; the sent copy lands in Sent. Sending cannot be undone: only send "
            "a draft the user has approved."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "uid": {"type": "string", "description": "UID within the Drafts folder"},
                "keep_draft": {"type": "boolean", "default": False, "description": "leave the draft in Drafts after sending"},
            },
            "required": ["uid"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "delete_draft",
        "description": (
            "Delete a draft by UID (from create_draft's result, or search_emails with folder='Drafts'). "
            "Only ever acts on the Drafts folder and refuses anything not flagged as a draft. The draft is "
            "moved to Trash, so it stays recoverable from there."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"uid": {"type": "string", "description": "UID within the Drafts folder"}},
            "required": ["uid"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]


def _image_block(payload, mime_type):
    return {"type": "image", "data": base64.b64encode(payload).decode("ascii"), "mimeType": mime_type}


def view_attachment_content(cfg, folder, uid, filename):
    payload, content_type = imap_fetch_attachment_bytes(cfg, folder, uid, filename)

    if content_type in ALLOWED_IMAGE_MEDIA_TYPES:
        if len(payload) > VIEW_ATTACHMENT_MAX_BYTES:
            raise RuntimeError(
                f"attachment {filename!r} is {len(payload)} bytes, over the "
                f"{VIEW_ATTACHMENT_MAX_BYTES}-byte inline preview cap — use download_attachment instead"
            )
        label = {"type": "text", "text": f"{filename} ({content_type}, {len(payload)} bytes)"}
        return [label, _image_block(payload, content_type)]

    if content_type == "application/pdf":
        if len(payload) > VIEW_ATTACHMENT_MAX_BYTES:
            raise RuntimeError(
                f"{filename!r} is {len(payload)} bytes, over the {VIEW_ATTACHMENT_MAX_BYTES}-byte cap on "
                f"source PDFs for inline rendering — use download_attachment instead"
            )
        pages = _render_pdf_to_png_pages(payload)
        total = sum(len(p) for p in pages)
        if total > VIEW_ATTACHMENT_MAX_BYTES:
            raise RuntimeError(
                f"{filename!r} rendered to {len(pages)} page(s) totalling {total} bytes, over the "
                f"{VIEW_ATTACHMENT_MAX_BYTES}-byte inline preview cap — use download_attachment instead"
            )
        note = f"{filename} — {len(pages)} page(s) rendered as images"
        if len(pages) == PDF_MAX_PAGES:
            note += f" (capped at {PDF_MAX_PAGES}; there may be more — use download_attachment for the full file)"
        label = {"type": "text", "text": note}
        return [label] + [_image_block(p, "image/png") for p in pages]

    raise RuntimeError(
        f"{filename!r} is {content_type!r}, which can't be previewed inline in this client (only images "
        "and PDF, rendered to images, are supported) — use download_attachment instead"
    )


def dispatch_tool(cfg, name, args):
    if name == "list_folders":
        return imap_folder_list(cfg)
    if name == "search_emails":
        return imap_search(
            cfg,
            args.get("folder", DEFAULT_SEARCH_FOLDER),
            args.get("text"),
            args.get("from_addr"),
            args.get("to_addr"),
            args.get("cc_addr"),
            args.get("subject"),
            args.get("unread_only", False),
            args.get("since"),
            args.get("before"),
            args.get("has_attachment", False),
            args.get("scan_cap"),
            args.get("limit", DEFAULT_SEARCH_LIMIT),
            args.get("offset", 0),
        )
    if name == "get_email":
        return imap_get_email(cfg, args.get("folder", "INBOX"), args["uid"], args.get("max_chars"))
    if name == "download_attachment":
        return imap_download_attachment(cfg, args.get("folder", "INBOX"), args["uid"], args["filename"])
    if name == "send_email":
        return smtp_send(
            cfg, args["to"], args["subject"], args["body"], args.get("cc"), args.get("bcc"), args.get("from"),
            args.get("attachments"),
        )
    if name == "get_unread_count":
        return imap_unread_count(cfg, args.get("folder", "INBOX"))
    if name == "mark_read":
        return imap_mark_read(cfg, args.get("folder", "INBOX"), args["uid"], args.get("read", True))
    if name == "move_email":
        return imap_move(cfg, args.get("folder", "INBOX"), args["uid"], args["target_folder"])
    if name == "reply_to_email":
        return imap_reply(
            cfg, args.get("folder", "INBOX"), args["uid"], args["body"], args.get("reply_all", False), args.get("from"),
            args.get("attachments"),
        )
    if name == "create_draft":
        return imap_create_draft(
            cfg, args["to"], args["subject"], args["body"], args.get("cc"), args.get("bcc"), args.get("attachments"),
            args.get("from"),
        )
    if name == "create_reply_draft":
        return imap_create_reply_draft(
            cfg, args.get("folder", "INBOX"), args["uid"], args["body"], args.get("reply_all", False), args.get("attachments"),
            args.get("from"),
        )
    if name == "update_draft":
        return imap_update_draft(
            cfg,
            args["uid"],
            args.get("to"),
            args.get("subject"),
            args.get("body"),
            args.get("cc"),
            args.get("bcc"),
            args.get("attachments"),
            args.get("remove_attachments"),
            args.get("from"),
        )
    if name == "send_draft":
        return imap_send_draft(cfg, args["uid"], args.get("keep_draft", False))
    if name == "delete_draft":
        return imap_delete_draft(cfg, args["uid"])
    raise RuntimeError(f"unknown tool {name!r}")


def send_message(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def handle_request(cfg, req):
    method = req.get("method")
    req_id = req.get("id")
    is_notification = "id" not in req

    if method == "initialize":
        result = {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
        send_message({"jsonrpc": "2.0", "id": req_id, "result": result})
        return

    if method == "notifications/initialized" or is_notification:
        return

    if method == "tools/list":
        send_message({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        return

    if method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            if name == "view_attachment":
                content = view_attachment_content(cfg, args.get("folder", "INBOX"), args["uid"], args["filename"])
            else:
                result = dispatch_tool(cfg, name, args)
                content = [{"type": "text", "text": json.dumps(result, indent=2)}]
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": content, "isError": False},
                }
            )
        except Exception as e:
            log(f"tool {name} failed: {e}")
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True},
                }
            )
        return

    if method == "ping":
        send_message({"jsonrpc": "2.0", "id": req_id, "result": {}})
        return

    send_message({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"method not found: {method}"}})


def main():
    try:
        cfg = load_config()
    except Exception as e:
        log(f"startup error: {e}")
        sys.exit(1)

    log(f"{SERVER_NAME} v{SERVER_VERSION} ready, account={cfg['email']}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            log(f"bad JSON from client: {e}")
            continue
        try:
            handle_request(cfg, req)
        except Exception as e:
            log(f"unhandled error: {e}")


if __name__ == "__main__":
    main()
