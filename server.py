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
from email import message_from_bytes
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr, getaddresses, parsedate_to_datetime

CONFIG_PATH = os.path.expanduser(
    sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PROTON_MCP_CONFIG", "~/.config/proton-mcp/config.json")
)
SERVER_NAME = "proton-mail-personal"
SERVER_VERSION = "1.0.0"
MAX_SEARCH_LIMIT = 100
DEFAULT_SEARCH_LIMIT = 20
DEFAULT_SEARCH_FOLDER = "All Mail"
DEFAULT_MAX_BODY_CHARS = 6000
SNIPPET_CHARS = 200
HAS_ATTACHMENT_SCAN_CAP = 300
DEFAULT_DOWNLOADS_DIR = "~/Downloads/proton-mail-mcp"


def log(msg):
    # MCP stdio reserves stdout for protocol frames — all diagnostics go to stderr.
    print(f"[proton-mcp] {msg}", file=sys.stderr, flush=True)


def load_config():
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    missing = [k for k in ("email", "bridge_password") if not cfg.get(k)]
    if missing:
        raise RuntimeError(
            f"config missing {missing} — fill in {CONFIG_PATH} (chmod 600) before connecting a client"
        )
    return cfg


def make_ssl_context(cfg):
    ctx = ssl.create_default_context()
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
    conn = imaplib.IMAP4(cfg["imap_host"], cfg["imap_port"], timeout=CONNECT_TIMEOUT)
    conn.starttls(ssl_context=ctx)
    conn.login(cfg["email"], cfg["bridge_password"])
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


def _attachment_list(msg):
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                name = part.get_filename() or "(unnamed)"
                names.append(" ".join(name.split()))  # un-fold a wrapped RFC 2231 filename header
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
                name = " ".join((part.get_filename() or "").split())
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


def imap_move(cfg, folder, uid, target_folder):
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
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
        return {"uid": uid, "from": folder, "to": target_folder}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _smtp_deliver(cfg, msg, all_recipients):
    # Unlike Bridge's IMAP (plaintext + STARTTLS), its SMTP port expects TLS
    # from the first byte (implicit TLS, like SMTPS) — STARTTLS here just hangs
    # waiting for a plaintext greeting that never comes, until it times out.
    ctx = make_ssl_context(cfg)
    with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=ctx, timeout=CONNECT_TIMEOUT) as server:
        server.login(cfg["email"], cfg["bridge_password"])
        server.sendmail(cfg["email"], all_recipients, msg.as_string())


def smtp_send(cfg, to, subject, body, cc, bcc):
    for field, value in (("to", to), ("subject", subject), ("cc", cc), ("bcc", bcc)):
        _reject_crlf(value, field)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["email"]
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    all_recipients = [addr for _, addr in _addr_list(to, cc, bcc) if addr]
    _smtp_deliver(cfg, msg, all_recipients)
    return {"sent_to": all_recipients, "subject": subject}


def imap_reply(cfg, folder, uid, body, reply_all):
    uid = _validate_uid(uid)
    conn = imap_connect(cfg)
    try:
        status, _ = conn.select(_imap_quote(folder), readonly=False)
        if status != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}")
        status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or msg_data[0] is None:
            raise RuntimeError(f"message uid {uid} not found in {folder!r}")
        orig = message_from_bytes(msg_data[0][1])

        orig_subject = _decode_header_value(orig.get("Subject"))
        orig_subject = orig_subject.replace("\r", " ").replace("\n", " ")  # a malformed inbound header must not carry into our outgoing one
        reply_subject = orig_subject if orig_subject.lower().startswith("re:") else f"Re: {orig_subject}"

        orig_from = orig.get("From", "")
        to_addrs = [orig_from] if orig_from else []
        cc_addrs = []
        if reply_all:
            self_email = cfg["email"].lower()
            orig_from_addr = parseaddr(orig_from)[1].lower()
            already = {parseaddr(orig_from)[1].lower()}
            for n, a in getaddresses([orig.get("To", "")]):
                if a and a.lower() not in (self_email, orig_from_addr) and a.lower() not in already:
                    to_addrs.append(formataddr((n, a)))
                    already.add(a.lower())
            for n, a in getaddresses([orig.get("Cc", "")]):
                if a and a.lower() not in (self_email, orig_from_addr) and a.lower() not in already:
                    cc_addrs.append(formataddr((n, a)))
                    already.add(a.lower())
        to_header = ", ".join(to_addrs)
        cc_header = ", ".join(cc_addrs)

        orig_msgid = orig.get("Message-ID", "")
        orig_refs = orig.get("References", "")
        references = f"{orig_refs} {orig_msgid}".strip() if orig_refs else orig_msgid

        orig_body = _extract_body(orig)
        quoted = "\n".join(f"> {line}" for line in orig_body.splitlines())
        full_body = f"{body}\n\nOn {orig.get('Date', '')}, {orig_from} wrote:\n{quoted}"

        msg = MIMEText(full_body, "plain", "utf-8")
        msg["Subject"] = reply_subject
        msg["From"] = cfg["email"]
        msg["To"] = to_header
        if cc_header:
            msg["Cc"] = cc_header
        if orig_msgid:
            msg["In-Reply-To"] = orig_msgid
        if references:
            msg["References"] = references

        all_recipients = [addr for _, addr in _addr_list(to_header, cc_header) if addr]
        _smtp_deliver(cfg, msg, all_recipients)

        try:
            conn.uid("STORE", uid, "+FLAGS", "(\\Answered)")
        except Exception:
            pass  # best-effort — the reply already went out, don't fail the tool over a flag

        return {"sent_to": all_recipients, "subject": reply_subject, "in_reply_to": orig_msgid}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def imap_create_draft(cfg, to, subject, body, cc):
    for field, value in (("to", to), ("subject", subject), ("cc", cc)):
        _reject_crlf(value, field)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["email"]
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    conn = imap_connect(cfg)
    try:
        conn.append(_imap_quote("Drafts"), "(\\Draft)", None, msg.as_string().encode("utf-8"))
        return {"folder": "Drafts", "to": to, "subject": subject}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


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
        "name": "send_email",
        "description": "Send an email from the personal Proton account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "comma-separated recipients"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "cc": {"type": "string"},
                "bcc": {"type": "string"},
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
            },
            "required": ["uid", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "create_draft",
        "description": "Save an email as a draft in the Drafts folder without sending it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "cc": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
]


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
        return smtp_send(cfg, args["to"], args["subject"], args["body"], args.get("cc"), args.get("bcc"))
    if name == "get_unread_count":
        return imap_unread_count(cfg, args.get("folder", "INBOX"))
    if name == "mark_read":
        return imap_mark_read(cfg, args.get("folder", "INBOX"), args["uid"], args.get("read", True))
    if name == "move_email":
        return imap_move(cfg, args.get("folder", "INBOX"), args["uid"], args["target_folder"])
    if name == "reply_to_email":
        return imap_reply(cfg, args.get("folder", "INBOX"), args["uid"], args["body"], args.get("reply_all", False))
    if name == "create_draft":
        return imap_create_draft(cfg, args["to"], args["subject"], args["body"], args.get("cc"))
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
            result = dispatch_tool(cfg, name, args)
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False},
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
