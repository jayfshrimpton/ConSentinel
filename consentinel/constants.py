"""Configurable detection vocabulary.

Everything a check keys off — dangerous verbs, side-effecting APIs, gate-parameter
names, injection phrases, entropy thresholds — lives here as module-level constants so
it can be tuned without touching check logic.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Group A — blast radius & excessive agency
# ---------------------------------------------------------------------------

# Method / attribute names that signal an external network write.
HTTP_WRITE_METHODS: frozenset[str] = frozenset({"post", "put", "patch", "delete"})

# HTTP client modules whose write methods count (informational; matching is by method
# name so any client using these verbs is caught conservatively).
HTTP_CLIENT_MODULES: frozenset[str] = frozenset({"requests", "httpx", "aiohttp"})

# Email-send signals: module names and method/function names.
EMAIL_MODULES: frozenset[str] = frozenset({"smtplib"})
EMAIL_SEND_METHODS: frozenset[str] = frozenset(
    {"sendmail", "send_message", "send_mail", "send_email"}
)

# Filesystem destruction: dotted call names and bare method names.
FS_DESTRUCTION_CALLS: frozenset[str] = frozenset(
    {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "shutil.rmtree",
    }
)
# Bare method names that destroy files regardless of receiver (e.g. Path.unlink()).
FS_DESTRUCTION_METHODS: frozenset[str] = frozenset({"unlink", "rmtree", "rmdir"})

# Process / shell execution.
SHELL_EXEC_CALLS: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
        "os.spawn",
        "os.execv",
        "os.execve",
        "eval",
        "exec",
    }
)
SUBPROCESS_MODULE = "subprocess"  # any subprocess.* call counts.

# Destructive SQL keywords looked for inside `.execute(...)` string arguments.
DESTRUCTIVE_SQL_KEYWORDS: frozenset[str] = frozenset(
    {"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "REPLACE"}
)

# ORM-style destructive/persisting methods.
ORM_DESTRUCTIVE_METHODS: frozenset[str] = frozenset({"delete", "save", "commit"})

# Destructive / external verbs matched as substrings in the tool name OR any called
# method / attribute name. Kept deliberately broad; Group A errs toward danger.
DESTRUCTIVE_VERBS: frozenset[str] = frozenset(
    {
        "delete",
        "remove",
        "drop",
        "purge",
        "truncate",
        "wipe",
        "reset",
        "send",
        "email",
        "publish",
        "post",
        "deploy",
        "bulk",
    }
)

# Subset of DESTRUCTIVE_VERBS matched against *called method names* (as whole tokens).
# Noun-ish verbs (email/post/bulk) are excluded here to avoid false signals like
# "EmailMessage" or "lookup_requester_email"; they are still matched in the tool NAME
# and, for post, via the HTTP write methods.
METHOD_NAME_VERBS: frozenset[str] = frozenset(
    {"delete", "remove", "drop", "purge", "truncate", "wipe", "reset", "send", "publish", "deploy"}
)

# File-open modes that indicate a (reversible, local) write.
WRITE_FILE_MODES: frozenset[str] = frozenset({"w", "a", "x", "+"})

# ---------------------------------------------------------------------------
# Enforced-gate check (the differentiator)
# ---------------------------------------------------------------------------

# Parameter names treated as a human-in-the-loop confirmation gate.
GATE_PARAM_NAMES: frozenset[str] = frozenset(
    {"confirmed", "confirm", "approve", "approved", "dry_run", "force", "yes"}
)

# Parameters that are not real tool inputs (framework context objects) — ignored when
# extracting tool parameters.
IGNORED_PARAM_NAMES: frozenset[str] = frozenset({"self", "cls", "ctx", "context"})

# ---------------------------------------------------------------------------
# Group B — poisoning surface
# ---------------------------------------------------------------------------

# Invisible / zero-width / bidi control code points. Stored as ints for exact matching.
INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x00AD,  # soft hyphen
        0x200B,  # zero-width space
        0x200C,  # zero-width non-joiner
        0x200D,  # zero-width joiner
        0x200E,  # left-to-right mark
        0x200F,  # right-to-left mark
        0x202A,  # left-to-right embedding
        0x202B,  # right-to-left embedding
        0x202C,  # pop directional formatting
        0x202D,  # left-to-right override
        0x202E,  # right-to-left override
        0x2060,  # word joiner
        0x2061,  # function application
        0x2062,  # invisible times
        0x2063,  # invisible separator
        0x2064,  # invisible plus
        0x2066,  # left-to-right isolate
        0x2067,  # right-to-left isolate
        0x2068,  # first strong isolate
        0x2069,  # pop directional isolate
        0xFEFF,  # zero-width no-break space (BOM)
    }
)

# Imperative-injection phrases. High-weight phrases attempt to override the model or
# exfiltrate; low-weight phrases are merely pushy.
INJECTION_PHRASES_HIGH: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard all",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "do not mention",
    "reveal your",
    "system prompt",
    "as an ai",
)
INJECTION_PHRASES_LOW: tuple[str, ...] = (
    "you must",
    "you must always",
    "always call",
    "always use",
    "must call this",
    "call this first",
    "before doing anything",
    "do not refuse",
)

# ---------------------------------------------------------------------------
# Group C — secrets & data exposure
# ---------------------------------------------------------------------------

# Named credential-provider patterns (high confidence).
SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret_key": r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "github_pat": r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "openai_key": r"\bsk-[A-Za-z0-9]{20,}\b",
    "stripe_key": r"\bsk_live_[A-Za-z0-9]{16,}\b",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}

# Variable / keyword names that look like they hold a credential.
SECRET_NAME_HINTS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "auth_token",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "client_secret",
    }
)

# Substrings that mark an obvious placeholder rather than a real secret.
SECRET_PLACEHOLDERS: tuple[str, ...] = (
    "your_",
    "xxx",
    "changeme",
    "change_me",
    "placeholder",
    "example",
    "dummy",
    "todo",
    "<",
    "...",
    "redacted",
    "insert_",
    "my_",
)

# Entropy scoring for anonymous string literals.
ENTROPY_MIN_LENGTH: int = 20
ENTROPY_THRESHOLD: float = 4.0  # Shannon bits/char; ~random base64 is ~4.5-6.0.

# Calls that emit to logs / stdout (secret-in-output surface).
LOG_CALLS: frozenset[str] = frozenset({"print", "log", "debug", "info", "warning", "error", "exception"})
LOG_MODULES: frozenset[str] = frozenset({"logging", "logger", "log"})

# PII column / field hints for the bulk-PII return check.
PII_FIELD_HINTS: frozenset[str] = frozenset(
    {"email", "e_mail", "phone", "mobile", "ssn", "address", "dob", "user", "users", "customer"}
)

# ---------------------------------------------------------------------------
# Group D — injection sinks
# ---------------------------------------------------------------------------

# Sink calls that execute code / commands.
EXEC_SINKS: frozenset[str] = frozenset({"eval", "exec", "system", "popen"})

# ---------------------------------------------------------------------------
# Group E — transport
# ---------------------------------------------------------------------------

# Transport keywords considered network-exposed.
NETWORK_TRANSPORTS: frozenset[str] = frozenset({"sse", "http", "streamable-http", "streamable_http", "ws", "websocket"})

# Names that hint an auth check / middleware is present nearby.
AUTH_HINTS: frozenset[str] = frozenset(
    {
        "auth",
        "authenticate",
        "authorization",
        "bearer",
        "token",
        "api_key",
        "apikey",
        "verify_token",
        "middleware",
        "require_auth",
        "check_auth",
        "login",
        "credentials",
        "oauth",
    }
)
