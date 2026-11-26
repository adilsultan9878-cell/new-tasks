"""Outgoing e-mail (Phase 10): password reset, address verification, invitations.

* ``EMAIL_BACKEND=disabled`` (default): nothing is sent, and the features that need e-mail say so
  instead of pretending (e.g. "password reset by e-mail is not configured").
* ``console``: development only — the message, link included, goes to the API log. Refused in
  production by the settings validator.
* ``smtp``: any SMTP provider (STARTTLS, implicit TLS or none for a local relay), TLS certificates
  verified.

Messages are sent after the response (FastAPI background task), never inside the database
transaction, and are not stored: their links carry single-use tokens that must not sit in a table
or a log in production. Sending never raises into a request; failures are logged and counted.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from collections import deque
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from fastapi import BackgroundTasks

from app.core.config import get_settings

log = logging.getLogger("sentinel.email")


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    text: str


class _Stats:
    def __init__(self) -> None:
        self.sent = 0
        self.failed = 0
        self.lock = threading.Lock()

    def add(self, ok: bool) -> None:
        with self.lock:
            if ok:
                self.sent += 1
            else:
                self.failed += 1


stats = _Stats()
outbox: deque[Email] = deque(maxlen=100)  # console backend only: what tests and developers read


def _message(email: Email) -> EmailMessage:
    settings = get_settings()
    msg = EmailMessage()
    msg["From"] = settings.email_from
    msg["To"] = email.to
    msg["Subject"] = email.subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=settings.email_from.rsplit("@", 1)[-1].strip("> ") or None)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(email.text)
    return msg


def _send_smtp(email: Email) -> None:
    s = get_settings()
    context = ssl.create_default_context()
    if s.smtp_security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds, context=context
        )
    else:
        server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds)
    with server:
        if s.smtp_security == "starttls":
            server.starttls(context=context)
        if s.smtp_username:
            server.login(s.smtp_username, s.smtp_password)
        server.send_message(_message(email))


def send(email: Email) -> bool:
    """Deliver one message with the configured backend. Never raises."""
    backend = get_settings().email_backend
    if backend == "disabled":
        return False
    try:
        if backend == "console":
            outbox.append(email)
            log.info("e-mail (console backend) to %s: %s\n%s", email.to, email.subject, email.text)
        else:
            _send_smtp(email)
        stats.add(True)
        return True
    except Exception as exc:  # network, auth, TLS, refused recipient: report, do not break the request
        stats.add(False)
        log.warning("e-mail to %s failed: %s", email.to.split("@")[-1], type(exc).__name__)
        return False


def queue(background: BackgroundTasks | None, email: Email) -> None:
    """Send after the response has been sent (and the transaction committed)."""
    if background is None:
        send(email)
    else:
        background.add_task(send, email)


def link(path: str, token: str) -> str:
    """Links carry the token in the fragment (#): browsers never send it to a server or a Referer."""
    return f"{get_settings().public_app_url.rstrip('/')}{path}#token={token}"
