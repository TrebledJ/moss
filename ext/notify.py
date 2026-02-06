"""
ext/discord.py

---

This extension showcases a handler which calls a Discord webhook. From there,
you can fine-tune your notification settings, control what guild/channel
messages appear in, etc.

Details and request data are escaped and rendered in a Markdown codeblock.
"""

from dataclasses import dataclass, field
import sys
import socket
import traceback
import random

GROUP = "notifications (ext/notify.py)"

# Controls the maximum length of the inner code snippet (HTTP details).
MAX_SNIPPET_LEN = 1024

def _field(default, group=None, doc="", metadata={}, flags=[], choices=[], **kwargs):
    """Simple wrapper to express fields more conveniently."""
    dwargs = {}
    if type(default).__name__ in ["function", "type"]:
        dwargs["default_factory"] = default
    else:
        dwargs["default"] = default
    return field(**dwargs, metadata=metadata | dict(group=group, doc=doc, flags=flags, choices=choices, **kwargs))

def random_id(n: int):
    return "".join(random.sample("abcdefghijkmnopqrstuvwxyz0123456789", n))

def escape_non_printable(s):
    if type(s) == bytes:
        s = s.decode(errors="backslashreplace")
    return "".join(c if c.isprintable() or c in "\r\n" else r"\x{0:02x}".format(ord(c)) for c in s)

@dataclass
class NotificationEventHandler:
    notify_platform: str = _field(None, group=GROUP, flags=["--notify"], choices=["discord"], doc="Enable third-party notifications")
    notify_on: list[str] = _field(list, group=GROUP, choices=["match", "correlation", "anomaly", "all"], doc="You can pass multiple choices, for example: `--notify-on match --notify-on anomaly`. \"all\" means notify on match/correlation/anomaly. Default is all.")
    webhook_url: str = _field(None, group=GROUP, doc="Webhook URL")
    identifier: str = _field(None, group=GROUP, flags=["--id"], doc="An identifier which will be sent along with the notification, primarily to help you identify this instance in case you have multiple running. An id will be automatically generated if not provided")

    def __post_init__(self):
        if not self.notify_on:
            self.notify_on = ["all"]
        if self.identifier is None:
            self.identifier = f"{socket.gethostname()}_{random_id(6)}"

        if self.notify_platform:
            if not self.webhook_url:
                self.printerr("--webhook-url was not provided")
                sys.exit(1)

            try:
                import requests
            except ImportError:
                self.printerr("Notifications requires the requests package:")
                self.printerr()
                self.printerr("\tpip install requests")
                sys.exit(1)
            self.requests = requests

        if self.notify_platform:
            self.printstatus(f"Notifications: {self.notify_platform} (id: {self.identifier})")

    def handle_event(self, data):
        try:
            self.notify_webhook(**data)
        except TypeError as e:
            self.logger.error(f"failed to run {__class__.__name__}.handle_event(): {e}")
            self.logger.error(traceback.format_exc())

    def notify_webhook(self, event_timestamp, client, proto, **kwargs):
        if not self.notify_platform:
            return
    
        type = "event"
        if kwargs.get("correlation_id", None):
            type = "correlation"
        elif "anomaly" in kwargs:
            type = "anomaly"
        elif kwargs.get("filter_matches", None):
            type = "match"
        
        if type in self.notify_on or "all" in self.notify_on:
            emoji = ":bulb:" if type in ["match", "correlation"] else ":warning:"
            msg = f"{emoji} {type.upper()} - [{event_timestamp}] {emoji}\n"
            msg += f"**Instance**: {self.identifier}\n"
            msg += f"**Protocol**: {proto}\n"
            msg += f"**Client IP**: {client}\n"
            if matches := kwargs.get("filter_matches", None):
                msg += f"**Matches**: {matches}\n"
            if correlation_id := kwargs.get("correlation_id", None):
                msg += f"**Correlation ID**: {sanitise_payload(correlation_id)}\n"
            if type in ["match", "correlation"]:
                msg += f"**Request**:\n```http\n"
                payload = f"{kwargs['requestline']}\n{kwargs['headers']}{kwargs['body']}\n"
                msg += sanitise_payload(shorten(payload))
                msg += "```"
            if type == "anomaly":
                msg += f"**Anomaly**:\n```\n"
                msg += f"{sanitise_payload(kwargs['anomaly'])}\n"
                if deets := kwargs.get("details", None):
                    msg += sanitise_payload(escape_non_printable(deets)) + "\n"
                msg += f"```"
            data = {"content": msg}
            try:
                self.requests.post(self.webhook_url, json=data)
            except self.requests.exceptions.RequestException as e:
                self.logger.error(f'failed to send webhook: {e}')

def shorten(x):
    if x > MAX_SNIPPET_LEN:
        return x[:MAX_SNIPPET_LEN] + f"...({len(x) - MAX_SNIPPET_LEN} more bytes, {len(x)} bytes in total)..."
    return x

def sanitise_payload(x):
    """Prevent escaping the codeblock context."""
    return x.replace("```", r"\`\`\`")