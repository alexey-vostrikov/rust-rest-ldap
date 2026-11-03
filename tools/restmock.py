#!/usr/bin/env python3
"""A stand-in for the directory service the REST backend reads.

Serves two collections and accepts writes, recording them to a file so the
check can show what the server actually sent.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = [
    {
        "cn": "alice",
        "uid": "alice",
        "sn": "Smith",
        "mail": "alice@example.com",
        "uidNumber": 1001,
        "gidNumber": 1001,
        "objectClass": ["top", "person", "inetOrgPerson", "posixAccount"],
    },
    {
        "cn": "bob",
        "uid": "bob",
        "sn": "Jones",
        "uidNumber": 1002,
        "gidNumber": 1001,
        "objectClass": ["top", "person", "inetOrgPerson", "posixAccount"],
    },
]

GROUPS = [
    {"cn": "admins", "gidNumber": 1001, "memberUid": ["alice"], "objectClass": ["posixGroup"]}
]

LOG = "/tmp/restmock/seen.log"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - the signature is the base class's
        """Silent: the check reads the log file, not stderr."""


    def _reply(self, body):
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        with open(LOG, "a") as log:
            log.write(f"GET {self.path} auth={self.headers.get('Authorization')}\n")

        if self.headers.get("Authorization") != "Token s3cret-token":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.endswith("/ldap/user"):
            self._reply(USERS)
        elif self.path.endswith("/ldap/group"):
            self._reply(GROUPS)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode()
        with open(LOG, "a") as log:
            log.write(f"PUT {self.path} body={body}\n")
        self._reply({})

    def do_DELETE(self):
        # The endpoint the backend sends when `allow_delete: true` is configured. The real
        # service is not part of this project, so what this proves is the request's shape and
        # that the flag is what decides whether it is sent at all.
        with open(LOG, "a") as log:
            log.write(f"DELETE {self.path}\n")

        if self.headers.get("Authorization") != "Token s3cret-token":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1])
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
