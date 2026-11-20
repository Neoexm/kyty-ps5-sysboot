import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


REQUEST = struct.Struct("<8sIIIIQIIIIIIII")
RESPONSE = struct.Struct("<8sIIIIQiiiiIIiI")
REQUEST_MAGIC = b"KYENV001"
RESPONSE_MAGIC = b"KYENR001"
HEADER_SIZE = 0x60
ENVELOPE = 1
RNPS = 2
MAX_ENVELOPE = 0x10000


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_token(path):
    raw = Path(path).read_bytes().strip(b"\r\n")
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", raw):
        raise ValueError("token file must contain 64 hexadecimal characters")
    return bytes.fromhex(raw.decode("ascii"))


def read_exact(sock, size):
    parts = bytearray()
    while len(parts) < size:
        chunk = sock.recv(min(1024 * 1024, size - len(parts)))
        if not chunk:
            raise EOFError("connection closed before the complete message")
        parts.extend(chunk)
    return bytes(parts)


def read_message(sock, max_bytes):
    header = read_exact(sock, HEADER_SIZE)
    total_size = struct.unpack_from("<I", header, 0x10)[0]
    if total_size < HEADER_SIZE or total_size > max_bytes + HEADER_SIZE:
        raise ValueError("message length outside capture limit")
    body = read_exact(sock, total_size - HEADER_SIZE)
    if sock.recv(1):
        raise ValueError("trailing message bytes")
    return header, body


def valid_tag(token, header, body):
    unsigned = bytearray(header)
    received = bytes(unsigned[0x40:0x60])
    unsigned[0x40:0x60] = bytes(32)
    return hmac.compare_digest(received, hmac.digest(token, unsigned + body, "sha256"))


def request_info(header, body, token):
    if len(header) != HEADER_SIZE or not valid_tag(token, header, body):
        raise ValueError("request authentication failed")
    fields = REQUEST.unpack_from(header)
    (magic, version, header_size, total_size, opcode, request_id, cid, mkv,
     key_size, salt_size, input_size, output_capacity, reserved0, reserved1) = fields
    if magic != REQUEST_MAGIC or version != 1 or header_size != HEADER_SIZE:
        raise ValueError("unsupported request protocol")
    if total_size != HEADER_SIZE + len(body) or request_id == 0 or reserved0 or reserved1:
        raise ValueError("invalid request header")
    if opcode == ENVELOPE:
        if (key_size != 0x300 or salt_size != 0x20 or not 0x1D1 <= input_size <= MAX_ENVELOPE
                or output_capacity != input_size - 0x1D0 or len(body) != 0x320 + input_size):
            raise ValueError("invalid envelope request")
        guest_input = body[0x320:]
    elif opcode == RNPS:
        if (cid or mkv or key_size or salt_size or input_size == 0
                or output_capacity != input_size or len(body) != input_size):
            raise ValueError("invalid RNPS request")
        guest_input = body
    else:
        raise ValueError("unsupported request opcode")
    identity_fields = struct.pack("<IIIIIII", opcode, cid, mkv, key_size,
                                  salt_size, input_size, output_capacity)
    return {
        "opcode": opcode,
        "request_id": request_id,
        "cid": cid,
        "mkv": mkv,
        "key_size": key_size,
        "salt_size": salt_size,
        "input_size": input_size,
        "output_capacity": output_capacity,
        "identity": sha256(identity_fields + body),
        "body_sha256": sha256(body),
        "guest_input_sha256": sha256(guest_input),
    }


def response_info(header, body, request, token):
    if len(header) != HEADER_SIZE or not valid_tag(token, header, body):
        raise ValueError("response authentication failed")
    fields = RESPONSE.unpack_from(header)
    (magic, version, header_size, total_size, opcode, request_id, transport,
     open_errno, ioctl_errno, close_errno, operation_result, output_size,
     cleanup, dispatch) = fields
    if (magic != RESPONSE_MAGIC or version != 1 or header_size != HEADER_SIZE
            or total_size != HEADER_SIZE + len(body) or output_size != len(body)
            or opcode != request["opcode"] or request_id != request["request_id"]):
        raise ValueError("response does not match request")
    success = (transport == 0 and open_errno == 0 and ioctl_errno == 0
               and close_errno == 0 and operation_result == 0 and cleanup == 0
               and dispatch == 1 and output_size == request["output_capacity"])
    return {
        "transport": transport,
        "open_errno": open_errno,
        "ioctl_errno": ioctl_errno,
        "close_errno": close_errno,
        "operation_result": operation_result,
        "output_size": output_size,
        "cleanup": cleanup,
        "dispatch": dispatch,
        "success": success,
        "body_sha256": sha256(body),
    }


def signed_response(request, saved, body, token):
    header = bytearray(RESPONSE.pack(
        RESPONSE_MAGIC, 1, HEADER_SIZE, HEADER_SIZE + len(body),
        request["opcode"], request["request_id"], saved["transport"],
        saved["open_errno"], saved["ioctl_errno"], saved["close_errno"],
        saved["operation_result"], len(body), saved["cleanup"], saved["dispatch"]
    ) + bytes(32))
    header[0x40:0x60] = hmac.digest(token, header + body, "sha256")
    return bytes(header) + body


def complete_success(response, capacity):
    return (response["transport"] == 0 and response["open_errno"] == 0
            and response["ioctl_errno"] == 0 and response["close_errno"] == 0
            and response["operation_result"] == 0 and response["cleanup"] == 0
            and response["dispatch"] == 1 and response["output_size"] == capacity)


def save_atomic(path, data):
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def current_user_sid():
    identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, check=True)
    row = next(csv.reader(identity.stdout.splitlines()), [])
    if len(row) != 2 or not re.fullmatch(r"S-1-\d+(?:-\d+)+", row[1]):
        raise ValueError("cannot identify current Windows user")
    return row[1]


def private_directory(path):
    if os.name != "nt":
        os.chmod(path, 0o700)
        return
    grant = "*" + current_user_sid() + ":(OI)(CI)F"
    subprocess.run(["icacls", str(path), "/grant:r", grant],
                   capture_output=True, text=True, check=True)
    subprocess.run(["icacls", str(path), "/inheritance:r"],
                   capture_output=True, text=True, check=True)


class Store:
    def __init__(self, path, events_path=None):
        self.path = Path(path)
        self.records = self.path / "records"
        self.requests = self.path / "requests"
        self.responses = self.path / "responses"
        self.conflicts = self.path / "conflicts"
        self.events_path = Path(events_path) if events_path is not None else self.path / "events.jsonl"
        self.lock = threading.Lock()

    def prepare(self, mode):
        if mode == "capture":
            self.path.mkdir(parents=True, exist_ok=False)
            private_directory(self.path)
            for folder in (self.records, self.requests, self.responses, self.conflicts):
                folder.mkdir()
        elif not self.path.is_dir() or not all(
                folder.is_dir() for folder in (self.records, self.requests, self.responses, self.conflicts)):
            raise ValueError("existing capture store is missing or incomplete")

    def event(self, kind, request=None, detail=None):
        row = {"at_utc": utc_now(), "event": kind}
        if request:
            row.update({"identity": request["identity"], "opcode": request["opcode"],
                        "guest_input_sha256": request["guest_input_sha256"]})
        if detail:
            row["detail"] = detail
        with self.lock:
            with self.events_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        print(json.dumps(row, sort_keys=True), flush=True)

    def capture(self, request, input_body, response, output_body):
        if not response["success"]:
            self.event("provider_failure", request, "authenticated response was not a complete success")
            return
        identity = request["identity"]
        record_path = self.records / (identity + ".json")
        input_path = self.requests / (identity + ".bin")
        output_path = self.responses / (identity + ".bin")
        record = {
            "schema": 1,
            "captured_at_utc": utc_now(),
            "provenance": "authenticated_live_console_provider",
            "request": {key: value for key, value in request.items() if key != "request_id"},
            "response": response,
        }
        with self.lock:
            if record_path.exists():
                old = json.loads(record_path.read_text(encoding="utf-8"))
                same = (old["request"] == record["request"]
                        and old["response"] == response
                        and input_path.read_bytes() == input_body
                        and output_path.read_bytes() == output_body)
                if not same:
                    conflict = self.conflicts / (identity + "." + uuid.uuid4().hex + ".json")
                    save_atomic(conflict, (json.dumps({
                        "at_utc": utc_now(), "identity": identity,
                        "new_request_sha256": sha256(input_body),
                        "new_response_sha256": sha256(output_body),
                    }, sort_keys=True, indent=2) + "\n").encode())
                    kind = "conflict"
                else:
                    kind = "repeat"
            else:
                save_atomic(input_path, input_body)
                save_atomic(output_path, output_body)
                save_atomic(record_path, (json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
                kind = "captured"
        self.event(kind, request)

    def replay(self, request, body):
        identity = request["identity"]
        if list(self.conflicts.glob(identity + ".*.json")):
            raise ValueError("conflicting console answers for this exact input")
        record_path = self.records / (identity + ".json")
        if not record_path.exists():
            return None
        record = json.loads(record_path.read_text(encoding="utf-8"))
        saved_request = record["request"]
        saved_response = record["response"]
        if (record.get("schema") != 1
                or record.get("provenance") != "authenticated_live_console_provider"
                or saved_request != {key: value for key, value in request.items() if key != "request_id"}
                or not saved_response.get("success")
                or not complete_success(saved_response, request["output_capacity"])
                or (self.requests / (identity + ".bin")).read_bytes() != body):
            raise ValueError("stored input validation failed")
        output = (self.responses / (identity + ".bin")).read_bytes()
        if (len(output) != saved_response["output_size"]
                or sha256(output) != saved_response["body_sha256"]):
            raise ValueError("stored output validation failed")
        return saved_response, output

    def verify(self):
        records = sorted(self.records.glob("*.json"))
        if not records:
            raise ValueError("capture contains no records")
        counts = {"envelope": 0, "rnps": 0, "output_bytes": 0, "conflicts": len(list(self.conflicts.glob("*.json")))}
        for path in records:
            data = json.loads(path.read_text(encoding="utf-8"))
            request = data["request"]
            response = data["response"]
            identity = request["identity"]
            if path.stem != identity or data["provenance"] != "authenticated_live_console_provider":
                raise ValueError("invalid record metadata: " + path.name)
            body = (self.requests / (identity + ".bin")).read_bytes()
            output = (self.responses / (identity + ".bin")).read_bytes()
            fields = struct.pack("<IIIIIII", request["opcode"], request["cid"], request["mkv"],
                                 request["key_size"], request["salt_size"],
                                 request["input_size"], request["output_capacity"])
            if (sha256(fields + body) != identity or sha256(body) != request["body_sha256"]
                    or sha256(body[0x320:] if request["opcode"] == ENVELOPE else body)
                    != request["guest_input_sha256"]
                    or sha256(output) != response["body_sha256"]
                    or len(output) != response["output_size"] or not response["success"]
                    or not complete_success(response, request["output_capacity"])):
                raise ValueError("record checksum mismatch: " + path.name)
            counts["envelope" if request["opcode"] == ENVELOPE else "rnps"] += 1
            counts["output_bytes"] += len(output)
        counts["records"] = len(records)
        return counts


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        self.request.settimeout(server.timeout)
        request = None
        try:
            header, body = read_message(self.request, server.max_bytes)
            request = request_info(header, body, server.token)
            if server.mode == "capture":
                with socket.create_connection(("127.0.0.1", server.upstream_port), timeout=server.timeout) as upstream:
                    upstream.settimeout(server.timeout)
                    upstream.sendall(header + body)
                    upstream.shutdown(socket.SHUT_WR)
                    response_header, response_body = read_message(upstream, server.max_bytes)
                response = response_info(response_header, response_body, request, server.token)
                server.store.capture(request, body, response, response_body)
                self.request.sendall(response_header + response_body)
            else:
                match = server.store.replay(request, body)
                if match is None:
                    server.store.event("replay_miss", request)
                    return
                response, output = match
                self.request.sendall(signed_response(request, response, output, server.token))
                server.store.event("replayed_console_data", request)
        except (OSError, EOFError, ValueError, KeyError, json.JSONDecodeError) as error:
            server.store.event("request_error", request, type(error).__name__ + ": " + str(error))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("capture", "replay", "verify"))
    parser.add_argument("--store", required=True)
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--upstream-port", type=int)
    parser.add_argument("--token-file")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    args = parser.parse_args()
    store = Store(args.store)
    if args.mode == "verify":
        print(json.dumps(store.verify(), sort_keys=True))
        return 0
    if not args.listen_port or not 1 <= args.listen_port <= 65535:
        parser.error("--listen-port is required")
    if not args.token_file:
        parser.error("--token-file is required")
    if args.mode == "capture" and (not args.upstream_port or args.upstream_port == args.listen_port):
        parser.error("capture requires a distinct --upstream-port")
    if args.timeout <= 0 or args.max_bytes <= 0:
        parser.error("timeout and max bytes must be positive")
    token = read_token(args.token_file)
    with Server(("127.0.0.1", args.listen_port), Handler) as server:
        store.prepare(args.mode)
        server.mode = args.mode
        server.store = store
        server.token = token
        server.upstream_port = args.upstream_port
        server.timeout = args.timeout
        server.max_bytes = args.max_bytes
        print(json.dumps({"mode": args.mode, "listen": "127.0.0.1", "port": args.listen_port,
                          "upstream_port": args.upstream_port if args.mode == "capture" else None,
                          "store": str(store.path)}, sort_keys=True), flush=True)
        server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
