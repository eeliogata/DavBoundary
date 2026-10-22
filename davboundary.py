#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit


MAX_RESPONSE = 1024 * 1024
RESERVED = {"host", "content-length", "transfer-encoding", "connection", "destination",
            "overwrite", "if-none-match"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_headers(path):
    headers = json.loads(path.read_text())
    if not isinstance(headers, dict):
        raise ValueError(f"expected a header object: {path}")
    for name, value in headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]+", name)
                or name.lower() in RESERVED or not isinstance(value, str)
                or "\r" in value or "\n" in value):
            raise ValueError(f"invalid header in {path}")
    return headers


def request(origin, method, path, headers, body=None, context=None, timeout=5):
    port = origin.port or (443 if origin.scheme == "https" else 80)
    if origin.scheme == "https":
        conn = http.client.HTTPSConnection(origin.hostname, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(origin.hostname, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise ValueError("response exceeds 1 MiB")
        result = {"status": response.status}
        if response.status == 200 and method == "GET":
            result["body_sha256"] = sha256(payload)
            result["etag"] = response.getheader("ETag")
        return result
    finally:
        conn.close()


def probe(args, origin, actor, owner, context):
    prefix = "davboundary-" + args.marker + "-"
    source_paths = {}
    destination_paths = {}
    report = {"origin": args.origin, "source_collection": args.source,
              "destination_collection": args.destination, "marker": args.marker,
              "control": {}, "trials": [], "cleanup": []}

    def call(method, path, headers, body=None):
        return request(origin, method, path, headers, body, context, args.timeout)

    def owner_get(path):
        return call("GET", path, owner)

    try:
        control = args.destination + prefix + "control.txt"
        baseline = owner_get(control)
        if baseline["status"] != 404:
            raise ValueError("control destination is not absent")
        destination_paths[control] = {sha256(b"direct-control")}
        denied_put = call("PUT", control, {**actor, "Content-Type": "text/plain",
                                           "If-None-Match": "*"}, b"direct-control")
        control_after = owner_get(control)
        report["control"] = {"actor_put": denied_put, "owner_before": baseline,
                             "owner_after": control_after,
                             "direct_write_seen": control_after.get("body_sha256") == sha256(b"direct-control")}

        for method in ("COPY", "MOVE"):
            for overwrite in ("F", "T"):
                suffix = method.lower() + ("-create" if overwrite == "F" else "-overwrite") + ".txt"
                source = args.source + prefix + suffix
                destination = args.destination + prefix + suffix
                body = ("davboundary:" + args.marker + ":" + suffix).encode()
                before = owner_get(destination)
                source_before = call("GET", source, actor)
                if before["status"] != 404 or source_before["status"] != 404:
                    raise ValueError("trial source or destination is not absent")
                source_paths[source] = {sha256(body)}
                destination_paths[destination] = {sha256(body)}
                source_put = call("PUT", source, {**actor, "Content-Type": "text/plain",
                                                  "If-None-Match": "*"}, body)
                trial = {"method": method, "overwrite": overwrite, "source_put": source_put}
                if not 200 <= source_put["status"] < 300:
                    trial["skipped"] = "source PUT failed"
                    report["trials"].append(trial)
                    continue
                if overwrite == "T":
                    destination_paths[destination].add(sha256(b"owner-original"))
                    owner_put = call("PUT", destination, {**owner, "Content-Type": "text/plain",
                                                           "If-None-Match": "*"}, b"owner-original")
                    trial["owner_put"] = owner_put
                    if not 200 <= owner_put["status"] < 300:
                        trial["skipped"] = "owner PUT failed"
                        report["trials"].append(trial)
                        continue
                trial["destination_before"] = owner_get(destination)
                headers = {**actor, "Destination": args.origin.rstrip("/") + destination,
                           "Overwrite": overwrite}
                trial["operation"] = call(method, source, headers)
                trial["destination_after"] = owner_get(destination)
                trial["source_after"] = call("GET", source, actor)
                trial["destination_has_actor_body"] = (
                    trial["destination_after"].get("body_sha256") == sha256(body))
                report["trials"].append(trial)
    except (OSError, ValueError, http.client.HTTPException) as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        paths = [(path, owner, hashes) for path, hashes in destination_paths.items()]
        paths += [(path, actor, hashes) for path, hashes in source_paths.items()]
        for path, headers, hashes in paths:
            try:
                current = call("GET", path, headers)
                if current["status"] == 404:
                    report["cleanup"].append({"path": path, "status": "absent"})
                elif current.get("body_sha256") not in hashes:
                    report["cleanup"].append({"path": path, "status": "left in place"})
                else:
                    result = call("DELETE", path, headers)
                    report["cleanup"].append({"path": path, "status": result["status"]})
            except (OSError, ValueError, http.client.HTTPException) as error:
                report["cleanup"].append({"path": path, "error": type(error).__name__})
    report["destination_write_after_failed_put"] = (
        report["control"].get("actor_put", {}).get("status", 200) >= 300
        and not report["control"].get("direct_write_seen", False)
        and any(trial.get("destination_has_actor_body") for trial in report["trials"]))
    return report


def main():
    parser = argparse.ArgumentParser(description="Check WebDAV destination authorization for COPY and MOVE")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--source", required=True, help="actor-writable collection path")
    parser.add_argument("--destination", required=True, help="owner-writable collection path")
    parser.add_argument("--actor-headers", type=Path, required=True)
    parser.add_argument("--owner-headers", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--marker", default=uuid.uuid4().hex)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    origin = urlsplit(args.origin)
    if (origin.scheme not in ("http", "https") or not origin.hostname or origin.path not in ("", "/")
            or origin.query or origin.fragment or origin.username or origin.password):
        parser.error("--origin must be an HTTP origin")
    if (not re.fullmatch(r"[A-Za-z0-9-]{1,64}", args.marker) or args.timeout <= 0
            or args.source == args.destination):
        parser.error("invalid marker, timeout, or collection paths")
    for path in (args.source, args.destination):
        if not path.startswith("/") or path.startswith("//") or not path.endswith("/") or "?" in path or "#" in path:
            parser.error("collection paths must start and end with / and have no query")
    try:
        actor = load_headers(args.actor_headers)
        owner = load_headers(args.owner_headers)
        context = ssl.create_default_context()
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            report = probe(args, origin, actor, owner, context)
            json.dump(report, output, indent=2)
            output.write("\n")
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(2, str(error) + "\n")
    print(args.out)
    incomplete = any("error" in item or item["status"] == "left in place"
                     or isinstance(item["status"], int) and item["status"] >= 300
                     for item in report["cleanup"])
    return 2 if "error" in report or incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
