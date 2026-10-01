# NextPulse

NextPulse is a focused SSRF exploitation framework for the Next.js WebSocket
Upgrade Handler vulnerability, CVE-2026-44578. It fingerprints a Next.js
target, confirms the vulnerable upgrade path, shapes the request to survive
common filtering, and walks cloud metadata and local environment exposure to
a validated credential. It ships as a single Python file.

<p align="center">
  <img src="logo.png" alt="NextPulse" width="340">
</p>

<br>

## What is NextPulse?

NextPulse targets one bug in one place: the WebSocket Upgrade handler in
Next.js. It detects the framework and version, drives the upgrade request
through the SSRF path, and turns the response into evidence. When a metadata
endpoint is reachable it extracts the credential and, where it can, validates
it.

The framework is built for authorized testing: security researchers, bug
bounty hunters, red team operators, and offensive engineers working with
consent.

<br>

> One target, one bug, the shortest path to proof.

<br>

## Why this matters

The WebSocket Upgrade handler sits in front of the server-side fetch path,
and a misconfigured deployment lets a crafted upgrade request reach internal
services. Cloud metadata services are the common prize: a reachable instance
metadata endpoint hands out temporary credentials that carry real permissions.

## Affected and fixed versions

- Affected: Next.js 13.4.13 to 15.5.15, and 16.0.0 to 16.2.4.
- Fixed: 15.5.16, and 16.2.5 for self-hosted deployments.

## Features

- Accurate Next.js fingerprinting and version detection.
- Confirmation of the vulnerable WebSocket upgrade path.
- WAF-aware request shaping and evasion.
- Cloud metadata retrieval for AWS, Azure, GCP, DigitalOcean, Oracle, and
  Alibaba.
- Kubernetes metadata targeting.
- Local environment exfiltration.
- AWS credential validation through boto3.
- S3 bucket enumeration.
- Interactive operator shell.
- JSON and JSONL session export.
- Multi-threaded scanning.
- Single-file deployment.

## Installation

```bash
git clone https://github.com/DeathShotXD/NextPulse.git
cd NextPulse
pip3 install -r requirements.txt
chmod +x nextpulse.py
```

Requires Python 3.10 or later and boto3 for the AWS validation features.

## Usage

```bash
# Single target
python3 nextpulse.py -t https://target.com

# Interactive shell
python3 nextpulse.py -t https://target.com -i

# Automatic exploitation
python3 nextpulse.py -t https://target.com --auto --force

# Mass scanning
python3 nextpulse.py -f targets.txt --threads 50 --cloud all

# From a pipeline
cat targets.txt | python3 nextpulse.py --pipe

# A specific SSRF target
python3 nextpulse.py -t https://target.com \
  --ssrf "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

## Interactive shell commands

| Command | Description |
|---------|-------------|
| `help` | show available commands |
| `cloud` | detect the cloud provider |
| `aws` | full AWS instance metadata extraction |
| `azure` | Azure token extraction |
| `scan` | automated exploitation routine |
| `url <http://...>` | custom SSRF request |
| `get <N>` | run a preset target |
| `list` | show preset SSRF targets |
| `history` | show request history |
| `telemetry` | show traffic statistics |
| `save` | export the session |
| `quit` | exit the interactive shell |

## Screenshots

### Terminal banner

![Banner](screenshots/banner.png)

### Cloud metadata extraction

![AWS extraction](screenshots/aws-extraction.png)

### Interactive operator mode

![Interactive](screenshots/interactive.png)

### Local environment exfiltration

![Local exfiltration](screenshots/localfile-exfil.png)

All screenshots are real captures from controlled lab runs.

## Detection and defensive guidance

Indicators of exposure to look for:

- Requests to internal metadata address ranges.
- Unexpected internal DNS resolution from server-side components.
- Abnormal WebSocket upgrade traffic.
- Repeated probing of internal service endpoints.
- Access attempts against system files or environment variables.

Mitigations:

- Restrict access to metadata services at the network layer.
- Enforce authenticated metadata (IMDSv2 and equivalents).
- Validate and sanitize server-side fetch operations.
- Block internal address ranges at the application layer.
- Monitor middleware logs for abnormal routing.

## Repository structure

```
NextPulse/
|-- nextpulse.py
|-- requirements.txt
|-- README.md
|-- LICENSE
|-- SECURITY.md
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- PLAN.md
|-- logo.png
|-- screenshots/
|   |-- banner.png
|   |-- aws-extraction.png
|   |-- interactive.png
|   +-- localfile-exfil.png
+-- tests/
    +-- test_nextpulse.py
```

## Limitations

- The framework evaluates only the WebSocket Upgrade SSRF path.
- AWS validation requires boto3; other providers return extracted values
  without validation.
- Metadata reachability depends on the target network.
- Results against production systems must stay within the authorized scope.

## References

- CVE-2026-44578.
- Next.js security advisories.

## Responsible use

NextPulse is built for authorized security research, defensive validation,
education, and approved penetration testing. Using it against systems without
explicit permission may violate law. You are responsible for lawful use.

## Author

Syed Wajeeh-ul-Hassan Rizvi (@DeathShotXD).

## License

MIT. See [LICENSE](LICENSE).
