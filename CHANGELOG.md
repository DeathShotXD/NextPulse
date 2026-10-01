# Changelog

Notable changes to NextPulse, newest first.

## Unreleased

### Changed

- Rewrote the README in plain ASCII with the project layout used across the
  repository set.

### Added

- Continuous integration that compiles the script and runs the tests.
- Unit tests for target parsing, fingerprinting, and header analysis.
- Security policy, contributing guide, maintenance plan, and templates.

## 1.0.0

### Added

- Next.js fingerprinting and version detection for CVE-2026-44578.
- WebSocket Upgrade SSRF exploitation with WAF-aware request shaping.
- Cloud metadata retrieval for AWS, Azure, GCP, DigitalOcean, Oracle, and
  Alibaba, plus Kubernetes metadata.
- Local environment exfiltration.
- AWS credential validation through boto3 and S3 bucket enumeration.
- Interactive shell, JSON and JSONL export, and multi-threaded scanning.
