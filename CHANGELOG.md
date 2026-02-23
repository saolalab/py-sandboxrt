# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-23

### Added

- Initial release
- macOS sandboxing using `sandbox-exec` with Seatbelt profiles
- Linux sandboxing using `bubblewrap`
- HTTP/HTTPS proxy with domain filtering
- SOCKS5 proxy for other TCP connections
- CLI interface (`srt` command)
- Python library API
- Configuration via JSON settings file
- Network configuration (allow-only pattern)
- Filesystem configuration (deny-read, allow-write patterns)
- Mandatory deny paths for sensitive files
- Violation tracking and reporting

[Unreleased]: https://github.com/saolalab/py-srt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saolalab/py-srt/releases/tag/v0.1.0
