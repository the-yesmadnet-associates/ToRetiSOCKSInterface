# Changelog

All notable changes to this project will be documented in this file.

## 2.5-tor

Security-related improvements and stricter SOCKS5 stream isolation enforcement.

### Added
- Added configurable Reticulum tunnel synthesis via the new `tunnel` option (enabled by default).
- Added incoming HDLC frame length validation to reject undersized and oversized frames.
- Added an `invalid_frames` counter to interface status reporting.
- Added configuration validation for bitrate, MTU, buffer sizes, keepalive settings, and reconnect delays.

### Changed
- Increased the default IFAC size from 8 to 16 bytes.
- Enforced SOCKS5 stream isolation when `isolate = yes`. Connections now fail when the proxy does not support username/password authentication, instead of silently continuing without isolation.
- Updated the configuration documentation to include the new `tunnel` option.

### Fixed
- Clear incomplete incoming frame data after reconnection to prevent stale data from being processed as part of a new connection.
- Improved handling of invalid incoming frames and connection recovery.

---

## v2.4-tor - 2026-10-20

This first public community publication.

### Added
- **Dynamic MTU (`AUTOCONFIGURE_MTU`)**: Added support for link MTU auto-configuration derived directly from the `bitrate` (e.g., scales up to 16384 bytes at 20 Mbit/s).
- **Tor Onion Reply Codes**: Added support for clear, human-readable SOCKS5 error messages mapping Tor's onion service reply codes (`0xF0`-`0xF7`).
- **Configurable `connect_timeout`**: Added a customizable timeout parameter for initial proxy connections (defaulting to 20 seconds).
- **Advanced Reconnect Logic**: Implemented robust exponential backoff with jitter and tunable keepalive handling to survive unstable Tor circuits.
- **Enhanced Configuration Keys**: Added explicit support for `bitrate`, `hw_mtu`, `isolate`, and customized buffer/keepalive tuning settings.
- **NomadNet Page**: Published active development node and community index at `436ef889d637b2aa78dd3d7f0b3b10fb:/page/index.mu`.

### Changed
- **Default Bitrate**: Bumped default interface speed to 20 Mbit/s (optimized for loopback/proxy transfers).
- **DNS Resolution**: Enforced remote proxy-side resolution for all hostnames and `.onion` addresses to prevent local leaks (IPv4/IPv6 literals are bypassed directly).
- **Logging**: Rewrote log formatting for clearer tracking of interface status changes (`ToRetiSOCKS[gatewayname]`).
- **Codebase Clean-up**: Refactored major portions of the inherited codebase for better maintainability.

### Fixed
- **IP Leaks**: Patched potential edge cases where hostnames could accidentally resolve via the local network stack rather than through the SOCKS5 proxy.
- **Connection Drops**: Fixed aggressive reconnection loops by smoothing out backoff timing during Tor circuit rebuilds.

---

## [Base Profile] - 2025-03-03

Based on Kevin Steen's (`SkyGuy`) `SOCKSClientInterface.py` (v1.1.202503) on Codeberg.

### Added
- HDLC framing preservation ensuring full out-of-the-box compatibility with Reticulum's native TCP interfaces.
- Standard SOCKS5 proxy client interface capabilities for Reticulum Networking Stack (RNS).
