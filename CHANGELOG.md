# Changelog

## 0.1.0

Initial release. Type-safe Dart port of the Node.js
[`turn-server`](https://github.com/colocohen/turn-server) library.

### Features
- STUN/TURN wire codec (RFC 5389, RFC 8489, RFC 5766, RFC 8656).
  - Long-term and short-term auth, MESSAGE-INTEGRITY (SHA-1 / SHA-256),
    FINGERPRINT, ChannelData, Send/Data indications.
  - RFC 6062 TCP relay, RFC 5780 NAT discovery, RFC 7635 OAuth.
- Multi-listener TURN `TurnServer` over UDP / TCP / TLS (RFC 7443 ALPN)
  with per-listener `SecurityContext`, accept hooks, realm callbacks,
  quotas, per-allocation limits, and a hot-pluggable credential store.
- `TurnSocket` client/server transport with relay management.
- Full ICE Agent (RFC 8445) with trickle ICE (RFC 8838), regular
  nomination, role-conflict resolution, peer-reflexive candidates,
  consent freshness (RFC 7675), ICE restart, host + srflx + relay
  candidate gathering, IPv4 + IPv6.
- Convenience helpers: `connect()`, `getPublicIP()`, `detectNAT()`.
