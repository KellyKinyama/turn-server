# turn_server

Production-grade STUN/TURN server, client, and ICE agent for Dart.
Type-safe port of the Node.js
[`turn-server`](https://github.com/colocohen/turn-server) library.

[![Dart](https://img.shields.io/badge/dart-%5E3.4-blue.svg)](https://dart.dev)
[![Tests](https://img.shields.io/badge/tests-62%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#license)

---

## Features

- **Full STUN/TURN wire protocol** — RFC 5389, RFC 8489, RFC 5766, RFC 8656.
  Long-term + short-term auth, MESSAGE-INTEGRITY (SHA-1 / SHA-256), FINGERPRINT,
  ChannelData, Send/Data indications, RFC 6062 TCP relay, RFC 5780 NAT discovery.
- **Pluggable transports** — UDP, TCP, TLS (RFC 7443 ALPN). DTLS / WebSocket
  layers can be composed externally with `TurnSocket(isServer: true).feed(bytes)`.
- **Multi-listener server** — bind any combination of UDP / TCP / TLS endpoints
  with per-listener `SecurityContext`, accept hooks, realm callbacks, quotas,
  per-allocation limits, and a hot-pluggable credential store.
- **Full ICE Agent** — RFC 8445 with trickle ICE (RFC 8838), regular nomination,
  role-conflict resolution, peer-reflexive candidates, consent freshness
  (RFC 7675), ICE restart with media continuity (§9), host + srflx + relay
  candidate gathering, IPv4 + IPv6.
- **Strict type safety** — sealed enums for state machines, typed `Stream<T>`s
  for every event, no `dynamic` payloads. Clean under `strict-casts`,
  `strict-inference`, `strict-raw-types` plus extensive lints.

## Install

```yaml
dependencies:
  turn_server: ^0.1.0
```

## Quick start

### Run a TURN server

```dart
import 'package:turn_server/turn_server.dart';

Future<void> main() async {
  final TurnServer server = createServer(TurnServerOptions(
    software: 'my-app/1.0',
    listen: const <ListenConfig>[
      ListenConfig(transport: ServerTransport.udp, address: '0.0.0.0', port: 3478),
      ListenConfig(transport: ServerTransport.tcp, address: '0.0.0.0', port: 3478),
    ],
    relay: const RelayServerConfig(
      ip: '0.0.0.0',
      portRange: <int>[49152, 65535],
    ),
    auth: const AuthServerConfig(
      mechanism: AuthMechanism.longTerm,
      realm: 'example.org',
      credentials: <String, String>{
        'alice': 'alice-secret',
        'bob':   'bob-secret',
      },
    ),
    // Per-allocation safety nets (0 = unlimited).
    maxAllocateLifetime: 3600,
    userQuota: 10,
    totalQuota: 1000,
    maxPermissionsPerAllocation: 16,
    maxChannelsPerAllocation: 16,
  ));

  server.onListening.listen((ListeningEvent e) {
    print('listening: ${e.transport.name} ${e.address}:${e.port}');
  });
  server.onAllocate.listen((AllocateServerEvent e) {
    print('allocated: ${e.allocation.relayAddress}');
  });

  await server.start();
}
```

### Run a TURN client

```dart
import 'package:turn_server/turn_server.dart';

Future<void> main() async {
  final TurnSocket sock = await connect(
    'turn:turn.example.org:3478',
    const ConnectOptions(
      username: 'alice',
      password: 'alice-secret',
    ),
  );

  sock.session.allocate(lifetime: 600);
  await sock.session.onSuccess.firstWhere(
      (m) => m.method == StunMethod.allocate);

  // Forward payloads to a peer
  sock.session.createPermission(<StunAddress>[
    const StunAddress(family: AddressFamily.ipv4, ip: '198.51.100.7', port: 5000),
  ]);
  sock.session.sendToPeer(
    const StunAddress(family: AddressFamily.ipv4, ip: '198.51.100.7', port: 5000),
    Uint8List.fromList(<int>[0xCA, 0xFE]),
  );

  await sock.close();
}
```

### Discover the public IP (STUN BINDING)

```dart
import 'package:turn_server/turn_server.dart';

Future<void> main() async {
  final PublicAddress? p = await getPublicIP(
    server: 'stun:stun.l.google.com:19302',
    timeout: Duration(seconds: 3),
  );
  print('public: ${p?.ip}:${p?.port}');   // e.g. 203.0.113.42:51234
}
```

### Detect NAT type (RFC 5780)

```dart
final NatDetectionResult r = await detectNAT(
  server: 'stun:stun.example.org:3478',
);
print('NAT: ${r.type}  mapped=${r.mappedAddress}  other=${r.otherAddress}');
```

`NatType` values: `unknown`, `blocked`, `openInternet`, `fullCone`,
`restrictedCone`, `symmetricOrPortRestricted`, `serverIncomplete`, `timeout`.
Requires a multi-address STUN server (one that returns OTHER-ADDRESS).

### Use the ICE agent

```dart
import 'package:turn_server/turn_server.dart';

Future<void> main() async {
  final IceAgent agent = IceAgent(IceAgentOptions(
    mode: IceMode.full,
    controlling: true,
    iceServers: const <IceServer>[
      IceServer(urls: <String>['stun:stun.l.google.com:19302']),
      IceServer(
        urls: <String>['turn:turn.example.org:3478'],
        username: 'alice',
        credential: 'alice-secret',
      ),
    ],
  ));

  // 1. Listen for our local candidates as they're gathered.
  agent.onCandidate.listen((IceCandidate? c) {
    if (c == null) {
      // end-of-candidates marker (RFC 8838)
      sendToPeerSdp('a=end-of-candidates');
    } else {
      sendToPeerSdp('a=${buildCandidateAttr(c)}');
    }
  });

  // 2. Ship our local ICE credentials.
  final IceParameters local = agent.localParameters;
  sendToPeerSdp('a=ice-ufrag:${local.ufrag}');
  sendToPeerSdp('a=ice-pwd:${local.pwd}');

  // 3. Once the answer arrives, plug in the peer's credentials.
  agent.setRemoteParameters(IceParameters(
    ufrag: '...', pwd: '...',
  ));

  // 4. Feed the peer's candidates as they trickle in.
  agent.addRemoteCandidate('candidate:1 1 udp 2113937151 192.0.2.10 51234 typ host');
  agent.addRemoteCandidate(null);   // signal end-of-candidates

  // 5. Trigger gathering (also kicks the connectivity-check engine).
  agent.gather();

  // 6. Watch state and selected pair.
  agent.onStateChange.listen(print);
  agent.onSelectedPair.listen((SelectedPairEvent e) {
    print('selected: ${e.pair.local.ip} → ${e.pair.remote.ip}');
  });

  // 7. Send media once connected.
  agent.send(Uint8List.fromList(<int>[/* RTP packet */]));
}
```

ICE restart preserves the previously-selected pair so media keeps flowing
(`agent.send` falls back to it) until the new session selects:

```dart
final IceParameters fresh = agent.restart()!;   // new ufrag + pwd
sendToPeerSdp('a=ice-ufrag:${fresh.ufrag}\r\na=ice-pwd:${fresh.pwd}');
agent.gather();                                  // re-gather
```

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Application                            │
└──────────┬───────────────┬─────────────────┬───────────────┘
           │               │                 │
     ┌─────▼─────┐   ┌─────▼──────┐    ┌─────▼─────┐
     │ TurnServer│   │ TurnSocket │    │  IceAgent │
     │ (server)  │   │ (client/srv)    │ (RFC 8445)│
     └─────┬─────┘   └─────┬──────┘    └─────┬─────┘
           │               │                  │
           └────┬──────────┴──────────────────┘
                │
        ┌───────▼───────┐
        │    Session    │  protocol state machine
        │  (RFC 8489    │  auth, allocations, permissions,
        │   RFC 8656)   │  channels, refresh, retransmit
        └───────┬───────┘
                │
        ┌───────▼───────┐
        │     wire      │  encode/decode, MESSAGE-INTEGRITY,
        │  (RFC 5389)   │  FINGERPRINT, demux, address codecs
        └───────────────┘

        ice_candidate (RFC 8839)  ── pure primitives, no I/O
```

| Module                                      | Purpose                                       |
|---------------------------------------------|-----------------------------------------------|
| [`wire.dart`](lib/src/wire.dart)            | STUN/TURN binary codec + URI parser           |
| [`ice_candidate.dart`](lib/src/ice_candidate.dart) | Candidate model, SDP grammar, priority |
| [`session.dart`](lib/src/session.dart)      | Protocol state machine (client + server)      |
| [`socket.dart`](lib/src/socket.dart)        | Transport bindings (UDP/TCP/TLS) + relay      |
| [`server.dart`](lib/src/server.dart)        | Multi-listener TURN server                    |
| [`ice_agent.dart`](lib/src/ice_agent.dart)  | RFC 8445 ICE Agent                            |
| [`index.dart`](lib/src/index.dart)          | `connect`, `getPublicIP`, `detectNAT`         |

## RFC compliance

| RFC      | Title                                     | Status |
|----------|-------------------------------------------|--------|
| RFC 5389 | STUN                                      | ✅ |
| RFC 8489 | STUN-bis (SHA-256, password algorithms)   | ✅ |
| RFC 5766 | TURN                                      | ✅ |
| RFC 8656 | TURN-bis (additional address family)      | ✅ |
| RFC 6062 | TURN extension for TCP allocations        | ✅ |
| RFC 7443 | ALPN labels for STUN/TURN over TLS        | ✅ |
| RFC 5780 | NAT behaviour discovery                   | ✅ |
| RFC 7635 | OAuth third-party auth                    | ✅ |
| RFC 8445 | ICE                                       | ✅ |
| RFC 8838 | Trickle ICE                               | ✅ |
| RFC 8839 | SDP for ICE                               | ✅ |
| RFC 7675 | ICE consent freshness                     | ✅ |
| RFC 6544 | TCP candidates for ICE                    | ⚠️ parse only |

## Testing

```bash
dart pub get
dart analyze            # → No issues found!
dart test               # → 62 tests passing
```

| Module          | Tests |
|-----------------|-------|
| `wire`          | 35    |
| `session`       | 9     |
| `socket`        | 2     |
| `server`        | 4     |
| `ice_agent`     | 6     |
| `index`         | 6     |
| **Total**       | **62** |

## Differences from the Node.js source

A few intentional omissions / changes vs. the JS implementation:

- **WebSocket transport** in `server.js` is omitted — Dart has no canonical
  WebSocket *server* in stdlib. Compose `package:web_socket_channel` with
  `TurnSocket(isServer: true).feed(bytes)` if you need it.
- **DNS SRV lookups** in `index.js`'s `resolve()` are omitted — `dart:io`
  exposes no public SRV API. `resolveServer` does A/AAAA only; resolve SRV
  externally if needed.
- **`set_context` reactive engine** in `ice_agent.js` is replaced with typed
  setters and a single `_runCascades()` recursion — same semantics, smaller
  surface.
- **Events** are typed broadcast `Stream<T>`s rather than `EventEmitter`.
- **Buffers** are `Uint8List`; we do not expose Node `Buffer` semantics.

## License

Apache-2.0 — see [LICENSE](LICENSE).
