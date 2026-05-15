// Transport layer — type-safe Dart port of `src/socket.js`.
//
// `TurnSocket` wires a [Session] (protocol state machine) to actual I/O:
//   - Client side: a `RawDatagramSocket` / `Socket` / `SecureSocket` that
//     talks to a remote TURN server.
//   - Server side: receives raw bytes from the listener (via [feed]) and
//     manages per-allocation relay sockets that forward UDP packets to peers.
//
// Spec references: RFC 5389 / 8489, RFC 5766 / 8656 (TURN), RFC 6062
// (TCP relay), RFC 5780 (NAT detection), RFC 8656 §18.13 (ICMP errors).

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'session.dart';
import 'wire.dart' as wire;

/* ============================== Public types ============================== */

/// Underlying transport used by the client to reach the TURN server.
enum TransportType { udp, tcp, tls }

/// Direction of a relayed packet, used by [RelayInfo].
enum RelayedDirection { inbound, outbound }

/// Description of a relayed packet — emitted on [TurnSocket.onRelayed].
class RelayedInfo {
  const RelayedInfo({
    required this.direction,
    required this.peer,
    required this.source,
    required this.username,
    required this.size,
    this.channel,
  });
  final RelayedDirection direction;
  final wire.StunAddress peer;
  final wire.StunAddress? source;
  final String? username;
  final int size;
  final int? channel;
}

/// ICMP error mapped from a relay-socket error (RFC 8656 §18.13).
class IcmpErrorEvent {
  const IcmpErrorEvent(
      {required this.type, required this.code, required this.error});
  final int type;
  final int code;
  final Object error;
}

/// Information passed to [RelayCallback] so apps can pick a relay IP /
/// port range per allocation (multi-IP, geo-routing).
class RelayCallbackInfo {
  const RelayCallbackInfo({
    required this.username,
    required this.source,
    required this.requestedFamily,
  });
  final String? username;
  final wire.StunAddress? source;
  final int? requestedFamily;
}

/// Optional override returned by a [RelayCallback].
class RelayConfig {
  const RelayConfig({this.ip, this.externalIp, this.portRange});
  final String? ip;
  final String? externalIp;
  final List<int>? portRange;
}

typedef RelayCallback = FutureOr<RelayConfig?> Function(RelayCallbackInfo info);

/// Server-side: function used to push outgoing bytes back to the client
/// across the shared listener socket.
typedef ClientSendFn = void Function(Uint8List buf);

/// Server-side hook: send a BINDING success from the secondary address
/// in response to a CHANGE-REQUEST (RFC 5780).
typedef SecondarySendFn = void Function(
    Uint8List buf, wire.ChangeRequestValue change);

/* ============================== Options ================================== */

class TurnSocketOptions {
  TurnSocketOptions({
    this.session,
    this.isServer = false,
    this.software,
    this.authMech = AuthMechanism.none,
    this.realm,
    this.credentials = const <String, String>{},
    this.secret,
    this.username,
    this.password,
    this.source,
    this.localAddress,
    this.relayIp,
    this.externalIp,
    this.portRange = const <int>[49152, 65535],
    this.maxAllocateLifetime = 3600,
    this.defaultAllocateLifetime = 600,
    this.secureStun = false,
    this.checkOriginConsistency = false,
    this.allowLoopback = false,
    this.allowMulticast = false,
    bool? useFingerprint,

    // I/O wiring
    this.send,
    this.transport,
    this.transportType = TransportType.udp,
    this.serverHost,
    this.serverPort = 3478,
    this.secondaryAddress,
    this.secondarySend,

    // Relay-port placement override
    this.relayCallback,

    // TLS-specific
    this.serverName,
    this.rejectUnauthorized = true,
    this.context,
  }) : useFingerprint = useFingerprint ?? (transportType != TransportType.tls);

  /// Pre-built session (used by Server which constructs one per client).
  /// If null, [TurnSocket] builds its own from the options below.
  final Session? session;

  final bool isServer;
  final String? software;
  final AuthMechanism authMech;
  final String? realm;
  final Map<String, String> credentials;
  final String? secret;
  final String? username;
  final String? password;
  final wire.StunAddress? source;
  final wire.StunAddress? localAddress;
  final String? relayIp;
  final String? externalIp;
  final List<int> portRange;
  final int maxAllocateLifetime;
  final int defaultAllocateLifetime;
  final bool secureStun;
  final bool checkOriginConsistency;
  final bool allowLoopback;
  final bool allowMulticast;
  final bool useFingerprint;

  /// Server-side: called with bytes to push to the connected client.
  final ClientSendFn? send;

  /// Client-side: pre-existing transport. Mutually exclusive with [connect].
  final Object? transport;
  final TransportType transportType;
  final String? serverHost;
  final int serverPort;

  final wire.StunAddress? secondaryAddress;
  final SecondarySendFn? secondarySend;

  final RelayCallback? relayCallback;

  final String? serverName;
  final bool rejectUnauthorized;
  final SecurityContext? context;
}

/* ============================== TurnSocket =============================== */

class TurnSocket {
  TurnSocket(TurnSocketOptions options) : _opts = options {
    _isServer = options.isServer;
    _session = options.session ?? _buildSession();
    _wireSession();
    if (!_isServer && options.transport != null) {
      _attachTransport(options.transport!);
    }
  }

  final TurnSocketOptions _opts;
  late final Session _session;
  late final bool _isServer;
  bool _destroyed = false;

  /* ---------- Client transport ---------- */
  RawDatagramSocket? _udpTransport;
  InternetAddress? _serverAddress;
  Socket? _tcpTransport;
  StreamSubscription<RawSocketEvent>? _udpSub;
  StreamSubscription<Uint8List>? _tcpSub;
  final List<int> _tcpBuffer = <int>[];

  /* ---------- Server relay ---------- */
  RawDatagramSocket? _relaySocket;
  StreamSubscription<RawSocketEvent>? _relaySub;
  wire.StunAddress? _relayAddress;

  /// Reservation tokens (hex) → reserved socket awaiting later ALLOCATE.
  final Map<String, RawDatagramSocket> _reservations =
      <String, RawDatagramSocket>{};

  /// RFC 6062 — connectionId → established TCP peer connection.
  final Map<int, Socket> _tcpPeerConnections = <int, Socket>{};

  /* ---------- Event sinks ---------- */
  final StreamController<void> _onConnect = StreamController<void>.broadcast();
  final StreamController<void> _onClose = StreamController<void>.broadcast();
  final StreamController<Object> _onError =
      StreamController<Object>.broadcast();
  final StreamController<Allocation> _onAllocateOut =
      StreamController<Allocation>.broadcast();
  final StreamController<Allocation> _onAllocateExpiredOut =
      StreamController<Allocation>.broadcast();
  final StreamController<RelayedInfo> _onRelayed =
      StreamController<RelayedInfo>.broadcast();
  final StreamController<IcmpErrorEvent> _onIcmpError =
      StreamController<IcmpErrorEvent>.broadcast();

  /* ---------- Public surface ---------- */

  Session get session => _session;
  bool get isServer => _isServer;
  bool get destroyed => _destroyed;
  wire.StunAddress? get relayAddress => _relayAddress;

  Stream<void> get onConnect => _onConnect.stream;
  Stream<void> get onClose => _onClose.stream;
  Stream<Object> get onError => _onError.stream;
  Stream<Allocation> get onAllocate => _onAllocateOut.stream;
  Stream<Allocation> get onAllocateExpired => _onAllocateExpiredOut.stream;
  Stream<RelayedInfo> get onRelayed => _onRelayed.stream;
  Stream<IcmpErrorEvent> get onIcmpError => _onIcmpError.stream;

  /// Server-side: feed raw client→server bytes (called by listener).
  void feed(Uint8List data) {
    if (_destroyed) return;
    _session.message(data);
  }

  /// Client-side: open the configured transport to the TURN server.
  Future<void> connect() async {
    if (_isServer) return;
    final String? host = _opts.serverHost;
    if (host == null) {
      throw StateError('serverHost required for client connect()');
    }
    final int port = _opts.serverPort;

    switch (_opts.transportType) {
      case TransportType.udp:
        // Resolve the server host (may be a hostname like
        // "stun.l.google.com") to an `InternetAddress` once, so subsequent
        // `RawDatagramSocket.send` calls don't throw `ArgumentError` for
        // non-IP literals.
        final List<InternetAddress> resolved = await InternetAddress.lookup(
          host,
          type: host.contains(':')
              ? InternetAddressType.IPv6
              : InternetAddressType.any,
        );
        if (resolved.isEmpty) {
          throw SocketException('Failed to resolve host: $host');
        }
        _serverAddress = resolved.first;
        final InternetAddress bind =
            _serverAddress!.type == InternetAddressType.IPv6
                ? InternetAddress.anyIPv6
                : InternetAddress.anyIPv4;
        _udpTransport = await RawDatagramSocket.bind(bind, 0);
        _attachUdp(_udpTransport!, host, port);

      case TransportType.tcp:
        _tcpTransport = await Socket.connect(host, port);
        _attachTcp(_tcpTransport!);

      case TransportType.tls:
        _tcpTransport = await SecureSocket.connect(
          host,
          port,
          context: _opts.context,
          onBadCertificate:
              _opts.rejectUnauthorized ? null : (X509Certificate _) => true,
        );
        _attachTcp(_tcpTransport!);
    }
    _onConnect.add(null);
  }

  /// Close the socket and release all OS resources. Idempotent.
  Future<void> close() async {
    if (_destroyed) return;
    _destroyed = true;

    _session.close();

    await _udpSub?.cancel();
    _udpSub = null;
    _udpTransport?.close();
    _udpTransport = null;

    await _tcpSub?.cancel();
    _tcpSub = null;
    try {
      await _tcpTransport?.close();
    } catch (_) {}
    _tcpTransport = null;

    await _relaySub?.cancel();
    _relaySub = null;
    _relaySocket?.close();
    _relaySocket = null;
    _relayAddress = null;

    for (final RawDatagramSocket s in _reservations.values) {
      s.close();
    }
    _reservations.clear();

    for (final Socket s in _tcpPeerConnections.values) {
      try {
        s.destroy();
      } catch (_) {}
    }
    _tcpPeerConnections.clear();

    _onClose.add(null);
    await _onConnect.close();
    await _onClose.close();
    await _onError.close();
    await _onAllocateOut.close();
    await _onAllocateExpiredOut.close();
    await _onRelayed.close();
    await _onIcmpError.close();
  }

  /* ============================== Internals ============================== */

  Session _buildSession() {
    return Session(SessionOptions(
      isServer: _opts.isServer,
      software: _opts.software,
      authMech: _opts.authMech,
      realm: _opts.realm,
      credentials: _opts.credentials,
      secret: _opts.secret,
      username: _opts.username,
      password: _opts.password,
      source: _opts.source,
      localAddress: _opts.localAddress,
      relayIp: _opts.relayIp,
      externalIp: _opts.externalIp,
      portRange: _opts.portRange,
      maxAllocateLifetime: _opts.maxAllocateLifetime,
      defaultAllocateLifetime: _opts.defaultAllocateLifetime,
      secureStun: _opts.secureStun,
      checkOriginConsistency: _opts.checkOriginConsistency,
      allowLoopback: _opts.allowLoopback,
      allowMulticast: _opts.allowMulticast,
      useFingerprint: _opts.useFingerprint,
      secondaryAddress: _opts.secondaryAddress,
    ));
  }

  void _wireSession() {
    // Outgoing on-wire bytes from the session.
    _session.onMessage.listen(_handleSessionMessage);
    _session.onError.listen(_emitError);

    if (_isServer) {
      _session.onAllocate.listen(_handleAllocate);
      _session.onAllocateExpired.listen(_handleAllocateExpired);
      _session.onRelay.listen(_handleSessionRelay);
      _session.onChangeRequest.listen(_handleChangeRequest);

      // RFC 6062 — TCP relay handlers required by Session.
      _session.connectPeerHandler =
          (int connectionId, wire.StunAddress peer) async {
        if (_destroyed) return StateError('socket destroyed');
        try {
          // ignore: close_sinks - lifecycle managed by _tcpPeerConnections / close()
          final Socket conn = await Socket.connect(
            peer.ip,
            peer.port,
            timeout: const Duration(seconds: 10),
          );
          _tcpPeerConnections[connectionId] = conn;
          unawaited(conn.done.whenComplete(() {
            _tcpPeerConnections.remove(connectionId);
          }));
          conn.handleError(_emitError);
          return null;
        } catch (e) {
          return e;
        }
      };

      _session.connectionBindHandler =
          (int connectionId, wire.StunAddress peer) async {
        // ignore: close_sinks - lifecycle managed by _tcpPeerConnections / close()
        final Socket? conn = _tcpPeerConnections[connectionId];
        if (conn == null) return StateError('no connection for ID');
        conn.listen(
          (Uint8List data) {
            if (_destroyed) return;
            _session.sendData(peer, data);
          },
          onError: _emitError,
          onDone: () {
            _tcpPeerConnections.remove(connectionId);
          },
        );
        return null;
      };
    }
  }

  void _handleSessionMessage(Uint8List buf) {
    if (_destroyed) return;
    final ClientSendFn? send = _opts.send;
    if (send != null) {
      send(buf);
      return;
    }
    if (!_isServer) _sendToServer(buf);
  }

  void _sendToServer(Uint8List buf) {
    if (_destroyed) return;
    if (_opts.transportType == TransportType.udp) {
      final RawDatagramSocket? t = _udpTransport;
      final InternetAddress? addr =
          _serverAddress ?? _tryParseLiteral(_opts.serverHost);
      if (t == null || addr == null) return;
      try {
        t.send(buf, addr, _opts.serverPort);
      } catch (e) {
        _emitError(e);
      }
    } else {
      final Socket? t = _tcpTransport;
      if (t == null) return;
      try {
        t.add(wire.tcpFrame(buf));
      } catch (e) {
        _emitError(e);
      }
    }
  }

  /* ---------- Transport binding ---------- */

  /// Parse [host] as an IP literal. Returns `null` if it isn't a valid
  /// IPv4/IPv6 literal (callers should resolve hostnames separately).
  InternetAddress? _tryParseLiteral(String? host) {
    if (host == null) return null;
    return InternetAddress.tryParse(host);
  }

  void _attachTransport(Object transport) {
    if (transport is RawDatagramSocket) {
      _udpTransport = transport;
      _attachUdp(transport, _opts.serverHost, _opts.serverPort);
    } else if (transport is Socket) {
      _tcpTransport = transport;
      _attachTcp(transport);
    } else {
      throw ArgumentError(
          'transport must be RawDatagramSocket or Socket, got ${transport.runtimeType}');
    }
  }

  void _attachUdp(RawDatagramSocket sock, String? _, int __) {
    _udpSub = sock.listen(
      (RawSocketEvent ev) {
        if (_destroyed) return;
        if (ev != RawSocketEvent.read) return;
        final Datagram? dg = sock.receive();
        if (dg == null) return;
        _session.message(dg.data);
      },
      onError: _emitError,
      onDone: () => _onClose.add(null),
    );
  }

  void _attachTcp(Socket sock) {
    _tcpSub = sock.listen(
      (Uint8List chunk) {
        if (_destroyed) return;
        _tcpBuffer.addAll(chunk);
        _drainTcpFrames();
      },
      onError: _emitError,
      onDone: () => _onClose.add(null),
    );
  }

  void _drainTcpFrames() {
    while (_tcpBuffer.length >= 2) {
      final int frameLen = (_tcpBuffer[0] << 8) | _tcpBuffer[1];
      if (_tcpBuffer.length < 2 + frameLen) return;
      final Uint8List frame =
          Uint8List.fromList(_tcpBuffer.sublist(2, 2 + frameLen));
      _tcpBuffer.removeRange(0, 2 + frameLen);
      _session.message(frame);
    }
  }

  /* ---------- Server: relay management ---------- */

  Future<void> _handleAllocate(Allocation alloc) async {
    if (!_isServer) return;
    // Take ownership synchronously so the session's fallback path doesn't
    // confirm with the placeholder relay address before our async bind.
    alloc.confirmed = true;
    try {
      final _RelayBindResult result = await _allocateRelayPort(alloc);
      _relaySocket = result.socket;
      _relayAddress = result.address;
      _bindRelaySocket(result.socket);
      alloc.confirm?.call(result.address);
      _onAllocateOut.add(alloc);
    } catch (e) {
      alloc.reject?.call(e);
      _emitError(e);
    }
  }

  void _handleAllocateExpired(Allocation alloc) {
    _relaySub?.cancel();
    _relaySub = null;
    try {
      _relaySocket?.close();
    } catch (_) {}
    _relaySocket = null;
    _relayAddress = null;
    _onAllocateExpiredOut.add(alloc);
  }

  Future<_RelayBindResult> _allocateRelayPort(Allocation alloc) async {
    String relayIp = _opts.relayIp ?? '0.0.0.0';
    String externalIp = _opts.externalIp ?? relayIp;
    int minPort = _opts.portRange[0];
    int maxPort = _opts.portRange[1];

    if (externalIp == '0.0.0.0' || externalIp == '::') {
      final wire.StunAddress? la = _session.localAddress;
      if (la != null &&
          la.ip != '0.0.0.0' &&
          la.ip != '::' &&
          !la.ip.startsWith('127.') &&
          la.ip != '::1') {
        externalIp = la.ip;
      } else {
        externalIp = await _detectExternalIp() ?? '127.0.0.1';
      }
    }

    final RelayCallback? cb = _opts.relayCallback;
    if (cb != null) {
      final RelayConfig? cfg = await cb(RelayCallbackInfo(
        username: alloc.username,
        source: _session.source,
        requestedFamily: alloc.requestedFamily,
      ));
      if (cfg != null) {
        if (cfg.ip != null) relayIp = cfg.ip!;
        if (cfg.externalIp != null) externalIp = cfg.externalIp!;
        if (cfg.portRange != null) {
          minPort = cfg.portRange![0];
          maxPort = cfg.portRange![1];
        }
      }
    }

    // RESERVATION-TOKEN — use a previously-reserved socket.
    final Uint8List? tok = alloc.reservationToken;
    if (tok != null) {
      final String hex = _hex(tok);
      final RawDatagramSocket? reserved = _reservations.remove(hex);
      if (reserved == null) {
        throw StateError('Invalid reservation token');
      }
      return _RelayBindResult(
        socket: reserved,
        address: wire.StunAddress(
          family: alloc.requestedFamily ?? wire.AddressFamily.ipv4,
          ip: externalIp,
          port: reserved.port,
        ),
      );
    }

    final bool ipv6 = alloc.requestedFamily == wire.AddressFamily.ipv6;
    final InternetAddress bindAddr = _resolveLocalBind(relayIp, ipv6: ipv6);
    final bool needEven = alloc.evenPort == true;

    const int maxAttempts = 100;
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
      int port;
      if (needEven) {
        final int half = math.max(1, (maxPort - minPort) ~/ 2);
        port = minPort + math.Random().nextInt(half) * 2;
        if (port.isOdd) port++;
      } else {
        port = minPort + math.Random().nextInt(math.max(1, maxPort - minPort));
      }
      try {
        final RawDatagramSocket sock =
            await RawDatagramSocket.bind(bindAddr, port);

        if (needEven) {
          // Reserve N+1.
          try {
            final RawDatagramSocket reserve =
                await RawDatagramSocket.bind(bindAddr, port + 1);
            final Uint8List token = _randomBytes(8);
            _reservations[_hex(token)] = reserve;
          } catch (_) {
            sock.close();
            continue; // try a different even port
          }
        }
        return _RelayBindResult(
          socket: sock,
          address: wire.StunAddress(
            family: ipv6 ? wire.AddressFamily.ipv6 : wire.AddressFamily.ipv4,
            ip: externalIp,
            port: sock.port,
          ),
        );
      } catch (_) {
        // Port busy — try another.
      }
    }
    throw StateError('No available relay port in range $minPort-$maxPort');
  }

  InternetAddress _resolveLocalBind(String ip, {required bool ipv6}) {
    if (ip == '0.0.0.0' || ip == '::') {
      return ipv6 ? InternetAddress.anyIPv6 : InternetAddress.anyIPv4;
    }
    return InternetAddress(ip);
  }

  Future<String?> _detectExternalIp() async {
    try {
      final List<NetworkInterface> ifs = await NetworkInterface.list(
        includeLoopback: false,
        type: InternetAddressType.IPv4,
      );
      for (final NetworkInterface i in ifs) {
        for (final InternetAddress a in i.addresses) {
          if (!a.isLoopback && a.type == InternetAddressType.IPv4) {
            return a.address;
          }
        }
      }
    } catch (_) {
      // fall through
    }
    return null;
  }

  void _bindRelaySocket(RawDatagramSocket sock) {
    _relaySub = sock.listen((RawSocketEvent ev) {
      if (_destroyed) return;
      if (ev == RawSocketEvent.readClosed || ev == RawSocketEvent.closed) {
        return;
      }
      if (ev == RawSocketEvent.read) {
        final Datagram? dg = sock.receive();
        if (dg == null) return;
        final wire.StunAddress from = wire.StunAddress(
          family: dg.address.type == InternetAddressType.IPv6
              ? wire.AddressFamily.ipv6
              : wire.AddressFamily.ipv4,
          ip: dg.address.address,
          port: dg.port,
        );
        _onPeerData(from, dg.data);
      }
    }, onError: (Object err) {
      if (_destroyed) return;
      _emitError(err);
      // Best-effort ICMP mapping — Dart doesn't expose recvmsg/MSG_ERRQUEUE,
      // so we surface SocketException with errno hints when available.
      int code = 3; // port unreachable
      if (err is SocketException) {
        final String s = err.osError?.message.toLowerCase() ?? '';
        if (s.contains('host')) {
          code = 1;
        } else if (s.contains('network')) {
          code = 0;
        }
      }
      _onIcmpError.add(IcmpErrorEvent(type: 3, code: code, error: err));
    });
  }

  void _onPeerData(wire.StunAddress from, Uint8List data) {
    if (!_session.hasPermission(from.ip)) return;

    final Allocation? alloc = _session.allocation;
    final String? username = alloc?.username;

    final int? channel = _session.getChannelByPeer(from.ip, from.port);
    if (channel != null) {
      _session.sendChannelData(channel, data);
    } else {
      _session.sendData(from, data);
    }

    _onRelayed.add(RelayedInfo(
      direction: RelayedDirection.inbound,
      peer: from,
      source: _session.source,
      username: username,
      size: data.length,
      channel: channel,
    ));
  }

  void _handleSessionRelay(RelayEvent ev) {
    if (_destroyed) return;
    final RawDatagramSocket? sock = _relaySocket;
    if (sock == null) return;
    try {
      sock.send(ev.data, InternetAddress(ev.peer.ip), ev.peer.port);
    } catch (e) {
      _emitError(e);
      return;
    }
    _onRelayed.add(RelayedInfo(
      direction: RelayedDirection.outbound,
      peer: ev.peer,
      source: _session.source,
      username: _session.allocation?.username,
      size: ev.data.length,
      channel: ev.channel,
    ));
  }

  void _handleChangeRequest(ChangeRequestEvent ev) {
    final SecondarySendFn? send = _opts.secondarySend;
    if (send == null) return;
    final wire.EncodedMessage result = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.success,
      transactionId: ev.message.transactionId,
      attributes: ev.responseAttributes,
    ));
    send(result.buf, ev.change);
  }

  void _emitError(Object err) {
    if (_onError.isClosed) return;
    _onError.add(err);
  }
}

/* ============================== Helpers ================================== */

class _RelayBindResult {
  const _RelayBindResult({required this.socket, required this.address});
  final RawDatagramSocket socket;
  final wire.StunAddress address;
}

String _hex(Uint8List bytes) {
  final StringBuffer sb = StringBuffer();
  for (final int b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List _randomBytes(int n) {
  final math.Random rng = math.Random.secure();
  final Uint8List out = Uint8List(n);
  for (int i = 0; i < n; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}
