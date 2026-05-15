// Multi-listener TURN server — type-safe Dart port of `src/server.js`.
//
// `TurnServer` accepts UDP / TCP / TLS clients on one or more listeners,
// spins up a per-client [TurnSocket] (and underlying [Session]), enforces
// quotas / limits, exposes a graceful drain, and tracks aggregate stats.
//
// WebSocket support from the JS port is intentionally omitted: Dart has no
// canonical WS server, but applications can integrate `package:web_socket_channel`
// or `dart:io` `HttpServer` upgrades by manually constructing a [TurnSocket]
// with `isServer: true` and a custom `send` callback, then calling `feed`.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'session.dart';
import 'socket.dart';
import 'wire.dart' as wire;

/* ============================== Public types ============================== */

/// Underlying transport for a [ListenConfig].
enum ServerTransport { udp, tcp, tls }

/// Configuration for one listener. Per-listener TLS material overrides the
/// server-level [SecurityContext].
class ListenConfig {
  const ListenConfig({
    this.transport = ServerTransport.udp,
    this.address = '0.0.0.0',
    this.port = 3478,
    this.context,
    this.alpnProtocols = const <String>['stun.turn', 'stun.nat-discovery'],
  });

  final ServerTransport transport;
  final String address;
  final int port;

  /// Required for [ServerTransport.tls]; ignored otherwise. Falls back to the
  /// server-level [TurnServerOptions.context] when null.
  final SecurityContext? context;

  /// RFC 7443 ALPN identifiers for STUN/TURN over TLS.
  final List<String> alpnProtocols;
}

/// Relay configuration shared by all per-client sockets.
class RelayServerConfig {
  const RelayServerConfig({
    this.ip = '0.0.0.0',
    this.externalIp,
    this.portRange = const <int>[49152, 65535],
  });
  final String ip;
  final String? externalIp;
  final List<int> portRange;
}

/// Authentication configuration shared by all per-client sockets.
class AuthServerConfig {
  const AuthServerConfig({
    this.mechanism = AuthMechanism.none,
    this.realm,
    this.credentials = const <String, String>{},
    this.secret,
  });
  final AuthMechanism mechanism;
  final String? realm;
  final Map<String, String> credentials;
  final String? secret;
}

/// Per-connection accept hook. Return `false` to drop.
class AcceptInfo {
  const AcceptInfo({required this.source, required this.transport});
  final wire.StunAddress source;
  final ServerTransport transport;
}

typedef AcceptHook = bool Function(AcceptInfo info);

/// Realm/credential resolver — invoked per inbound 5-tuple.
class RealmResolution {
  const RealmResolution({
    this.realm,
    this.mechanism,
    this.credentials,
    this.secret,
  });
  final String? realm;
  final AuthMechanism? mechanism;
  final Map<String, String>? credentials;
  final String? secret;
}

typedef RealmCallback = FutureOr<RealmResolution?> Function(
    wire.StunAddress source);

/// Listening notification.
class ListeningEvent {
  const ListeningEvent(
      {required this.transport, required this.address, required this.port});
  final ServerTransport transport;
  final String address;
  final int port;
}

/// Aggregate server statistics.
class ServerStats {
  ServerStats();
  int totalConnections = 0;
  int activeConnections = 0;
  int totalAllocations = 0;
  int activeAllocations = 0;
  int authFailures = 0;
  int packetsRelayed = 0;
  int bytesRelayed = 0;

  ServerStats snapshot() => ServerStats()
    ..totalConnections = totalConnections
    ..activeConnections = activeConnections
    ..totalAllocations = totalAllocations
    ..activeAllocations = activeAllocations
    ..authFailures = authFailures
    ..packetsRelayed = packetsRelayed
    ..bytesRelayed = bytesRelayed;
}

/* ============================== Options ================================== */

class TurnServerOptions {
  TurnServerOptions({
    this.software,
    this.listen = const <ListenConfig>[],
    this.relay = const RelayServerConfig(),
    this.auth = const AuthServerConfig(),
    this.context,
    this.realmCallback,
    this.relayCallback,
    this.maxAllocateLifetime = 3600,
    this.defaultAllocateLifetime = 600,
    this.secureStun = false,
    this.checkOriginConsistency = false,
    this.allowLoopback = false,
    this.allowMulticast = false,
    this.maxConnections = 0,
    this.userQuota = 0,
    this.totalQuota = 0,
    this.maxDataSize = 0,
    this.maxPermissionsPerAllocation = 0,
    this.maxChannelsPerAllocation = 0,
    this.idleTimeout = const Duration(minutes: 5),
    this.acceptHook,
    this.authenticateHandler,
    this.oauthHandler,
    this.authorize,
    this.beforeAllocate,
    this.beforeRefresh,
    this.beforePermission,
    this.beforeChannelBind,
    this.beforeRelay,
    this.beforeConnect,
  });

  final String? software;
  final List<ListenConfig> listen;
  final RelayServerConfig relay;
  final AuthServerConfig auth;

  /// Server-level fallback TLS context.
  final SecurityContext? context;

  final RealmCallback? realmCallback;
  final RelayCallback? relayCallback;

  final int maxAllocateLifetime;
  final int defaultAllocateLifetime;
  final bool secureStun;
  final bool checkOriginConsistency;
  final bool allowLoopback;
  final bool allowMulticast;

  /// Convenience limits — `0` means unlimited.
  final int maxConnections;
  final int userQuota;
  final int totalQuota;
  final int maxDataSize;
  final int maxPermissionsPerAllocation;
  final int maxChannelsPerAllocation;

  /// UDP idle timeout — drop a 5-tuple after this much silence. Use
  /// [Duration.zero] to disable.
  final Duration idleTimeout;

  /// Synchronous accept gate — return `false` to reject.
  final AcceptHook? acceptHook;

  /// User-supplied auth/authorization hooks. These are wired into every
  /// per-client [Session] in addition to (and after) the built-in quota checks.
  final AuthenticateHandler? authenticateHandler;
  final OauthHandler? oauthHandler;
  final Hook<AuthorizeInfo>? authorize;
  final Hook<AllocateInfo>? beforeAllocate;
  final Hook<RefreshInfo>? beforeRefresh;
  final Hook<PermissionInfo>? beforePermission;
  final Hook<ChannelBindInfo>? beforeChannelBind;
  final Hook<RelayInfo>? beforeRelay;
  final Hook<ConnectInfo>? beforeConnect;
}

/* ============================== TurnServer ================================ */

class TurnServer {
  TurnServer(TurnServerOptions options) : _opts = options;

  final TurnServerOptions _opts;

  bool _destroyed = false;
  bool _draining = false;

  final List<_Listener> _listeners = <_Listener>[];
  final Map<String, _ClientEntry> _clients = <String, _ClientEntry>{};
  final Map<String, int> _userAllocations = <String, int>{};
  final ServerStats _stats = ServerStats();

  final StreamController<ListeningEvent> _onListening =
      StreamController<ListeningEvent>.broadcast();
  final StreamController<TurnSocket> _onConnection =
      StreamController<TurnSocket>.broadcast();
  final StreamController<AllocateServerEvent> _onAllocate =
      StreamController<AllocateServerEvent>.broadcast();
  final StreamController<AllocateServerEvent> _onAllocateExpired =
      StreamController<AllocateServerEvent>.broadcast();
  final StreamController<RelayedServerEvent> _onRelayed =
      StreamController<RelayedServerEvent>.broadcast();
  final StreamController<Object> _onError =
      StreamController<Object>.broadcast();
  final StreamController<void> _onClose = StreamController<void>.broadcast();

  /* ---------- Public surface ---------- */

  Stream<ListeningEvent> get onListening => _onListening.stream;
  Stream<TurnSocket> get onConnection => _onConnection.stream;
  Stream<AllocateServerEvent> get onAllocate => _onAllocate.stream;
  Stream<AllocateServerEvent> get onAllocateExpired =>
      _onAllocateExpired.stream;
  Stream<RelayedServerEvent> get onRelayed => _onRelayed.stream;
  Stream<Object> get onError => _onError.stream;
  Stream<void> get onClose => _onClose.stream;

  bool get isDraining => _draining;
  bool get isHealthy => !_destroyed && _listeners.isNotEmpty;
  int get clientCount => _clients.length;
  ServerStats getStats() => _stats.snapshot();

  /// Map of opaque 5-tuple key → [TurnSocket]. Treat as read-only.
  Map<String, TurnSocket> getClients() => <String, TurnSocket>{
        for (final MapEntry<String, _ClientEntry> e in _clients.entries)
          e.key: e.value.socket,
      };

  /// Start every listener configured in [TurnServerOptions.listen]. Returns
  /// when each listener has bound (or thrown).
  Future<void> start() async {
    for (final ListenConfig lc in _opts.listen) {
      await _startListener(lc);
    }
  }

  /// Start one or more listeners. If a [ListenConfig] omits the transport
  /// override below, the JS port's behavior is reproduced (UDP only); pass
  /// explicit configs to combine UDP+TCP on the same port.
  Future<void> listen(List<ListenConfig> configs) async {
    for (final ListenConfig lc in configs) {
      await _startListener(lc);
    }
  }

  /// Add (or update) a static credential on every running client and on the
  /// shared credentials map used by future clients.
  void addUser(String username, String password) {
    _opts.auth.credentials.cast<String, String>(); // typed access
    final Map<String, String> creds =
        Map<String, String>.of(_opts.auth.credentials)..[username] = password;
    _replaceCredentials(creds);
    for (final _ClientEntry c in _clients.values) {
      c.socket.session.addUser(username, password);
    }
  }

  /// Remove a static credential.
  void removeUser(String username) {
    final Map<String, String> creds =
        Map<String, String>.of(_opts.auth.credentials)..remove(username);
    _replaceCredentials(creds);
    for (final _ClientEntry c in _clients.values) {
      c.socket.session.removeUser(username);
    }
  }

  // The shared credentials map lives on the const-ish AuthServerConfig — we
  // copy it into the live map exposed to new clients via _resolveAuth().
  Map<String, String> _liveCredentials = <String, String>{};
  void _replaceCredentials(Map<String, String> creds) {
    _liveCredentials = creds;
  }

  /// Graceful shutdown — stop accepting new connections, wait for clients to
  /// drain (or [timeout] to elapse), then [stop].
  Future<void> drain([Duration timeout = const Duration(seconds: 30)]) async {
    _draining = true;
    final DateTime deadline = DateTime.now().add(timeout);
    while (_clients.isNotEmpty && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    await stop();
  }

  /// Hard shutdown — close all listeners, all clients, all event sinks.
  Future<void> stop() async {
    if (_destroyed) return;
    _destroyed = true;
    _draining = false;

    // Close clients first so their session.close() runs cleanly.
    final List<_ClientEntry> snapshot = _clients.values.toList();
    _clients.clear();
    for (final _ClientEntry c in snapshot) {
      c.idleTimer?.cancel();
      try {
        await c.socket.close();
      } catch (_) {}
    }

    for (final _Listener l in _listeners) {
      await l.close();
    }
    _listeners.clear();

    if (!_onClose.isClosed) _onClose.add(null);
    await Future.wait(<Future<void>>[
      _onListening.close(),
      _onConnection.close(),
      _onAllocate.close(),
      _onAllocateExpired.close(),
      _onRelayed.close(),
      _onError.close(),
      _onClose.close(),
    ]);
  }

  /* ============================== Internals ============================== */

  Future<void> _startListener(ListenConfig lc) async {
    switch (lc.transport) {
      case ServerTransport.udp:
        await _startUdp(lc);
      case ServerTransport.tcp:
        await _startTcp(lc);
      case ServerTransport.tls:
        await _startTls(lc);
    }
  }

  /* ---------- UDP listener ---------- */

  Future<void> _startUdp(ListenConfig lc) async {
    final InternetAddress bind = _bindAddr(lc.address);
    final RawDatagramSocket sock =
        await RawDatagramSocket.bind(bind, lc.port, reuseAddress: true);
    final wire.StunAddress local = wire.StunAddress(
      family: bind.type == InternetAddressType.IPv6
          ? wire.AddressFamily.ipv6
          : wire.AddressFamily.ipv4,
      ip: lc.address,
      port: sock.port,
    );

    final StreamSubscription<RawSocketEvent> sub =
        sock.listen((RawSocketEvent ev) {
      if (_destroyed) return;
      if (ev != RawSocketEvent.read) return;
      final Datagram? dg = sock.receive();
      if (dg == null) return;

      final wire.StunAddress src = wire.StunAddress(
        family: dg.address.type == InternetAddressType.IPv6
            ? wire.AddressFamily.ipv6
            : wire.AddressFamily.ipv4,
        ip: dg.address.address,
        port: dg.port,
      );
      final String key = _udpKey(src.ip, src.port, local.ip, local.port);

      _ClientEntry? entry = _clients[key];
      if (entry == null) {
        if (_draining) return;
        if (_opts.maxConnections > 0 &&
            _stats.activeConnections >= _opts.maxConnections) {
          return;
        }
        if (!_runAccept(src, ServerTransport.udp)) return;

        // Capture for closure.
        final InternetAddress dstAddr = dg.address;
        final int dstPort = dg.port;

        final TurnSocket client = _createClientSocket(
          source: src,
          localAddress: local,
          send: (Uint8List buf) {
            if (_destroyed) return;
            try {
              sock.send(buf, dstAddr, dstPort);
            } catch (e) {
              _emitError(e);
            }
          },
        );
        entry = _ClientEntry(socket: client, key: key);
        _clients[key] = entry;
        _attachClientLifecycle(entry);
        if (_opts.idleTimeout > Duration.zero) {
          entry.idleTimer = _armIdleTimer(key);
        }
      } else if (entry.idleTimer != null) {
        entry.idleTimer!.cancel();
        entry.idleTimer = _armIdleTimer(key);
      }

      entry.socket.feed(dg.data);
    }, onError: _emitError);

    _listeners.add(_Listener(
      transport: ServerTransport.udp,
      close: () async {
        await sub.cancel();
        sock.close();
      },
    ));
    _onListening.add(ListeningEvent(
        transport: ServerTransport.udp, address: lc.address, port: sock.port));
  }

  /* ---------- TCP / TLS listeners ---------- */

  Future<void> _startTcp(ListenConfig lc) async {
    final ServerSocket server =
        await ServerSocket.bind(_bindAddr(lc.address), lc.port);
    _bindStreamServer(lc, server, ServerTransport.tcp);
  }

  Future<void> _startTls(ListenConfig lc) async {
    final SecurityContext? ctx = lc.context ?? _opts.context;
    if (ctx == null) {
      throw StateError('TLS listener requires a SecurityContext');
    }
    final SecureServerSocket server = await SecureServerSocket.bind(
      _bindAddr(lc.address),
      lc.port,
      ctx,
      supportedProtocols: lc.alpnProtocols,
    );
    _bindStreamServer(lc, server, ServerTransport.tls);
  }

  void _bindStreamServer(
      ListenConfig lc, Stream<Socket> server, ServerTransport tag) {
    final StreamSubscription<Socket> sub = server.listen((Socket conn) {
      if (_destroyed) {
        conn.destroy();
        return;
      }
      _handleStreamConnection(conn, tag);
    }, onError: _emitError);

    int boundPort;
    if (server is ServerSocket) {
      boundPort = server.port;
    } else if (server is SecureServerSocket) {
      boundPort = server.port;
    } else {
      boundPort = lc.port;
    }

    _listeners.add(_Listener(
      transport: tag,
      close: () async {
        await sub.cancel();
        if (server is ServerSocket) await server.close();
        if (server is SecureServerSocket) await server.close();
      },
    ));
    _onListening.add(
        ListeningEvent(transport: tag, address: lc.address, port: boundPort));
  }

  void _handleStreamConnection(Socket conn, ServerTransport tag) {
    final wire.StunAddress src = wire.StunAddress(
      family: conn.remoteAddress.type == InternetAddressType.IPv6
          ? wire.AddressFamily.ipv6
          : wire.AddressFamily.ipv4,
      ip: conn.remoteAddress.address,
      port: conn.remotePort,
    );

    if (!_runAccept(src, tag)) {
      conn.destroy();
      return;
    }

    final wire.StunAddress local = wire.StunAddress(
      family: conn.address.type == InternetAddressType.IPv6
          ? wire.AddressFamily.ipv6
          : wire.AddressFamily.ipv4,
      ip: conn.address.address,
      port: conn.port,
    );

    final TurnSocket client = _createClientSocket(
      source: src,
      localAddress: local,
      send: (Uint8List buf) {
        try {
          conn.add(buf);
        } catch (e) {
          _emitError(e);
        }
      },
    );

    final String key = '${tag.name}:${src.ip}:${src.port}';
    final _ClientEntry entry = _ClientEntry(socket: client, key: key);
    _clients[key] = entry;
    _attachClientLifecycle(entry);

    final List<int> buf = <int>[];
    entry.streamSub = conn.listen(
        (Uint8List chunk) {
          if (_destroyed) return;
          buf.addAll(chunk);
          _drainStunOverTcp(buf, client);
        },
        onError: _emitError,
        onDone: () {
          _removeClient(key);
          try {
            conn.destroy();
          } catch (_) {}
        });
  }

  /// RFC 8489 §6.2.2: STUN-over-TCP uses STUN's own length, not a 2-byte
  /// length-prefix (that's only the legacy NAT-discovery profile).
  void _drainStunOverTcp(List<int> buf, TurnSocket client) {
    while (buf.length >= 4) {
      final int first = buf[0];
      int msgLen;
      if ((first & 0xC0) == 0x00) {
        // STUN: 20-byte header + body length
        final int bodyLen = (buf[2] << 8) | buf[3];
        msgLen = 20 + bodyLen;
      } else if (first >= 0x40 && first <= 0x4F) {
        // ChannelData: 4-byte header + data, padded to 4-byte boundary
        final int dataLen = (buf[2] << 8) | buf[3];
        msgLen = 4 + dataLen;
        if (msgLen % 4 != 0) msgLen += 4 - (msgLen % 4);
      } else {
        // Junk byte — skip to resync.
        buf.removeAt(0);
        continue;
      }
      if (buf.length < msgLen) return;
      final Uint8List frame = Uint8List.fromList(buf.sublist(0, msgLen));
      buf.removeRange(0, msgLen);
      client.feed(frame);
    }
  }

  /* ---------- Client lifecycle ---------- */

  bool _runAccept(wire.StunAddress source, ServerTransport tag) {
    final AcceptHook? h = _opts.acceptHook;
    if (h == null) return true;
    try {
      return h(AcceptInfo(source: source, transport: tag));
    } catch (e) {
      _emitError(e);
      return false;
    }
  }

  TurnSocket _createClientSocket({
    required wire.StunAddress source,
    required wire.StunAddress localAddress,
    required ClientSendFn send,
  }) {
    // Apply realmCallback synchronously (must complete before the first packet
    // is fed). We pass a snapshot of the resolution into the per-client config.
    String? realm = _opts.auth.realm;
    AuthMechanism mech = _opts.auth.mechanism;
    Map<String, String> creds = _liveCredentials.isEmpty
        ? Map<String, String>.of(_opts.auth.credentials)
        : _liveCredentials;
    String? secret = _opts.auth.secret;

    // Note: realmCallback is async-capable; we invoke it but don't await here
    // because the JS pattern is fire-and-forget for sync-resolution callers.
    // Async resolvers should set credentials before any client traffic is
    // expected, or use the lower-level TurnSocket directly.
    final RealmCallback? rc = _opts.realmCallback;
    if (rc != null) {
      final Object? maybeFut = rc(source);
      if (maybeFut is RealmResolution) {
        if (maybeFut.realm != null) realm = maybeFut.realm;
        if (maybeFut.mechanism != null) mech = maybeFut.mechanism!;
        if (maybeFut.credentials != null) creds = maybeFut.credentials!;
        if (maybeFut.secret != null) secret = maybeFut.secret;
      }
    }

    final TurnSocket sock = TurnSocket(TurnSocketOptions(
      isServer: true,
      software: _opts.software,
      authMech: mech,
      realm: realm,
      credentials: creds,
      secret: secret,
      source: source,
      localAddress: localAddress,
      relayIp: _opts.relay.ip,
      externalIp: _opts.relay.externalIp,
      portRange: _opts.relay.portRange,
      maxAllocateLifetime: _opts.maxAllocateLifetime,
      defaultAllocateLifetime: _opts.defaultAllocateLifetime,
      secureStun: _opts.secureStun,
      checkOriginConsistency: _opts.checkOriginConsistency,
      allowLoopback: _opts.allowLoopback,
      allowMulticast: _opts.allowMulticast,
      relayCallback: _opts.relayCallback,
      send: send,
    ));

    _wireClientHooks(sock);
    return sock;
  }

  void _wireClientHooks(TurnSocket sock) {
    final Session sess = sock.session;

    // User-supplied callbacks pass through directly.
    sess.authenticateHandler = _opts.authenticateHandler;
    sess.oauthHandler = _opts.oauthHandler;
    sess.authorize = _opts.authorize;
    sess.beforeRefresh = _opts.beforeRefresh;
    sess.beforeConnect = _opts.beforeConnect;
    sess.beforeAllocate = _opts.beforeAllocate;

    // Built-in quotas — totalQuota / userQuota → 486 Allocation Quota.
    if (_opts.totalQuota > 0 || _opts.userQuota > 0) {
      sess.quotaHook = (String? username) {
        if (_opts.totalQuota > 0 &&
            _stats.activeAllocations >= _opts.totalQuota) {
          return false;
        }
        if (_opts.userQuota > 0) {
          final String u = username ?? '_anon';
          final int count = _userAllocations[u] ?? 0;
          if (count >= _opts.userQuota) return false;
        }
        return true;
      };
    }

    final Hook<RelayInfo>? userBeforeRelay = _opts.beforeRelay;
    sess.beforeRelay = (RelayInfo info) {
      if (_opts.maxDataSize > 0 && info.size > _opts.maxDataSize) {
        return false;
      }
      if (userBeforeRelay != null) return userBeforeRelay(info);
      return true;
    };

    final Hook<PermissionInfo>? userBeforePerm = _opts.beforePermission;
    sess.beforePermission = (PermissionInfo info) {
      if (_opts.maxPermissionsPerAllocation > 0) {
        final Allocation? alloc = sess.allocation;
        if (alloc != null &&
            alloc.permissions.length >= _opts.maxPermissionsPerAllocation) {
          return false;
        }
      }
      if (userBeforePerm != null) return userBeforePerm(info);
      return true;
    };

    final Hook<ChannelBindInfo>? userBeforeCh = _opts.beforeChannelBind;
    sess.beforeChannelBind = (ChannelBindInfo info) {
      if (_opts.maxChannelsPerAllocation > 0) {
        final Allocation? alloc = sess.allocation;
        if (alloc != null &&
            alloc.channels.length >= _opts.maxChannelsPerAllocation) {
          return false;
        }
      }
      if (userBeforeCh != null) return userBeforeCh(info);
      return true;
    };
  }

  void _attachClientLifecycle(_ClientEntry entry) {
    _stats.totalConnections++;
    _stats.activeConnections++;

    final TurnSocket sock = entry.socket;

    entry.subs.add(sock.onAllocate.listen((Allocation alloc) {
      _stats.totalAllocations++;
      _stats.activeAllocations++;
      final String u = alloc.username ?? '_anon';
      _userAllocations[u] = (_userAllocations[u] ?? 0) + 1;
      _onAllocate.add(AllocateServerEvent(socket: sock, allocation: alloc));
    }));

    entry.subs.add(sock.onAllocateExpired.listen((Allocation alloc) {
      if (_stats.activeAllocations > 0) _stats.activeAllocations--;
      final String u = alloc.username ?? '_anon';
      final int? n = _userAllocations[u];
      if (n != null && n > 0) {
        _userAllocations[u] = n - 1;
        if (_userAllocations[u] == 0) _userAllocations.remove(u);
      }
      _onAllocateExpired
          .add(AllocateServerEvent(socket: sock, allocation: alloc));
    }));

    entry.subs.add(sock.onRelayed.listen((RelayedInfo info) {
      _stats.packetsRelayed++;
      _stats.bytesRelayed += info.size;
      _onRelayed.add(RelayedServerEvent(socket: sock, info: info));
    }));

    entry.subs.add(sock.onError.listen(_emitError));
    entry.subs.add(sock.session.onError.listen(_emitError));

    entry.subs.add(sock.onClose.listen((_) {
      if (_stats.activeConnections > 0) _stats.activeConnections--;
      _removeClient(entry.key);
    }));

    _onConnection.add(sock);
  }

  void _removeClient(String key) {
    final _ClientEntry? entry = _clients.remove(key);
    if (entry == null) return;
    entry.idleTimer?.cancel();
    entry.streamSub?.cancel();
    for (final StreamSubscription<Object?> s in entry.subs) {
      s.cancel();
    }
  }

  Timer _armIdleTimer(String key) {
    return Timer(_opts.idleTimeout, () {
      final _ClientEntry? entry = _clients[key];
      if (entry == null) return;
      entry.socket.close();
      _removeClient(key);
    });
  }

  void _emitError(Object err) {
    if (_onError.isClosed) return;
    _onError.add(err);
  }

  String _udpKey(String sIp, int sPort, String lIp, int lPort) =>
      'udp:$sIp:$sPort:$lIp:$lPort';

  InternetAddress _bindAddr(String s) {
    if (s == '0.0.0.0') return InternetAddress.anyIPv4;
    if (s == '::') return InternetAddress.anyIPv6;
    return InternetAddress(s);
  }
}

/* ============================== Supporting types =========================== */

class _Listener {
  _Listener({required this.transport, required this.close});
  final ServerTransport transport;
  final Future<void> Function() close;
}

class _ClientEntry {
  _ClientEntry({required this.socket, required this.key});
  final TurnSocket socket;
  final String key;
  Timer? idleTimer;
  // ignore: cancel_subscriptions - cancelled in TurnServer._removeClient
  StreamSubscription<Uint8List>? streamSub;
  final List<StreamSubscription<Object?>> subs =
      <StreamSubscription<Object?>>[];
}

class AllocateServerEvent {
  const AllocateServerEvent({required this.socket, required this.allocation});
  final TurnSocket socket;
  final Allocation allocation;
}

class RelayedServerEvent {
  const RelayedServerEvent({required this.socket, required this.info});
  final TurnSocket socket;
  final RelayedInfo info;
}

/* ============================== createServer =============================== */

/// Convenience constructor mirroring the JS `createServer`.
TurnServer createServer(TurnServerOptions options) => TurnServer(options);
