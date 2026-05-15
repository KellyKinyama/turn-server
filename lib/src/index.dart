// Top-level convenience APIs — type-safe Dart port of `index.js`.
//
// Provides:
//   - resolveServer(uri)  → DNS SRV + A/AAAA lookup for STUN/TURN URIs
//   - connect(uri, ...)   → convenience TURN-client factory
//   - getPublicIP(...)    → STUN BINDING to discover public IP/port
//   - detectNAT(...)      → RFC 5780 NAT-type classification

import 'dart:async';
import 'dart:io';

import 'session.dart' show AuthMechanism;
import 'socket.dart';
import 'wire.dart' as wire;

/* ============================ resolveServer =============================== */

/// Outcome of [resolveServer] — a fully-resolved STUN/TURN endpoint.
class ResolvedStunServer {
  const ResolvedStunServer({
    required this.scheme,
    required this.host,
    required this.port,
    required this.transport,
    required this.secure,
    required this.isTurn,
  });

  /// `stun` | `stuns` | `turn` | `turns`
  final String scheme;
  final String host; // resolved IP literal when DNS succeeded
  final int port;
  final String transport; // 'udp' | 'tcp' | 'tls'
  final bool secure;
  final bool isTurn;
}

/// Resolve a STUN/TURN URI to a concrete host:port.
///
/// 1. Parse the URI with [wire.parseUri]
/// 2. If the host is already an IP literal, return as-is
/// 3. Otherwise look up a DNS SRV record (`_stun._udp.<host>`,
///    `_turn._tcp.<host>`, etc.) — the highest-priority/weight result
///    overrides host+port
/// 4. Resolve A/AAAA for the (possibly SRV-overridden) host
///
/// Throws [ArgumentError] if the URI cannot be parsed.
Future<ResolvedStunServer> resolveServer(String uri) async {
  final wire.StunUri? parsed = wire.parseUri(uri);
  if (parsed == null) {
    throw ArgumentError.value(uri, 'uri', 'Invalid STUN/TURN URI');
  }

  String host = parsed.host;
  final int port = parsed.port;

  final bool isIpLiteral = _isIpLiteral(host);
  if (!isIpLiteral) {
    // SRV lookup. Dart core has no resolveSrv; we attempt only the
    // direct A/AAAA lookup. (The Node port did SRV via dns.resolveSrv
    // — Dart users who need SRV can resolve externally and pass the
    // resolved host directly.)
    try {
      final List<InternetAddress> addrs = await InternetAddress.lookup(host);
      if (addrs.isNotEmpty) host = addrs.first.address;
    } catch (_) {/* leave host unresolved */}
  }

  return ResolvedStunServer(
    scheme: parsed.scheme,
    host: host,
    port: port,
    transport: parsed.transport,
    secure: parsed.secure,
    isTurn: parsed.isTurn,
  );
}

/* ============================== connect =================================== */

/// Convenience options for [connect].
class ConnectOptions {
  const ConnectOptions({
    this.username,
    this.password,
    this.software,
    this.serverName,
    this.rejectUnauthorized = true,
    this.context,
    this.transport,
    this.autoRefresh = true,
    this.timeout = const Duration(seconds: 10),
  });
  final String? username;
  final String? password;
  final String? software;
  final String? serverName;
  final bool rejectUnauthorized;
  final SecurityContext? context;

  /// Override the transport when not embedded in the URI (defaults to UDP
  /// for `turn:`, TLS for `turns:`).
  final String? transport;

  /// If true, the underlying [Session] auto-refreshes the allocation
  /// before its lifetime expires.
  final bool autoRefresh;

  /// Hard cap on the connect attempt.
  final Duration timeout;
}

/// Connect to a TURN server given a STUN/TURN URI. Returns a connected
/// [TurnSocket]. The caller is responsible for calling [TurnSocket.close].
///
/// * [uri] — `turn:host:port`, `turns:host:port?transport=tcp`, etc.
Future<TurnSocket> connect(
  String uri, [
  ConnectOptions options = const ConnectOptions(),
]) async {
  final ResolvedStunServer resolved = await resolveServer(uri);

  final TransportType transport = _parseTransport(
    resolved.secure ? 'tls' : (options.transport ?? resolved.transport),
  );

  final TurnSocket sock = TurnSocket(TurnSocketOptions(
    isServer: false,
    serverHost: resolved.host,
    serverPort: resolved.port,
    transportType: transport,
    username: options.username,
    password: options.password,
    authMech: (options.username != null && options.password != null)
        ? AuthMechanism.longTerm
        : AuthMechanism.none,
    software: options.software,
    serverName: options.serverName ?? resolved.host,
    rejectUnauthorized: options.rejectUnauthorized,
    context: options.context,
  ));

  try {
    await sock.connect().timeout(options.timeout);
  } catch (e) {
    await sock.close();
    rethrow;
  }

  if (options.autoRefresh) {
    sock.session.enableAutoRefresh();
  }

  return sock;
}

/* ============================== getPublicIP =============================== */

/// Result of a [getPublicIP] probe.
class PublicAddress {
  const PublicAddress(
      {required this.ip, required this.port, required this.family});
  final String ip;
  final int port;

  /// `4` for IPv4, `6` for IPv6.
  final int family;
}

/// Discover the public-facing IP/port by sending a STUN BINDING request
/// to [server] (default `stun:stun.l.google.com:19302`).
///
/// Returns `null` if the server's response carried no MAPPED-ADDRESS.
/// Throws [TimeoutException] on no response within [timeout].
Future<PublicAddress?> getPublicIP({
  String server = 'stun:stun.l.google.com:19302',
  Duration timeout = const Duration(seconds: 5),
}) async {
  final ResolvedStunServer resolved = await resolveServer(server);

  final TurnSocket sock = TurnSocket(TurnSocketOptions(
    isServer: false,
    serverHost: resolved.host,
    serverPort: resolved.port,
    transportType: _parseTransport(resolved.transport),
  ));

  final Completer<PublicAddress?> completer = Completer<PublicAddress?>();

  void finishOk(PublicAddress? p) {
    if (!completer.isCompleted) completer.complete(p);
  }

  void finishErr(Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  }

  final StreamSubscription<wire.StunMessage> okSub =
      sock.session.onSuccess.listen((wire.StunMessage msg) {
    if (msg.method != wire.StunMethod.binding) return;
    final wire.StunAddress? mapped =
        msg.getAddress(wire.Attr.xorMappedAddress) ??
            msg.getAddress(wire.Attr.mappedAddress);
    finishOk(mapped == null
        ? null
        : PublicAddress(
            ip: mapped.ip,
            port: mapped.port,
            family: mapped.family == wire.AddressFamily.ipv6 ? 6 : 4,
          ));
  });

  final StreamSubscription<void> tSub = sock.session.onTimeout
      .listen((_) => finishErr(TimeoutException('STUN binding timeout')));

  final StreamSubscription<Object> errSub = sock.onError.listen(finishErr);

  try {
    await sock.connect();
    sock.session.binding();
    return await completer.future.timeout(timeout);
  } finally {
    await okSub.cancel();
    await tSub.cancel();
    await errSub.cancel();
    await sock.close();
  }
}

/* ============================== detectNAT ================================ */

/// NAT classification produced by [detectNAT].
///
/// Values follow the legacy "RFC 3489 cone-NAT" taxonomy that the JS
/// implementation uses. RFC 5780 itself avoids these names — for a
/// strict reading of behavior categories, inspect [NatDetectionResult]'s
/// raw fields directly.
enum NatType {
  unknown,
  blocked,
  openInternet,
  fullCone,
  restrictedCone,
  symmetricOrPortRestricted,
  serverIncomplete,
  timeout,
}

/// Result of a [detectNAT] probe.
class NatDetectionResult {
  const NatDetectionResult({
    required this.type,
    required this.mappedAddress,
    required this.otherAddress,
  });
  final NatType type;
  final wire.StunAddress? mappedAddress;
  final wire.StunAddress? otherAddress;
}

/// Classify the local NAT by running an RFC 5780-style probe sequence
/// against [server] (which MUST be a multi-address STUN server, i.e. one
/// that returns OTHER-ADDRESS).
///
/// Sequence:
///   1. BINDING (no flags) — observe MAPPED + OTHER
///   2. BINDING + CHANGE-REQUEST(change-ip + change-port) — full cone if reply
///   3. On timeout, BINDING + CHANGE-REQUEST(change-port) — restricted cone if reply
///   4. Otherwise: symmetric / port-restricted / blocked
Future<NatDetectionResult> detectNAT({
  String server = 'stun:stun.l.google.com:19302',
  Duration timeout = const Duration(seconds: 10),
  Duration stepTimeout = const Duration(seconds: 2),
}) async {
  final ResolvedStunServer resolved = await resolveServer(server);

  final TurnSocket sock = TurnSocket(TurnSocketOptions(
    isServer: false,
    serverHost: resolved.host,
    serverPort: resolved.port,
    transportType: TransportType.udp,
  ));

  wire.StunAddress? mapped;
  wire.StunAddress? other;
  int step = 0;
  final Completer<NatDetectionResult> done = Completer<NatDetectionResult>();
  Timer? stepTimer;

  void finish(NatType t) {
    if (done.isCompleted) return;
    stepTimer?.cancel();
    done.complete(NatDetectionResult(
      type: t,
      mappedAddress: mapped,
      otherAddress: other,
    ));
  }

  late final void Function() onStepTimeout;
  late final Future<void> Function(int) sendStep;

  sendStep = (int newStep) async {
    step = newStep;
    stepTimer?.cancel();
    stepTimer = Timer(stepTimeout, onStepTimeout);

    final List<wire.StunAttribute> attrs = <wire.StunAttribute>[];
    if (newStep == 1) {
      attrs.add(wire.StunAttribute(
        type: wire.Attr.changeRequest,
        value: const wire.ChangeRequestValue(changeIp: true, changePort: true),
      ));
    } else if (newStep == 2) {
      attrs.add(wire.StunAttribute(
        type: wire.Attr.changeRequest,
        value: const wire.ChangeRequestValue(changeIp: false, changePort: true),
      ));
    }
    sock.session.binding(attributes: attrs);
  };

  onStepTimeout = () {
    if (done.isCompleted) return;
    if (step == 1) {
      sendStep(2);
    } else if (step == 2) {
      finish(NatType.symmetricOrPortRestricted);
    } else {
      finish(NatType.blocked);
    }
  };

  final StreamSubscription<wire.StunMessage> okSub =
      sock.session.onSuccess.listen((wire.StunMessage msg) {
    if (msg.method != wire.StunMethod.binding) return;
    final wire.StunAddress? m = msg.getAddress(wire.Attr.xorMappedAddress) ??
        msg.getAddress(wire.Attr.mappedAddress);
    final wire.StunAddress? o = msg.getAddress(wire.Attr.otherAddress);

    if (step == 0) {
      mapped = m;
      other = o;
      if (o == null) {
        finish(NatType.serverIncomplete);
        return;
      }
      sendStep(1);
    } else if (step == 1) {
      finish(NatType.fullCone);
    } else if (step == 2) {
      finish(NatType.restrictedCone);
    }
  });

  final StreamSubscription<void> tSub = sock.session.onTimeout.listen((_) {
    onStepTimeout();
  });

  Timer? overall;
  try {
    await sock.connect();
    sock.session.binding();
    stepTimer = Timer(stepTimeout, onStepTimeout);
    overall = Timer(timeout, () => finish(NatType.timeout));
    return await done.future;
  } finally {
    overall?.cancel();
    stepTimer?.cancel();
    await okSub.cancel();
    await tSub.cancel();
    await sock.close();
  }
}

/* ============================== Helpers =================================== */

bool _isIpLiteral(String host) {
  if (host.contains(':')) return true; // IPv6
  return RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(host);
}

TransportType _parseTransport(String t) {
  switch (t.toLowerCase()) {
    case 'tcp':
      return TransportType.tcp;
    case 'tls':
      return TransportType.tls;
    case 'udp':
    default:
      return TransportType.udp;
  }
}
