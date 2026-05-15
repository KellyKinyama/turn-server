// Protocol state machine — type-safe Dart port of `src/session.js`.
//
// `Session` implements the full STUN/TURN message-processing state machine
// for both client and server roles. It is purely an in-memory protocol
// engine: I/O is delegated to a transport layer (see `socket.dart`) which
// feeds raw bytes into [Session.message] and listens to [Session.onMessage]
// for outgoing bytes.
//
// Event model: where the JS uses `EventEmitter`, the Dart port exposes a
// typed [Stream] per event. Synchronous "hooks" (JS pattern: caller emits
// and listener calls `cb(true/false)` synchronously) are represented as
// nullable callback fields on [Session] — set them once, return `true` to
// allow / `false` to deny.
//
// Spec references: RFC 5389 / 8489 (STUN-bis), RFC 5766 / 8656 (TURN-bis),
// RFC 6062 (TCP relay), RFC 5780 (NAT detection), RFC 7635 (OAuth),
// RFC 6156 (IPv6 allocation).

import 'dart:async';
import 'dart:convert' show base64, utf8;
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'wire.dart' as wire;

/* =============================== Public types ============================= */

/// Authentication mechanisms supported by the server.
enum AuthMechanism { none, shortTerm, longTerm, oauth }

/// Session lifecycle state.
enum SessionState { fresh, ready, closed }

/// Direction tag for relay info events.
enum RelayDirection { inbound, outbound }

/// Async key-lookup callback: return the HMAC key (long-term: 16 bytes
/// MD5 / 32 bytes SHA-256), the password as a [String] (which will be
/// hashed with the active realm), or `null` to reject.
typedef AuthenticateHandler = FutureOr<Object?> Function(
    String username, String? realm);

/// OAuth ACCESS-TOKEN validator. Return the derived HMAC key, or `null`
/// to reject (401).
typedef OauthHandler = FutureOr<Uint8List?> Function(
    Uint8List token, String? realm);

/// Synchronous hook used by `before*` predicates. Return `true` to allow.
typedef Hook<T> = bool Function(T info);

/// Synchronous quota check.
typedef QuotaHook = bool Function(String? username);

/// Async hook used by Socket layer to actually open a TCP peer connection.
/// Resolve the future with `null` on success, an error otherwise.
typedef ConnectPeerHandler = FutureOr<Object?> Function(
    int connectionId, wire.StunAddress peer);

/// Async hook used by Socket layer to bind an inbound TCP stream to an
/// existing peer connection (RFC 6062 ConnectionBind).
typedef ConnectionBindHandler = FutureOr<Object?> Function(
    int connectionId, wire.StunAddress peer);

/// REFRESH lifetime info — hook may mutate [lifetime] before the call returns.
class RefreshInfo {
  RefreshInfo({
    required this.username,
    required this.source,
    required this.currentLifetime,
    required this.lifetime,
  });
  final String? username;
  final wire.StunAddress? source;
  final int currentLifetime;
  int lifetime; // mutable — hook can adjust
}

/// ALLOCATE info — hook may adjust [lifetime] before the call returns.
class AllocateInfo {
  AllocateInfo({
    required this.username,
    required this.source,
    required this.transport,
    required this.lifetime,
    required this.requestedFamily,
    required this.evenPort,
    required this.reservationToken,
    required this.dontFragment,
  });
  final String? username;
  final wire.StunAddress? source;
  final int transport;
  int lifetime;
  final int? requestedFamily;
  final bool? evenPort;
  final Uint8List? reservationToken;
  final bool dontFragment;
}

class PermissionInfo {
  const PermissionInfo({
    required this.username,
    required this.source,
    required this.peer,
  });
  final String? username;
  final wire.StunAddress? source;
  final wire.StunAddress peer;
}

class ChannelBindInfo {
  const ChannelBindInfo({
    required this.username,
    required this.source,
    required this.channel,
    required this.peer,
  });
  final String? username;
  final wire.StunAddress? source;
  final int channel;
  final wire.StunAddress peer;
}

class RelayInfo {
  const RelayInfo({
    required this.username,
    required this.source,
    required this.peer,
    required this.size,
    required this.direction,
    this.channel,
  });
  final String? username;
  final wire.StunAddress? source;
  final wire.StunAddress peer;
  final int size;
  final RelayDirection direction;
  final int? channel;
}

class ConnectInfo {
  const ConnectInfo({
    required this.username,
    required this.source,
    required this.peer,
  });
  final String? username;
  final wire.StunAddress? source;
  final wire.StunAddress peer;
}

class AuthorizeInfo {
  const AuthorizeInfo({
    required this.method,
    required this.methodName,
    required this.username,
    required this.source,
  });
  final int method;
  final String? methodName;
  final String? username;
  final wire.StunAddress? source;
}

class BeforeDataInfo {
  const BeforeDataInfo({
    required this.peer,
    required this.source,
    required this.username,
    required this.size,
    required this.direction,
  });
  final wire.StunAddress peer;
  final wire.StunAddress? source;
  final String? username;
  final int size;
  final RelayDirection direction;
}

/// Permission entry held by an [Allocation].
class Permission {
  Permission({required this.ip, required this.expiresAt});
  final String ip;
  int expiresAt; // ms-since-epoch
}

/// Channel binding entry held by an [Allocation].
class Channel {
  Channel({required this.peer, required this.expiresAt});
  final wire.StunAddress peer;
  int expiresAt; // ms-since-epoch
}

/// One TURN allocation per session (5-tuple).
class Allocation {
  Allocation({
    required this.relayAddress,
    required this.lifetime,
    required this.expiresAt,
    required this.transport,
    this.username,
  });

  wire.StunAddress relayAddress;
  int lifetime; // seconds
  int expiresAt; // ms-since-epoch
  final int transport; // wire.TransportProtocol.udp / .tcp
  final String? username;

  final Map<String, Permission> permissions = <String, Permission>{};
  final Map<int, Channel> channels = <int, Channel>{};
  final Map<String, int> _peerToChannel = <String, int>{};

  // ALLOCATE-time flags (set by Session, consumed by Socket).
  bool? evenPort;
  Uint8List? reservationToken;
  bool dontFragment = false;
  int? requestedFamily;
  int? additionalFamily;

  // Lifecycle timer; set by Session.
  Timer? timer;

  // Deferred-response coordination with the Socket layer.
  /// External handler claims responsibility for confirming the response
  /// (must be set synchronously inside an [Session.onAllocate] listener).
  bool confirmed = false;
  bool _responseSent = false;
  void Function(wire.StunAddress)? confirm;
  void Function(Object error)? reject;
}

/// Snapshot of cumulative bandwidth counters.
class BandwidthCounters {
  const BandwidthCounters({required this.bytesIn, required this.bytesOut});
  final int bytesIn;
  final int bytesOut;
}

/// Successful response payload — a decoded [wire.StunMessage].
typedef SuccessEvent = wire.StunMessage;

class ErrorResponseEvent {
  const ErrorResponseEvent(this.message, this.error);
  final wire.StunMessage message;
  final wire.StunErrorCode? error;
}

class DataEvent {
  const DataEvent({required this.peer, required this.data, this.channel});
  final wire.StunAddress peer;
  final Uint8List data;
  final int? channel;
}

class RedirectEvent {
  const RedirectEvent({this.server, this.domain});
  final wire.StunAddress? server;
  final String? domain;
}

class ChangeRequestEvent {
  ChangeRequestEvent({
    required this.message,
    required this.change,
    required this.responseAttributes,
  });
  final wire.StunMessage message;
  final wire.ChangeRequestValue change;
  final List<wire.StunAttribute> responseAttributes;
}

class _PendingRequest {
  _PendingRequest({required this.method, required this.attributes});
  final int method;
  final List<wire.StunAttribute> attributes;
  int retries = 0;
}

/* ================================ Options ================================ */

class SessionOptions {
  SessionOptions({
    this.isServer = false,
    this.software,
    this.authMech = AuthMechanism.none,
    this.realm,
    this.nonce,
    this.nonceExpiry = const Duration(minutes: 10),
    this.thirdPartyAuthUrl,
    this.useFingerprint = true,
    this.secret,
    this.restCredentialExpirySeconds = 86400,
    this.credentials = const <String, String>{},
    this.username,
    this.password,
    this.rto,
    this.passwordAlgorithm,
    this.source,
    this.localAddress,
    this.relayIp,
    this.externalIp,
    this.portRange = const <int>[49152, 65535],
    this.maxAllocateLifetime = 3600,
    this.defaultAllocateLifetime = 600,
    this.secondaryAddress,
    this.allowLoopback = false,
    this.allowMulticast = false,
    this.secureStun = false,
    this.checkOriginConsistency = false,
    this.tcpTimeout = const Duration(milliseconds: 39500),
  });

  final bool isServer;
  final String? software;
  final AuthMechanism authMech;
  String? realm;
  String? nonce;
  final Duration nonceExpiry;
  final String? thirdPartyAuthUrl;
  final bool useFingerprint;
  final String? secret;
  final int restCredentialExpirySeconds;
  final Map<String, String> credentials;
  final String? username;
  final String? password;
  final Duration? rto;
  final int? passwordAlgorithm;
  final wire.StunAddress? source;
  final wire.StunAddress? localAddress;
  final String? relayIp;
  final String? externalIp;
  final List<int> portRange;
  final int maxAllocateLifetime;
  final int defaultAllocateLifetime;
  final wire.StunAddress? secondaryAddress;
  final bool allowLoopback;
  final bool allowMulticast;
  final bool secureStun;
  final bool checkOriginConsistency;
  final Duration tcpTimeout;
}

/* =================================== Session ============================== */

class Session {
  Session(SessionOptions options) : _opts = options {
    _isServer = options.isServer;
    _useFingerprint = options.useFingerprint;
    _state = SessionState.fresh;
    _credentials = Map<String, String>.of(options.credentials);
    _realm = options.realm;
    _nonce = options.nonce;
    _username = options.username;
    _password = options.password;
    _passwordAlgorithm = options.passwordAlgorithm;
    _source = options.source;
    _localAddress = options.localAddress;
    _secondaryAddress = options.secondaryAddress;
    _rng.nextInt(1 << 30); // warm
  }

  final SessionOptions _opts;

  /* ---------- Mutable state ---------- */

  late bool _isServer;
  late SessionState _state;
  late bool _useFingerprint;

  String? _realm;
  String? _nonce;
  DateTime? _nonceCreatedAt;
  late Map<String, String> _credentials;
  String? _username;
  String? _password;
  int? _passwordAlgorithm;

  wire.StunAddress? _source;
  wire.StunAddress? _localAddress;
  wire.StunAddress? _secondaryAddress;

  String? _sessionOrigin;

  int _bytesIn = 0;
  int _bytesOut = 0;

  Allocation? _allocation;

  // RFC 6062 — TCP relay state held inside the session.
  final Map<int, _TcpConnState> _tcpConnections = <int, _TcpConnState>{};
  int _nextConnectionId = 1;

  // Retransmission detection (server side).
  Uint8List? _lastTransactionId;
  Uint8List? _lastResponse;

  // Client request tracking.
  _PendingRequest? _pendingRequest;
  Uint8List? _pendingTransactionId;

  // Cached client key.
  Uint8List? _clientKey;
  String? _clientKeyInputs;

  // Retransmission timers.
  Timer? _rtoTimer;
  int _rtoAttempt = 0;
  Uint8List? _rtoLastBuf;
  static const int _rtoMaxRetries = 7;

  // Auto-refresh timers.
  Timer? _refreshTimer;
  final Map<String, Timer> _permissionTimers = <String, Timer>{};
  final Map<int, Timer> _channelTimers = <int, Timer>{};
  bool _autoRefresh = false;

  // Nonce HMAC key (per-session, random).
  final Uint8List _nonceKey = _randomBytes(16);

  static final math.Random _rng = math.Random.secure();

  /* ---------- Hooks (synchronous predicates) ---------- */

  Hook<AllocateInfo>? beforeAllocate;
  Hook<RefreshInfo>? beforeRefresh;
  Hook<PermissionInfo>? beforePermission;
  Hook<ChannelBindInfo>? beforeChannelBind;
  Hook<RelayInfo>? beforeRelay;
  Hook<ConnectInfo>? beforeConnect;
  Hook<AuthorizeInfo>? authorize;
  Hook<BeforeDataInfo>? beforeData;
  QuotaHook? quotaHook;

  /// Async lookup for long-term/short-term credentials.
  AuthenticateHandler? authenticateHandler;

  /// OAuth ACCESS-TOKEN validator.
  OauthHandler? oauthHandler;

  /// Socket-layer plumbing for TCP relay.
  ConnectPeerHandler? connectPeerHandler;
  ConnectionBindHandler? connectionBindHandler;

  /* ---------- Event sinks ---------- */

  final StreamController<Uint8List> _onMessage =
      StreamController<Uint8List>.broadcast();
  final StreamController<wire.StunMessage> _onRaw =
      StreamController<wire.StunMessage>.broadcast();
  final StreamController<wire.StunMessage> _onSuccess =
      StreamController<wire.StunMessage>.broadcast();
  final StreamController<ErrorResponseEvent> _onErrorResponse =
      StreamController<ErrorResponseEvent>.broadcast();
  final StreamController<DataEvent> _onData =
      StreamController<DataEvent>.broadcast();
  final StreamController<RelayEvent> _onRelay =
      StreamController<RelayEvent>.broadcast();
  final StreamController<Allocation> _onAllocate =
      StreamController<Allocation>.broadcast(sync: true);
  final StreamController<Allocation> _onAllocateExpired =
      StreamController<Allocation>.broadcast();
  final StreamController<Allocation> _onRefresh =
      StreamController<Allocation>.broadcast();
  final StreamController<PermissionEvent> _onPermission =
      StreamController<PermissionEvent>.broadcast();
  final StreamController<ChannelEvent> _onChannel =
      StreamController<ChannelEvent>.broadcast();
  final StreamController<ChangeRequestEvent> _onChangeRequest =
      StreamController<ChangeRequestEvent>.broadcast();
  final StreamController<RedirectEvent> _onRedirect =
      StreamController<RedirectEvent>.broadcast();
  final StreamController<void> _onTimeout = StreamController<void>.broadcast();
  final StreamController<void> _onClose = StreamController<void>.broadcast();
  final StreamController<Object> _onError =
      StreamController<Object>.broadcast();

  /// Outgoing on-wire bytes — Socket layer subscribes and sends.
  Stream<Uint8List> get onMessage => _onMessage.stream;

  /// Decoded message about to be processed (post-validation).
  Stream<wire.StunMessage> get onRaw => _onRaw.stream;

  /// Client-side success response.
  Stream<wire.StunMessage> get onSuccess => _onSuccess.stream;

  /// Client-side error response (with parsed ERROR-CODE).
  Stream<ErrorResponseEvent> get onErrorResponse => _onErrorResponse.stream;

  /// Inbound relay data — `peer` is the remote peer; `data` is the payload.
  Stream<DataEvent> get onData => _onData.stream;

  /// Server-side: client sent a Send indication or ChannelData. Socket layer
  /// subscribes and forwards bytes to the peer.
  Stream<RelayEvent> get onRelay => _onRelay.stream;

  /// New allocation created (server side).
  Stream<Allocation> get onAllocate => _onAllocate.stream;

  /// Allocation expired or was deleted.
  Stream<Allocation> get onAllocateExpired => _onAllocateExpired.stream;

  Stream<Allocation> get onRefresh => _onRefresh.stream;
  Stream<PermissionEvent> get onPermission => _onPermission.stream;
  Stream<ChannelEvent> get onChannel => _onChannel.stream;
  Stream<ChangeRequestEvent> get onChangeRequest => _onChangeRequest.stream;
  Stream<RedirectEvent> get onRedirect => _onRedirect.stream;

  /// Client-side: request transaction timed out (no response).
  Stream<void> get onTimeout => _onTimeout.stream;

  Stream<void> get onClose => _onClose.stream;
  Stream<Object> get onError => _onError.stream;

  /* ---------- Public surface ---------- */

  bool get isServer => _isServer;
  SessionState get state => _state;
  Allocation? get allocation => _allocation;
  wire.StunAddress? get source => _source;
  wire.StunAddress? get localAddress => _localAddress;
  BandwidthCounters get bandwidth =>
      BandwidthCounters(bytesIn: _bytesIn, bytesOut: _bytesOut);

  /// Add a static credential (long-term username → password).
  void addUser(String username, String password) {
    _credentials[username] = password;
  }

  /// Remove a static credential.
  void removeUser(String username) {
    _credentials.remove(username);
  }

  /// Update mutable session context. Mirrors JS `set_context`.
  void updateContext({
    wire.StunAddress? source,
    String? realm,
    String? nonce,
    String? username,
    String? password,
    Map<String, String>? credentials,
    wire.StunAddress? relayAddress,
  }) {
    if (source != null) _source = source;
    if (realm != null) _realm = realm;
    if (nonce != null) _nonce = nonce;
    if (username != null) _username = username;
    if (password != null) {
      _password = password;
      _clientKeyInputs = null;
    }
    if (credentials != null) {
      _credentials = Map<String, String>.of(credentials);
    }
    if (relayAddress != null && _allocation != null) {
      _allocation!.relayAddress = relayAddress;
    }
  }

  /// Feed raw incoming bytes (one STUN message or one ChannelData frame).
  void message(Uint8List data) => _processIncoming(data);

  /// Close the session. Idempotent.
  void close() {
    if (_state == SessionState.closed) return;
    _stopRetransmission();
    _clearRefreshTimers();
    if (_allocation != null) _expireAllocation();
    _state = SessionState.closed;
    _onClose.add(null);

    _onMessage.close();
    _onRaw.close();
    _onSuccess.close();
    _onErrorResponse.close();
    _onData.close();
    _onRelay.close();
    _onAllocate.close();
    _onAllocateExpired.close();
    _onRefresh.close();
    _onPermission.close();
    _onChannel.close();
    _onChangeRequest.close();
    _onRedirect.close();
    _onTimeout.close();
    _onClose.close();
    _onError.close();
  }

  /// Server-side: send a DATA indication to the client.
  void sendData(wire.StunAddress peer, Uint8List data) {
    _sendIndication(wire.StunMethod.data, <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: peer),
      wire.StunAttribute(type: wire.Attr.data, value: data),
    ]);
  }

  /// Server-side: send a ChannelData frame to the client.
  void sendChannelData(int channelNumber, Uint8List data) {
    _onMessage.add(wire.encodeChannelData(channelNumber, data));
  }

  bool hasPermission(String ip) => _hasPermission(ip);

  wire.StunAddress? getPeerByChannel(int channelNumber) =>
      _getPeerByChannel(channelNumber);

  int? getChannelByPeer(String ip, int port) => _getChannelByPeer(ip, port);

  bool isBlockedPeer(String ip) => _isBlockedPeer(ip);

  /// Send 300 Try Alternate to redirect the client.
  void redirect(wire.StunMessage msg, wire.StunAddress alternateServer) {
    _sendError(
        msg,
        300,
        <wire.StunAttribute>[
          wire.StunAttribute(
              type: wire.Attr.errorCode,
              value: const wire.StunErrorCode(code: 300)),
          wire.StunAttribute(
              type: wire.Attr.alternateServer, value: alternateServer),
        ],
        null);
  }

  /* ---------- Client-side request helpers ---------- */

  /// Send a Binding request.
  Uint8List binding({List<wire.StunAttribute>? attributes}) =>
      _sendClientRequest(
          wire.StunMethod.binding, attributes ?? <wire.StunAttribute>[]);

  /// Send an ALLOCATE request.
  Uint8List allocate({
    int transport = wire.TransportProtocol.udp,
    int? lifetime,
    bool dontFragment = false,
  }) {
    final List<wire.StunAttribute> a = <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.requestedTransport, value: transport),
      if (lifetime != null)
        wire.StunAttribute(type: wire.Attr.lifetime, value: lifetime),
      if (dontFragment)
        wire.StunAttribute(type: wire.Attr.dontFragment, value: true),
    ];
    return _sendClientRequest(wire.StunMethod.allocate, a);
  }

  Uint8List refresh([int? lifetime]) {
    final List<wire.StunAttribute> a = <wire.StunAttribute>[
      if (lifetime != null)
        wire.StunAttribute(type: wire.Attr.lifetime, value: lifetime),
    ];
    return _sendClientRequest(wire.StunMethod.refresh, a);
  }

  Uint8List createPermission(List<wire.StunAddress> peers) {
    final List<wire.StunAttribute> a = <wire.StunAttribute>[
      for (final wire.StunAddress p in peers)
        wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: p),
    ];
    return _sendClientRequest(wire.StunMethod.createPermission, a);
  }

  Uint8List channelBind(int channelNumber, wire.StunAddress peer) {
    return _sendClientRequest(wire.StunMethod.channelBind, <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.channelNumber, value: channelNumber),
      wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: peer),
    ]);
  }

  /// Send a SEND indication.
  void sendToPeer(wire.StunAddress peer, Uint8List data) {
    _sendIndication(wire.StunMethod.send, <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: peer),
      wire.StunAttribute(type: wire.Attr.data, value: data),
    ]);
  }

  Uint8List connect(wire.StunAddress peer) =>
      _sendClientRequest(wire.StunMethod.connect, <wire.StunAttribute>[
        wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: peer),
      ]);

  Uint8List connectionBind(int connectionId) =>
      _sendClientRequest(wire.StunMethod.connectionBind, <wire.StunAttribute>[
        wire.StunAttribute(type: wire.Attr.connectionId, value: connectionId),
      ]);

  void enableAutoRefresh() {
    _autoRefresh = true;
  }

  /* ============================== Internals ============================== */

  /* ---------- Hook helper ---------- */

  bool _runHook<T>(Hook<T>? hook, T info) {
    if (hook == null) return true;
    try {
      return hook(info);
    } catch (e) {
      _emitError(e);
      return false;
    }
  }

  void _emitError(Object e) {
    if (!_onError.isClosed) _onError.add(e);
  }

  /* ---------- Nonce management (RFC 8489 §9.2) ---------- */

  String _nonceScope() =>
      _source == null ? '' : '${_source!.ip}:${_source!.port}';

  String _generateNonce() {
    final String timestamp =
        (DateTime.now().millisecondsSinceEpoch ~/ 1000).toRadixString(16);
    final List<int> mac = crypto.Hmac(crypto.sha1, _nonceKey)
        .convert(utf8.encode(timestamp + _nonceScope()))
        .bytes;
    final String macHex =
        mac.take(8).map((int b) => b.toRadixString(16).padLeft(2, '0')).join();
    final String nonce = '$timestamp:$macHex';
    _nonce = nonce;
    _nonceCreatedAt = DateTime.now();
    return nonce;
  }

  bool _isNonceStale() {
    if (_nonceCreatedAt == null) return true;
    return DateTime.now().difference(_nonceCreatedAt!) > _opts.nonceExpiry;
  }

  bool _validateNonce(String? nonce) {
    if (nonce == null || !nonce.contains(':')) return false;
    final List<String> parts = nonce.split(':');
    if (parts.length < 2) return false;
    final String timestamp = parts[0];
    final String mac = parts[1];
    final List<int> expected = crypto.Hmac(crypto.sha1, _nonceKey)
        .convert(utf8.encode(timestamp + _nonceScope()))
        .bytes;
    final String expectedHex = expected
        .take(8)
        .map((int b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    if (mac != expectedHex) return false;
    final int? ts = int.tryParse(timestamp, radix: 16);
    if (ts == null) return false;
    final int ageMs = DateTime.now().millisecondsSinceEpoch - ts * 1000;
    return ageMs <= _opts.nonceExpiry.inMilliseconds;
  }

  /* ---------- Auth key lookup ---------- */

  Future<Uint8List?> _getKeyForUser(String username) async {
    // 1. Static credentials.
    final String? staticPw = _credentials[username];
    if (staticPw != null && _realm != null) {
      return wire.computeLongTermKey(username, _realm!, staticPw);
    }

    // 2. REST API credentials (timestamp:userId / HMAC(secret, username)).
    if (_opts.secret != null) {
      final List<String> parts = username.split(':');
      if (parts.length >= 2) {
        final int? ts = int.tryParse(parts[0]);
        if (ts != null &&
            ts > 0 &&
            ts < DateTime.now().millisecondsSinceEpoch ~/ 1000) {
          return null; // expired
        }
      }
      final List<int> hmacBytes =
          crypto.Hmac(crypto.sha1, utf8.encode(_opts.secret!))
              .convert(utf8.encode(username))
              .bytes;
      final String password = base64.encode(hmacBytes);
      if (_realm == null) return null;
      return wire.computeLongTermKey(username, _realm!, password);
    }

    // 3. Dynamic lookup via handler.
    final AuthenticateHandler? h = authenticateHandler;
    if (h != null) {
      final Object? r = await h(username, _realm);
      if (r == null) return null;
      if (r is Uint8List) return r;
      if (r is String && _realm != null) {
        return wire.computeLongTermKey(username, _realm!, r);
      }
      return null;
    }
    return null;
  }

  void _sendChallenge(wire.StunMessage msg) {
    if (_nonce == null || _isNonceStale()) _generateNonce();
    final List<wire.StunAttribute> attrs = <wire.StunAttribute>[
      wire.StunAttribute(
          type: wire.Attr.errorCode,
          value: const wire.StunErrorCode(code: 401)),
      wire.StunAttribute(type: wire.Attr.realm, value: _realm),
      wire.StunAttribute(type: wire.Attr.nonce, value: _nonce),
      wire.StunAttribute(
          type: wire.Attr.passwordAlgorithms,
          value: <wire.PasswordAlgorithm>[
            wire.PasswordAlgorithm(algorithm: wire.PasswordAlgorithm.sha256),
            wire.PasswordAlgorithm(algorithm: wire.PasswordAlgorithm.md5),
          ]),
    ];
    _sendError(msg, 401, attrs, null);
  }

  void _sendStaleNonce(wire.StunMessage msg) {
    _generateNonce();
    final List<wire.StunAttribute> attrs = <wire.StunAttribute>[
      wire.StunAttribute(
          type: wire.Attr.errorCode,
          value: const wire.StunErrorCode(code: 438)),
      wire.StunAttribute(type: wire.Attr.realm, value: _realm),
      wire.StunAttribute(type: wire.Attr.nonce, value: _nonce),
      wire.StunAttribute(
          type: wire.Attr.passwordAlgorithms,
          value: <wire.PasswordAlgorithm>[
            wire.PasswordAlgorithm(algorithm: wire.PasswordAlgorithm.sha256),
            wire.PasswordAlgorithm(algorithm: wire.PasswordAlgorithm.md5),
          ]),
    ];
    _sendError(msg, 438, attrs, null);
  }

  /* ---------- Response builders ---------- */

  void _sendMessage(int method, int cls, Uint8List tid,
      List<wire.StunAttribute> attributes, Uint8List? key) {
    final List<wire.StunAttribute> finalAttrs = _opts.software != null &&
            cls != wire.StunClass.indication
        ? <wire.StunAttribute>[
            ...attributes,
            wire.StunAttribute(type: wire.Attr.software, value: _opts.software),
          ]
        : attributes;

    final wire.EncodedMessage result = wire.encodeMessage(wire.EncodeOptions(
      method: method,
      cls: cls,
      transactionId: tid,
      attributes: finalAttrs,
      key: key,
      fingerprint: _useFingerprint,
    ));

    _lastTransactionId = tid;
    _lastResponse = result.buf;
    _onMessage.add(result.buf);
  }

  void _sendSuccess(
      wire.StunMessage msg, List<wire.StunAttribute> attrs, Uint8List? key) {
    _sendMessage(
        msg.method, wire.StunClass.success, msg.transactionId, attrs, key);
  }

  void _sendError(wire.StunMessage msg, int code,
      List<wire.StunAttribute>? attrs, Uint8List? key) {
    final List<wire.StunAttribute> a = attrs ??
        <wire.StunAttribute>[
          wire.StunAttribute(
              type: wire.Attr.errorCode, value: wire.StunErrorCode(code: code)),
        ];
    _sendMessage(msg.method, wire.StunClass.error, msg.transactionId, a, key);
  }

  void _sendIndication(int method, List<wire.StunAttribute> attrs) {
    final wire.EncodedMessage result = wire.encodeMessage(wire.EncodeOptions(
      method: method,
      cls: wire.StunClass.indication,
      attributes: attrs,
      fingerprint: false,
    ));
    _onMessage.add(result.buf);
  }

  /* ---------- Retransmission detection (server) ---------- */

  bool _isRetransmission(wire.StunMessage msg) {
    final Uint8List? a = _lastTransactionId;
    final Uint8List b = msg.transactionId;
    if (a == null || a.length != b.length) return false;
    for (int i = 0; i < 12; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /* ---------- Allocation lifecycle ---------- */

  Allocation _createAllocation(
      wire.StunMessage msg, int transport, int lifetime) {
    final int minPort = _opts.portRange[0];
    final int maxPort = _opts.portRange[1];
    final int relayPort =
        minPort + _rng.nextInt(math.max(1, maxPort - minPort));
    String relayIp = _opts.externalIp ?? _opts.relayIp ?? '0.0.0.0';
    if (relayIp == '0.0.0.0' || relayIp == '::') {
      final String? la = _localAddress?.ip;
      if (la != null &&
          la != '0.0.0.0' &&
          la != '::' &&
          !la.startsWith('127.') &&
          la != '::1') {
        relayIp = la;
      }
    }

    int lt = lifetime;
    if (lt > _opts.maxAllocateLifetime) lt = _opts.maxAllocateLifetime;
    if (lt < _opts.defaultAllocateLifetime) lt = _opts.defaultAllocateLifetime;

    final Allocation alloc = Allocation(
      relayAddress: wire.StunAddress(
        family: relayIp.contains(':')
            ? wire.AddressFamily.ipv6
            : wire.AddressFamily.ipv4,
        ip: relayIp,
        port: relayPort,
      ),
      lifetime: lt,
      expiresAt: DateTime.now().millisecondsSinceEpoch + lt * 1000,
      transport: transport,
      username: msg.getString(wire.Attr.username),
    );

    alloc.timer = Timer(Duration(seconds: lt), _expireAllocation);
    _allocation = alloc;
    _state = SessionState.ready;
    return alloc;
  }

  void _refreshAllocation(int lifetime) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return;
    alloc.timer?.cancel();
    if (lifetime == 0) {
      _expireAllocation();
      return;
    }
    int lt = lifetime;
    if (lt > _opts.maxAllocateLifetime) lt = _opts.maxAllocateLifetime;
    if (lt > 0 && lt < _opts.defaultAllocateLifetime) {
      lt = _opts.defaultAllocateLifetime;
    }
    alloc.lifetime = lt;
    alloc.expiresAt = DateTime.now().millisecondsSinceEpoch + lt * 1000;
    alloc.timer = Timer(Duration(seconds: lt), _expireAllocation);
    _onRefresh.add(alloc);
  }

  void _expireAllocation() {
    final Allocation? alloc = _allocation;
    if (alloc == null) return;
    alloc.timer?.cancel();
    _allocation = null;
    _state = SessionState.fresh;
    _onAllocateExpired.add(alloc);
  }

  /* ---------- Peer/permission/channel safety ---------- */

  bool _isBlockedPeer(String ip) {
    if (ip.isEmpty) return true;
    if (!_opts.allowLoopback) {
      if (ip == '127.0.0.1' ||
          ip.startsWith('127.') ||
          ip == '::1' ||
          ip == '0:0:0:0:0:0:0:1') {
        return true;
      }
    }
    if (ip == '0.0.0.0' ||
        ip.startsWith('0.') ||
        ip == '::' ||
        ip == '0:0:0:0:0:0:0:0') {
      return true;
    }
    if (!_opts.allowMulticast) {
      final List<String> parts = ip.split('.');
      if (parts.length == 4) {
        final int? first = int.tryParse(parts[0]);
        if (first != null && first >= 224 && first <= 255) return true;
      }
      if (ip.toLowerCase().startsWith('ff')) return true; // IPv6 multicast
    }
    return false;
  }

  bool _addPermission(String ip) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return false;
    if (_isBlockedPeer(ip)) return false;
    final int exp = DateTime.now().millisecondsSinceEpoch + 300000;
    alloc.permissions[ip] = Permission(ip: ip, expiresAt: exp);
    _onPermission.add(PermissionEvent(ip: ip, allocation: alloc));
    return true;
  }

  bool _hasPermission(String ip) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return false;
    final Permission? p = alloc.permissions[ip];
    if (p == null) return false;
    if (DateTime.now().millisecondsSinceEpoch > p.expiresAt) {
      alloc.permissions.remove(ip);
      return false;
    }
    return true;
  }

  bool _bindChannel(int channelNumber, wire.StunAddress peer) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return false;
    if (channelNumber < 0x4000 || channelNumber > 0x4FFF) return false;

    final Channel? existing = alloc.channels[channelNumber];
    if (existing != null) {
      if (existing.peer.ip != peer.ip || existing.peer.port != peer.port) {
        return false;
      }
    }
    final int? existingChannel = _getChannelByPeer(peer.ip, peer.port);
    if (existingChannel != null && existingChannel != channelNumber) {
      return false;
    }

    alloc.channels[channelNumber] = Channel(
      peer: peer,
      expiresAt: DateTime.now().millisecondsSinceEpoch + 600000,
    );
    alloc._peerToChannel['${peer.ip}:${peer.port}'] = channelNumber;
    _addPermission(peer.ip);
    _onChannel.add(
        ChannelEvent(number: channelNumber, peer: peer, allocation: alloc));
    return true;
  }

  int? _getChannelByPeer(String ip, int port) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return null;
    final String key = '$ip:$port';
    final int? chNum = alloc._peerToChannel[key];
    if (chNum == null) return null;
    final Channel? ch = alloc.channels[chNum];
    if (ch == null) {
      alloc._peerToChannel.remove(key);
      return null;
    }
    if (DateTime.now().millisecondsSinceEpoch > ch.expiresAt) {
      alloc.channels.remove(chNum);
      alloc._peerToChannel.remove(key);
      return null;
    }
    return chNum;
  }

  wire.StunAddress? _getPeerByChannel(int channelNumber) {
    final Allocation? alloc = _allocation;
    if (alloc == null) return null;
    final Channel? ch = alloc.channels[channelNumber];
    if (ch == null) return null;
    if (DateTime.now().millisecondsSinceEpoch > ch.expiresAt) {
      alloc.channels.remove(channelNumber);
      return null;
    }
    return ch.peer;
  }

  /* ---------- Incoming message dispatch ---------- */

  void _processIncoming(Uint8List data) {
    try {
      if (wire.isChannelData(data)) {
        _processChannelData(data);
        return;
      }
      if (!wire.isStun(data)) return;

      final wire.StunMessage? msg = wire.decodeMessage(data);
      if (msg == null) return;

      _onRaw.add(msg);

      if (_isRetransmission(msg) && _lastResponse != null) {
        _onMessage.add(_lastResponse!);
        return;
      }

      // FINGERPRINT validation.
      if (msg.fingerprintOffset != null) {
        final int? fpVal = msg.getInt(wire.Attr.fingerprint);
        if (fpVal == null) return;
        final Uint8List before =
            Uint8List.fromList(data.sublist(0, msg.fingerprintOffset!));
        if (wire.computeFingerprint(before) != fpVal) return;
      }

      if (_isServer) {
        _processServerMessage(msg, data);
      } else {
        _processClientMessage(msg);
      }
    } catch (e) {
      _emitError(e);
    }
  }

  void _processChannelData(Uint8List data) {
    final wire.DecodedChannelData parsed = wire.decodeChannelData(data);
    final wire.StunAddress? peer = _getPeerByChannel(parsed.channel);
    if (peer == null) return;

    if (_isServer) {
      if (!_runHook<RelayInfo>(
          beforeRelay,
          RelayInfo(
            username: _allocation?.username,
            source: _source,
            peer: peer,
            size: parsed.data.length,
            direction: RelayDirection.outbound,
            channel: parsed.channel,
          ))) {
        return;
      }
    }

    _bytesOut += parsed.data.length;
    final Uint8List copy = Uint8List.fromList(parsed.data);
    _onRelay.add(RelayEvent(peer: peer, data: copy, channel: parsed.channel));
  }

  /* ---------- Server-side processing ---------- */

  List<int> _checkUnknownComprehension(wire.StunMessage msg) {
    final List<int> unknown = <int>[];
    for (final wire.StunAttribute a in msg.attributes) {
      final int t = a.type;
      // Comprehension-required range: 0x0000-0x7FFF.
      if (t < 0x8000 &&
          t != wire.Attr.messageIntegrity &&
          t != wire.Attr.fingerprint) {
        if (!wire.attrCodecsContains(t)) unknown.add(t);
      }
    }
    return unknown;
  }

  Future<void> _processServerMessage(
      wire.StunMessage msg, Uint8List raw) async {
    // Fingerprint mirroring (per session, reset on each request).
    if (msg.cls == wire.StunClass.request) {
      _useFingerprint = msg.fingerprintOffset != null;
    }

    if (msg.cls == wire.StunClass.request) {
      final List<int> unknown = _checkUnknownComprehension(msg);
      if (unknown.isNotEmpty) {
        _sendError(
            msg,
            420,
            <wire.StunAttribute>[
              wire.StunAttribute(
                  type: wire.Attr.errorCode,
                  value: const wire.StunErrorCode(code: 420)),
              wire.StunAttribute(
                  type: wire.Attr.unknownAttributes, value: unknown),
            ],
            null);
        return;
      }
    }

    if (msg.cls == wire.StunClass.indication) {
      if (_checkUnknownComprehension(msg).isNotEmpty) return;
    }

    // BINDING indication (keep-alive) — silent accept.
    if (msg.method == wire.StunMethod.binding &&
        msg.cls == wire.StunClass.indication) {
      return;
    }

    // Origin consistency.
    if (_opts.checkOriginConsistency) {
      final String? origin = msg.getString(wire.Attr.origin);
      if (origin != null) {
        if (_sessionOrigin == null) {
          _sessionOrigin = origin;
        } else if (origin != _sessionOrigin) {
          if (msg.cls == wire.StunClass.request) {
            _sendError(msg, 403, null, null);
          }
          return;
        }
      }
    }

    // BINDING request.
    if (msg.method == wire.StunMethod.binding &&
        msg.cls == wire.StunClass.request) {
      if (_opts.secureStun && _opts.authMech != AuthMechanism.none) {
        await _authenticateAndHandle(msg, raw);
      } else {
        _handleBinding(msg);
      }
      return;
    }

    // SEND indication (no auth, must have allocation).
    if (msg.method == wire.StunMethod.send &&
        msg.cls == wire.StunClass.indication) {
      _handleSendIndication(msg);
      return;
    }

    // Everything else needs auth.
    if (_opts.authMech != AuthMechanism.none &&
        msg.cls == wire.StunClass.request) {
      await _authenticateAndHandle(msg, raw);
      return;
    }

    _routeServerRequest(msg, null);
  }

  Future<void> _authenticateAndHandle(
      wire.StunMessage msg, Uint8List raw) async {
    switch (_opts.authMech) {
      case AuthMechanism.longTerm:
        await _authenticateLongTerm(msg, raw);
      case AuthMechanism.shortTerm:
        await _authenticateShortTerm(msg, raw);
      case AuthMechanism.oauth:
        await _authenticateOauth(msg, raw);
      case AuthMechanism.none:
        _routeServerRequest(msg, null);
    }
  }

  Future<void> _authenticateOauth(wire.StunMessage msg, Uint8List raw) async {
    final Uint8List? token = msg.getBytes(wire.Attr.accessToken);
    if (token == null) {
      final List<wire.StunAttribute> attrs = <wire.StunAttribute>[
        wire.StunAttribute(
            type: wire.Attr.errorCode,
            value: const wire.StunErrorCode(code: 401)),
        if (_realm != null)
          wire.StunAttribute(type: wire.Attr.realm, value: _realm),
        if (_opts.thirdPartyAuthUrl != null)
          wire.StunAttribute(
              type: wire.Attr.thirdPartyAuthorization,
              value: _opts.thirdPartyAuthUrl),
      ];
      _sendError(msg, 401, attrs, null);
      return;
    }
    final OauthHandler? h = oauthHandler;
    if (h == null) {
      _sendError(msg, 401, null, null);
      return;
    }
    final Uint8List? key = await h(token, _realm);
    if (key == null) {
      _sendError(msg, 401, null, null);
      return;
    }
    if (msg.integrityOffset != null &&
        !wire.validateIntegrity(raw, msg.integrityOffset!, key)) {
      _sendError(msg, 401, null, null);
      return;
    }
    _routeServerRequest(msg, key);
  }

  Future<void> _authenticateShortTerm(
      wire.StunMessage msg, Uint8List raw) async {
    final String? username = msg.getString(wire.Attr.username);
    if (username == null || msg.integrityOffset == null) {
      _sendError(msg, 400, null, null);
      return;
    }

    String? password;
    final AuthenticateHandler? h = authenticateHandler;
    if (h != null) {
      final Object? r = await h(username, null);
      if (r is String) password = r;
    } else {
      password = _credentials[username] ?? _password;
    }
    if (password == null) {
      _sendError(msg, 401, null, null);
      return;
    }

    final Uint8List key = wire.computeShortTermKey(password);
    if (!wire.validateIntegrity(raw, msg.integrityOffset!, key)) {
      _sendError(msg, 401, null, null);
      return;
    }
    if (_allocation != null && _allocation!.username != null) {
      if (_allocation!.username != username) {
        _sendError(msg, 441, null, key);
        return;
      }
    }
    _routeServerRequest(msg, key);
  }

  Future<void> _authenticateLongTerm(
      wire.StunMessage msg, Uint8List raw) async {
    final String? username = msg.getString(wire.Attr.username);
    final String? msgRealm = msg.getString(wire.Attr.realm);
    final String? msgNonce = msg.getString(wire.Attr.nonce);

    if (username == null || msgRealm == null || msgNonce == null) {
      _sendChallenge(msg);
      return;
    }
    if (!_validateNonce(msgNonce)) {
      _sendStaleNonce(msg);
      return;
    }
    if (msg.integrityOffset == null && msg.integritySha256Offset == null) {
      _sendChallenge(msg);
      return;
    }

    final Uint8List? key = await _getKeyForUser(username);
    if (key == null) {
      _sendChallenge(msg);
      return;
    }

    bool valid = false;
    if (msg.integritySha256Offset != null) {
      valid =
          wire.validateIntegritySha256(raw, msg.integritySha256Offset!, key);
    } else if (msg.integrityOffset != null) {
      valid = wire.validateIntegrity(raw, msg.integrityOffset!, key);
    }
    if (!valid) {
      _sendChallenge(msg);
      return;
    }

    // Bid-down protection (RFC 8489 §9.2.1).
    final wire.PasswordAlgorithm? clientAlgo =
        msg.getAttribute<wire.PasswordAlgorithm>(wire.Attr.passwordAlgorithm);
    if (msg.integritySha256Offset == null &&
        msg.integrityOffset != null &&
        clientAlgo != null &&
        clientAlgo.algorithm != wire.PasswordAlgorithm.md5) {
      _sendError(msg, 400, null, null);
      return;
    }

    if (_allocation != null && _allocation!.username != null) {
      if (_allocation!.username != username) {
        _sendError(msg, 441, null, key);
        return;
      }
    }
    _routeServerRequest(msg, key);
  }

  void _routeServerRequest(wire.StunMessage msg, Uint8List? key) {
    final String? username = msg.getString(wire.Attr.username);
    if (!_runHook<AuthorizeInfo>(
        authorize,
        AuthorizeInfo(
          method: msg.method,
          methodName: wire.methodName[msg.method],
          username: username,
          source: _source,
        ))) {
      _sendError(msg, 403, null, key);
      return;
    }

    switch (msg.method) {
      case wire.StunMethod.binding:
        _handleBinding(msg);
      case wire.StunMethod.allocate:
        _handleAllocate(msg, key);
      case wire.StunMethod.refresh:
        _handleRefresh(msg, key);
      case wire.StunMethod.createPermission:
        _handleCreatePermission(msg, key);
      case wire.StunMethod.channelBind:
        _handleChannelBind(msg, key);
      case wire.StunMethod.connect:
        unawaited(_handleConnect(msg, key));
      case wire.StunMethod.connectionBind:
        unawaited(_handleConnectionBind(msg, key));
      default:
        _sendError(msg, 400, null, key);
    }
  }

  /* ---------- Server handlers ---------- */

  void _handleBinding(wire.StunMessage msg) {
    if (_source == null) {
      _sendError(msg, 400, null, null);
      return;
    }

    final List<wire.StunAttribute> responseAttrs = <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.xorMappedAddress, value: _source),
      if (_localAddress != null)
        wire.StunAttribute(
            type: wire.Attr.responseOrigin, value: _localAddress),
      if (_secondaryAddress != null)
        wire.StunAttribute(
            type: wire.Attr.otherAddress, value: _secondaryAddress),
    ];

    final wire.ChangeRequestValue? change =
        msg.getAttribute<wire.ChangeRequestValue>(wire.Attr.changeRequest);
    if (change != null) {
      _onChangeRequest.add(ChangeRequestEvent(
          message: msg, change: change, responseAttributes: responseAttrs));
      return;
    }
    _sendSuccess(msg, responseAttrs, null);
  }

  void _handleAllocate(wire.StunMessage msg, Uint8List? key) {
    if (_allocation != null) {
      _sendError(msg, 437, null, key);
      return;
    }

    final int? transport = msg.getInt(wire.Attr.requestedTransport);
    if (transport == null) {
      _sendError(msg, 400, null, key);
      return;
    }
    if (transport != wire.TransportProtocol.udp &&
        transport != wire.TransportProtocol.tcp) {
      _sendError(msg, 442, null, key);
      return;
    }

    final Uint8List? reservationToken =
        msg.getBytes(wire.Attr.reservationToken);
    final bool? evenPort = msg.getAttribute<bool>(wire.Attr.evenPort);
    if (reservationToken != null && evenPort != null) {
      _sendError(msg, 400, null, key);
      return;
    }

    final int? requestedFamily = msg.getInt(wire.Attr.requestedAddressFamily);
    if (requestedFamily != null &&
        requestedFamily != wire.AddressFamily.ipv4 &&
        requestedFamily != wire.AddressFamily.ipv6) {
      _sendError(msg, 440, null, key);
      return;
    }

    final String? username = msg.getString(wire.Attr.username);
    if (quotaHook != null && !quotaHook!(username)) {
      _sendError(msg, 486, null, key);
      return;
    }

    int lifetime =
        msg.getInt(wire.Attr.lifetime) ?? _opts.defaultAllocateLifetime;
    final AllocateInfo allocInfo = AllocateInfo(
      username: username,
      source: _source,
      transport: transport,
      lifetime: lifetime,
      requestedFamily: requestedFamily,
      evenPort: evenPort,
      reservationToken: reservationToken,
      dontFragment: msg.getAttribute<bool>(wire.Attr.dontFragment) ?? false,
    );
    if (!_runHook<AllocateInfo>(beforeAllocate, allocInfo)) {
      _sendError(msg, 403, null, key);
      return;
    }
    lifetime = allocInfo.lifetime;

    final Allocation alloc = _createAllocation(msg, transport, lifetime);
    alloc.evenPort = evenPort;
    alloc.reservationToken = reservationToken;
    alloc.dontFragment =
        msg.getAttribute<bool>(wire.Attr.dontFragment) ?? false;
    alloc.requestedFamily = requestedFamily;

    int? additionalFamily = msg.getInt(wire.Attr.additionalAddressFamily);
    if (additionalFamily != null) {
      if (additionalFamily != wire.AddressFamily.ipv4 &&
          additionalFamily != wire.AddressFamily.ipv6) {
        additionalFamily = null;
      } else if (additionalFamily == requestedFamily ||
          (requestedFamily == null &&
              additionalFamily == wire.AddressFamily.ipv4)) {
        additionalFamily = null;
      }
    }
    alloc.additionalFamily = additionalFamily;

    alloc.confirm = (wire.StunAddress addr) {
      if (alloc._responseSent) return;
      alloc._responseSent = true;
      alloc.confirmed = true;
      alloc.relayAddress = addr;
      _sendSuccess(
          msg,
          <wire.StunAttribute>[
            wire.StunAttribute(
                type: wire.Attr.xorRelayedAddress, value: alloc.relayAddress),
            wire.StunAttribute(
                type: wire.Attr.xorMappedAddress, value: _source),
            wire.StunAttribute(type: wire.Attr.lifetime, value: alloc.lifetime),
          ],
          key);
    };

    alloc.reject = (Object _) {
      if (alloc._responseSent) return;
      alloc._responseSent = true;
      alloc.confirmed = true;
      _expireAllocation();
      _sendError(msg, 508, null, key);
    };

    _onAllocate.add(alloc);
    if (!alloc.confirmed) alloc.confirm!(alloc.relayAddress);
  }

  void _handleRefresh(wire.StunMessage msg, Uint8List? key) {
    if (_allocation == null) {
      _sendError(msg, 437, null, key);
      return;
    }

    int lifetime = msg.getInt(wire.Attr.lifetime) ?? _allocation!.lifetime;
    final RefreshInfo info = RefreshInfo(
      username: _allocation!.username,
      source: _source,
      currentLifetime: _allocation!.lifetime,
      lifetime: lifetime,
    );
    if (!_runHook<RefreshInfo>(beforeRefresh, info)) {
      _sendError(msg, 403, null, key);
      return;
    }
    lifetime = info.lifetime;

    _refreshAllocation(lifetime);

    _sendSuccess(
        msg,
        <wire.StunAttribute>[
          wire.StunAttribute(
              type: wire.Attr.lifetime,
              value: lifetime == 0 ? 0 : (_allocation?.lifetime ?? 0)),
        ],
        key);
  }

  void _handleCreatePermission(wire.StunMessage msg, Uint8List? key) {
    if (_allocation == null) {
      _sendError(msg, 437, null, key);
      return;
    }

    final List<wire.StunAddress> peers = <wire.StunAddress>[
      for (final wire.StunAttribute a in msg.attributes)
        if (a.type == wire.Attr.xorPeerAddress && a.value is wire.StunAddress)
          a.value! as wire.StunAddress,
    ];
    if (peers.isEmpty) {
      _sendError(msg, 400, null, key);
      return;
    }

    for (final wire.StunAddress p in peers) {
      if (!_runHook<PermissionInfo>(
          beforePermission,
          PermissionInfo(
            username: _allocation!.username,
            source: _source,
            peer: p,
          ))) {
        _sendError(msg, 403, null, key);
        return;
      }
    }

    for (final wire.StunAddress p in peers) {
      _addPermission(p.ip);
    }
    _sendSuccess(msg, <wire.StunAttribute>[], key);
  }

  void _handleChannelBind(wire.StunMessage msg, Uint8List? key) {
    if (_allocation == null) {
      _sendError(msg, 437, null, key);
      return;
    }

    final int? channelNumber = msg.getInt(wire.Attr.channelNumber);
    final wire.StunAddress? peer = msg.getAddress(wire.Attr.xorPeerAddress);
    if (channelNumber == null || peer == null) {
      _sendError(msg, 400, null, key);
      return;
    }
    if (channelNumber < 0x4000 || channelNumber > 0x4FFF) {
      _sendError(msg, 400, null, key);
      return;
    }

    if (!_runHook<ChannelBindInfo>(
        beforeChannelBind,
        ChannelBindInfo(
          username: _allocation!.username,
          source: _source,
          channel: channelNumber,
          peer: peer,
        ))) {
      _sendError(msg, 403, null, key);
      return;
    }

    if (!_bindChannel(channelNumber, peer)) {
      _sendError(msg, 400, null, key);
      return;
    }
    _sendSuccess(msg, <wire.StunAttribute>[], key);
  }

  void _handleSendIndication(wire.StunMessage msg) {
    if (_allocation == null) return;
    final wire.StunAddress? peer = msg.getAddress(wire.Attr.xorPeerAddress);
    final Uint8List? data = msg.getBytes(wire.Attr.data);
    if (peer == null || data == null) return;
    if (!_hasPermission(peer.ip)) return;

    if (!_runHook<RelayInfo>(
        beforeRelay,
        RelayInfo(
          username: _allocation!.username,
          source: _source,
          peer: peer,
          size: data.length,
          direction: RelayDirection.outbound,
        ))) {
      return;
    }

    _bytesOut += data.length;
    _onRelay.add(RelayEvent(peer: peer, data: data, channel: null));
  }

  /* ---------- TCP relay handlers (RFC 6062) ---------- */

  Future<void> _handleConnect(wire.StunMessage msg, Uint8List? key) async {
    if (_allocation == null) {
      _sendError(msg, 437, null, key);
      return;
    }
    final wire.StunAddress? peer = msg.getAddress(wire.Attr.xorPeerAddress);
    if (peer == null) {
      _sendError(msg, 400, null, key);
      return;
    }
    if (!_hasPermission(peer.ip)) {
      _sendError(msg, 403, null, key);
      return;
    }

    for (final _TcpConnState existing in _tcpConnections.values) {
      if (existing.peer.ip == peer.ip && existing.peer.port == peer.port) {
        _sendError(msg, 446, null, key);
        return;
      }
    }

    if (!_runHook<ConnectInfo>(
        beforeConnect,
        ConnectInfo(
          username: _allocation!.username,
          source: _source,
          peer: peer,
        ))) {
      _sendError(msg, 403, null, key);
      return;
    }

    final int connectionId = _nextConnectionId++;
    _tcpConnections[connectionId] =
        _TcpConnState(peer: peer, state: _TcpConnPhase.pending);

    final ConnectPeerHandler? h = connectPeerHandler;
    if (h == null) {
      _tcpConnections.remove(connectionId);
      _sendError(msg, 447, null, key);
      return;
    }

    final Object? err = await h(connectionId, peer);
    if (err != null) {
      _tcpConnections.remove(connectionId);
      _sendError(msg, 447, null, key);
      return;
    }

    _tcpConnections[connectionId]!.state = _TcpConnPhase.established;
    _sendSuccess(
        msg,
        <wire.StunAttribute>[
          wire.StunAttribute(type: wire.Attr.connectionId, value: connectionId),
        ],
        key);
    _sendIndication(wire.StunMethod.connectionAttempt, <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.xorPeerAddress, value: peer),
      wire.StunAttribute(type: wire.Attr.connectionId, value: connectionId),
    ]);
  }

  Future<void> _handleConnectionBind(
      wire.StunMessage msg, Uint8List? key) async {
    final int? connectionId = msg.getInt(wire.Attr.connectionId);
    if (connectionId == null) {
      _sendError(msg, 400, null, key);
      return;
    }
    final _TcpConnState? conn = _tcpConnections[connectionId];
    if (conn == null || conn.state != _TcpConnPhase.established) {
      _sendError(msg, 400, null, key);
      return;
    }

    final ConnectionBindHandler? h = connectionBindHandler;
    if (h == null) {
      _sendError(msg, 400, null, key);
      return;
    }
    final Object? err = await h(connectionId, conn.peer);
    if (err != null) {
      _sendError(msg, 400, null, key);
      return;
    }
    _sendSuccess(msg, <wire.StunAttribute>[], key);
  }

  /* ---------- Client-side processing ---------- */

  void _processClientMessage(wire.StunMessage msg) {
    // Match transactionId (RFC 8489 §6.3.3).
    final Uint8List? pending = _pendingTransactionId;
    if (pending != null) {
      bool match = pending.length == msg.transactionId.length;
      if (match) {
        for (int i = 0; i < 12; i++) {
          if (msg.transactionId[i] != pending[i]) {
            match = false;
            break;
          }
        }
      }
      if (!match) return;
    }

    if (msg.cls == wire.StunClass.success) {
      _pendingRequest = null;
      _pendingTransactionId = null;
      _stopRetransmission();
      _onSuccess.add(msg);
      _maybeAutoSchedule(msg);
      return;
    }

    if (msg.cls == wire.StunClass.error) {
      final wire.StunErrorCode? err = msg.getErrorCode();

      // 300 Try Alternate
      if (err != null && err.code == 300) {
        _pendingRequest = null;
        _pendingTransactionId = null;
        _stopRetransmission();
        _onRedirect.add(RedirectEvent(
          server: msg.getAddress(wire.Attr.alternateServer),
          domain: msg.getString(wire.Attr.alternateDomain),
        ));
        return;
      }

      // 401 Unauthorized — auto-retry once with extracted realm/nonce.
      if (err != null &&
          err.code == 401 &&
          _pendingRequest != null &&
          _pendingRequest!.retries < 1) {
        final String? newRealm = msg.getString(wire.Attr.realm);
        final String? newNonce = msg.getString(wire.Attr.nonce);
        if (newRealm != null &&
            newNonce != null &&
            _username != null &&
            _password != null) {
          _realm = newRealm;
          _nonce = newNonce;
          _clientKeyInputs = null;

          final List<wire.PasswordAlgorithm>? algos = msg
              .getAttribute<List<Object?>>(wire.Attr.passwordAlgorithms)
              ?.cast<wire.PasswordAlgorithm>();
          if (algos != null && algos.isNotEmpty) {
            int? chosen;
            for (final wire.PasswordAlgorithm a in algos) {
              if (a.algorithm == wire.PasswordAlgorithm.sha256) {
                chosen = wire.PasswordAlgorithm.sha256;
                break;
              }
            }
            _passwordAlgorithm = chosen ?? algos.first.algorithm;
          }

          _pendingRequest!.retries++;
          _sendClientRequest(
              _pendingRequest!.method, _pendingRequest!.attributes);
          return;
        }
      }

      // 438 Stale Nonce — auto-retry once with new nonce.
      if (err != null &&
          err.code == 438 &&
          _pendingRequest != null &&
          _pendingRequest!.retries < 1) {
        final String? staleNonce = msg.getString(wire.Attr.nonce);
        if (staleNonce != null) {
          _nonce = staleNonce;
          _pendingRequest!.retries++;
          _sendClientRequest(
              _pendingRequest!.method, _pendingRequest!.attributes);
          return;
        }
      }

      _pendingRequest = null;
      _pendingTransactionId = null;
      _stopRetransmission();
      _onErrorResponse.add(ErrorResponseEvent(msg, err));
      return;
    }

    // DATA indication.
    if (msg.method == wire.StunMethod.data &&
        msg.cls == wire.StunClass.indication) {
      final wire.StunAddress? peer = msg.getAddress(wire.Attr.xorPeerAddress);
      final Uint8List? data = msg.getBytes(wire.Attr.data);
      if (peer != null && data != null) {
        _bytesIn += data.length;
        _onData.add(DataEvent(peer: peer, data: data));
      }
    }
  }

  void _maybeAutoSchedule(wire.StunMessage msg) {
    if (_isServer || !_autoRefresh) return;
    if (msg.method == wire.StunMethod.allocate ||
        msg.method == wire.StunMethod.refresh) {
      final int? lt = msg.getInt(wire.Attr.lifetime);
      if (lt != null && lt > 0) _scheduleAllocationRefresh(lt);
    }
  }

  /* ---------- Client send + retransmit ---------- */

  Uint8List? _getClientKey() {
    if (_opts.authMech == AuthMechanism.longTerm &&
        _username != null &&
        _realm != null &&
        _password != null) {
      final String inputs = '$_username:$_realm:$_password';
      if (_clientKeyInputs != inputs) {
        _clientKey = wire.computeLongTermKey(_username!, _realm!, _password!);
        _clientKeyInputs = inputs;
      }
      return _clientKey;
    }
    if (_opts.authMech == AuthMechanism.shortTerm && _password != null) {
      return wire.computeShortTermKey(_password!);
    }
    return null;
  }

  void _startRetransmission(Uint8List buf) {
    _stopRetransmission();
    if (_opts.rto != null) {
      _rtoLastBuf = buf;
      _rtoAttempt = 0;
      _scheduleRetransmit();
    } else {
      _rtoTimer = Timer(_opts.tcpTimeout, () {
        _rtoTimer = null;
        _pendingRequest = null;
        _pendingTransactionId = null;
        _onTimeout.add(null);
      });
    }
  }

  void _scheduleRetransmit() {
    if (_rtoAttempt >= _rtoMaxRetries) {
      _stopRetransmission();
      _onTimeout.add(null);
      return;
    }
    final int rtoMs = _opts.rto!.inMilliseconds;
    int delay = rtoMs * (1 << _rtoAttempt);
    if (delay > 16 * rtoMs) delay = 16 * rtoMs;
    _rtoTimer = Timer(Duration(milliseconds: delay), () {
      _rtoAttempt++;
      if (_rtoLastBuf != null) _onMessage.add(_rtoLastBuf!);
      _scheduleRetransmit();
    });
  }

  void _stopRetransmission() {
    _rtoTimer?.cancel();
    _rtoTimer = null;
    _rtoLastBuf = null;
    _rtoAttempt = 0;
  }

  Uint8List _sendClientRequest(
      int method, List<wire.StunAttribute> attributes) {
    if (_pendingRequest == null || _pendingRequest!.method != method) {
      _pendingRequest = _PendingRequest(method: method, attributes: attributes);
    }

    final List<wire.StunAttribute> finalAttrs = <wire.StunAttribute>[
      ...attributes,
      if (_opts.authMech == AuthMechanism.longTerm &&
          _username != null &&
          _realm != null &&
          _nonce != null) ...<wire.StunAttribute>[
        wire.StunAttribute(type: wire.Attr.username, value: _username),
        wire.StunAttribute(type: wire.Attr.realm, value: _realm),
        wire.StunAttribute(type: wire.Attr.nonce, value: _nonce),
      ],
      if (_opts.authMech == AuthMechanism.shortTerm && _username != null)
        wire.StunAttribute(type: wire.Attr.username, value: _username),
      if (_opts.authMech == AuthMechanism.longTerm &&
          _passwordAlgorithm != null)
        wire.StunAttribute(
            type: wire.Attr.passwordAlgorithm,
            value: wire.PasswordAlgorithm(algorithm: _passwordAlgorithm!)),
      if (_opts.software != null)
        wire.StunAttribute(type: wire.Attr.software, value: _opts.software),
    ];

    final wire.IntegrityAlgo integrityAlgo =
        _opts.authMech == AuthMechanism.longTerm &&
                _passwordAlgorithm == wire.PasswordAlgorithm.sha256
            ? wire.IntegrityAlgo.sha256
            : wire.IntegrityAlgo.sha1;

    final wire.EncodedMessage result = wire.encodeMessage(wire.EncodeOptions(
      method: method,
      cls: wire.StunClass.request,
      attributes: finalAttrs,
      key: _getClientKey(),
      integrity: integrityAlgo,
      fingerprint: _useFingerprint,
    ));

    _onMessage.add(result.buf);
    _pendingTransactionId = result.transactionId;
    _startRetransmission(result.buf);
    return result.transactionId;
  }

  /* ---------- Auto-refresh ---------- */

  void _scheduleAllocationRefresh(int lifetime) {
    if (!_autoRefresh || _isServer) return;
    _refreshTimer?.cancel();
    final int delay = math.max((lifetime - 60) * 1000, 30000);
    _refreshTimer = Timer(Duration(milliseconds: delay), () {
      if (_state == SessionState.closed) return;
      _sendClientRequest(wire.StunMethod.refresh, <wire.StunAttribute>[
        wire.StunAttribute(type: wire.Attr.lifetime, value: lifetime),
      ]);
    });
  }

  void schedulePermissionRefresh(List<wire.StunAddress> peers) {
    if (!_autoRefresh || _isServer) return;
    final String key = peers.map((wire.StunAddress p) => p.ip).join(',');
    _permissionTimers[key]?.cancel();
    _permissionTimers[key] = Timer(const Duration(minutes: 4), () {
      if (_state == SessionState.closed) return;
      createPermission(peers);
    });
  }

  void scheduleChannelRefresh(int channel, wire.StunAddress peer) {
    if (!_autoRefresh || _isServer) return;
    _channelTimers[channel]?.cancel();
    _channelTimers[channel] = Timer(const Duration(minutes: 9), () {
      if (_state == SessionState.closed) return;
      channelBind(channel, peer);
    });
  }

  void _clearRefreshTimers() {
    _refreshTimer?.cancel();
    _refreshTimer = null;
    for (final Timer t in _permissionTimers.values) {
      t.cancel();
    }
    _permissionTimers.clear();
    for (final Timer t in _channelTimers.values) {
      t.cancel();
    }
    _channelTimers.clear();
  }
}

/* ============================ Supporting types ============================ */

enum _TcpConnPhase { pending, established }

class _TcpConnState {
  _TcpConnState({required this.peer, required this.state});
  final wire.StunAddress peer;
  _TcpConnPhase state;
}

/// Server-side relay event — Socket layer subscribes.
class RelayEvent {
  const RelayEvent({required this.peer, required this.data, this.channel});
  final wire.StunAddress peer;
  final Uint8List data;
  final int? channel;
}

class PermissionEvent {
  const PermissionEvent({required this.ip, required this.allocation});
  final String ip;
  final Allocation allocation;
}

class ChannelEvent {
  const ChannelEvent({
    required this.number,
    required this.peer,
    required this.allocation,
  });
  final int number;
  final wire.StunAddress peer;
  final Allocation allocation;
}

/* ============================ Helpers ============================ */

Uint8List _randomBytes(int n) {
  final math.Random rng = math.Random.secure();
  final Uint8List out = Uint8List(n);
  for (int i = 0; i < n; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}
