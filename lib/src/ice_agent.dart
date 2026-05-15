// ICE Agent (RFC 8445) — interactive connectivity establishment.
// Type-safe Dart port of `src/ice_agent.js`.
//
// Supports:
//   - Full ICE + ICE-Lite
//   - Trickle + vanilla gathering
//   - Host + server-reflexive (srflx) + relay (TURN) candidates
//   - Regular nomination (controlling agent)
//   - Consent freshness (RFC 7675)
//   - ICE restart (RFC 8445 §9) with media continuity
//   - Role-conflict resolution (RFC 8445 §7.3.1.1)
//   - Peer-reflexive candidate discovery
//   - IPv4 + IPv6
//
// Spec references:
//   RFC 8445   — ICE
//   RFC 8489   — STUN
//   RFC 5389   — STUN (legacy)
//   RFC 5766   — TURN (legacy)
//   RFC 8656   — TURN-bis
//   RFC 7675   — Consent freshness
//   RFC 8839   — SDP for ICE
//   RFC 8838   — Trickle ICE

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'ice_candidate.dart';
import 'session.dart' show AuthMechanism;
import 'socket.dart' as turn_socket;
import 'wire.dart' as wire;

/* ============================ Public types =============================== */

/// ICE agent operating mode (RFC 8445 §6.1.1).
enum IceMode { full, lite }

/// ICE connection state (RFC 8445 §6.1.4).
enum IceState {
  fresh, // 'new' — but Dart can't use that as identifier
  checking,
  connected,
  completed,
  disconnected,
  failed,
  closed,
}

/// ICE gathering state (RFC 8445 §5.1.1.4).
enum IceGatheringState { fresh, gathering, complete }

/// ICE role (RFC 8445 §6.1.1).
enum IceRole { controlling, controlled }

/// ICE transport policy (WebRTC).
enum IceTransportPolicy { all, relay }

/// Configuration for a single ICE/STUN/TURN server.
class IceServer {
  const IceServer({
    required this.urls,
    this.username,
    this.credential,
    this.serverName,
    this.rejectUnauthorized = true,
    this.context,
  });
  final List<String> urls;
  final String? username;
  final String? credential;

  /// TLS server name override (`turns:` URLs).
  final String? serverName;
  final bool rejectUnauthorized;
  final SecurityContext? context;
}

/// A pair of (local, remote) candidates undergoing connectivity checking.
///
/// Mutable — its `state`, `valid`, and nomination flags evolve as the agent
/// progresses through the check list. Consumers should treat instances as
/// opaque tokens; equality is identity.
class CandidatePair {
  CandidatePair._({
    required _LocalCandidate local,
    required this.remote,
    required this.priority,
  }) : _local = local;

  /// The local candidate (wire-stable view).
  IceCandidate get local => _local.cand;

  /// The remote candidate.
  final IceCandidate remote;

  // Internal mutable wrapper for the local candidate (carries socket / TURN
  // client). Not exposed to user code.
  final _LocalCandidate _local;

  /// Pair priority (RFC 8445 §6.1.2.3).
  int priority;

  CheckState state = CheckState.frozen;
  bool valid = false;
  bool nominated = false;
  bool peerNominated = false;
  bool weNominated = false;

  /* --- internal --- */
  int retransmits = 0;
  Uint8List? transactionId;
  int lastSent = 0;
  Uint8List? encodedCheck;
  Timer? retransmitTimer;
  bool _permissionReady = false;
  int? _channel;
  RawDatagramSocket? _sock;
}

/// Per-pair check state (RFC 8445 §6.1.2.6).
enum CheckState { frozen, waiting, inProgress, succeeded, failed }

/// Local ICE parameters (sent in SDP).
class IceParameters {
  const IceParameters({
    required this.ufrag,
    required this.pwd,
    this.iceLite = false,
  });
  final String ufrag;
  final String pwd;
  final bool iceLite;
}

/// Event payload for a connectivity-check result.
class PairCheckEvent {
  const PairCheckEvent({required this.pair, required this.success});
  final CandidatePair pair;
  final bool success;
}

/// Event payload for a selected-pair change.
class SelectedPairEvent {
  const SelectedPairEvent({required this.pair, this.previous});
  final CandidatePair pair;
  final CandidatePair? previous;
}

/// Source info for an ingress (non-STUN) packet — emitted on
/// [IceAgent.onPacket].
class PacketEvent {
  const PacketEvent({
    required this.data,
    required this.source,
    required this.kind,
  });
  final Uint8List data;
  final wire.StunAddress source;
  final wire.DemuxKind kind;
}

/// Reported when a candidate-gathering attempt fails.
class CandidateErrorEvent {
  const CandidateErrorEvent({
    required this.type,
    required this.server,
    this.base,
    required this.error,
  });
  final String type; // 'srflx' | 'relay'
  final String server;
  final String? base;
  final Object error;
}

/// Configuration for a new [IceAgent].
class IceAgentOptions {
  const IceAgentOptions({
    this.mode = IceMode.full,
    this.trickle = true,
    this.controlling = true,
    this.iceServers = const <IceServer>[],
    this.iceTransportPolicy = IceTransportPolicy.all,
    this.includeLoopback = false,
    this.ipv6 = true,
    this.components = 1,
    this.ufrag,
    this.pwd,
  });
  final IceMode mode;
  final bool trickle;
  final bool controlling;
  final List<IceServer> iceServers;
  final IceTransportPolicy iceTransportPolicy;
  final bool includeLoopback;
  final bool ipv6;
  final int components;
  final String? ufrag;
  final String? pwd;
}

/* ============================ Constants ================================== */

const int _stunInitialRtoUdp = 500; // ms
const int _stunMaxRetransmissions = 7;

const int _checkPaceMs = 50;
const int _nominationDelayMs = 100;

const int _consentIntervalMs = 15000;
const double _consentRandomization = 0.2;
const int _consentDisconnectMs = 30000;
const int _consentFailedMs = 45000;

const int _gatherSrflxTimeoutMs = 5000;
const int _gatherRelayTimeoutMs = 8000;

const int _turnPermissionLifetimeMs = 300000;
const int _turnPermissionRefreshMs = 240000;

const int _componentRtp = 1;
const int _localPreferenceDefault = 65535;

/* ============================ Internal types ============================= */

class _LocalCandidate {
  _LocalCandidate(
    this.cand, {
    required this.base,
    this.socket,
    this.turnClient,
    this.turnKey,
  });
  IceCandidate cand;
  _BaseAddr base;
  RawDatagramSocket? socket;
  turn_socket.TurnSocket? turnClient;
  String? turnKey;
}

class _BaseAddr {
  const _BaseAddr({required this.ip, required this.port, required this.family});
  final String ip;
  final int port;
  final int family; // 4 | 6
}

class _PendingTransaction {
  _PendingTransaction({
    required this.kind,
    required this.callback,
    this.pair,
    this.timer,
  });
  final String kind; // 'check' | 'consent' | 'gather-srflx'
  final void Function(
      wire.StunMessage? msg, wire.StunAddress? source, Object? error) callback;
  CandidatePair? pair;
  Timer? timer;
}

class _StunServer {
  _StunServer({required this.uri, required this.parsed});
  final String uri;
  final wire.StunUri parsed;
}

class _TurnServerConfig {
  _TurnServerConfig({
    required this.uri,
    required this.parsed,
    required this.username,
    required this.credential,
    this.serverName,
    this.rejectUnauthorized = true,
    this.context,
  });
  final String uri;
  final wire.StunUri parsed;
  final String username;
  final String credential;
  final String? serverName;
  final bool rejectUnauthorized;
  final SecurityContext? context;
}

class _TurnPermission {
  _TurnPermission({required this.expires, this.timer});
  int expires;
  Timer? timer;
}

/* ============================== IceAgent ================================= */

class IceAgent {
  IceAgent([IceAgentOptions options = const IceAgentOptions()])
      : _opts = options {
    _mode = options.mode;
    _trickle = options.trickle;
    _controlling = options.controlling;
    _iceServers = List<IceServer>.unmodifiable(options.iceServers);
    _iceTransportPolicy = options.iceTransportPolicy;
    _includeLoopback = options.includeLoopback;
    _ipv6 = options.ipv6;
    _components = options.components;

    _localUfrag = options.ufrag ?? _randomUfrag();
    _localPwd = options.pwd ?? _randomPwd();

    _tieBreaker = wire.IceTiebreaker(_randomBytes(8));
  }

  // ignore: unused_field
  final IceAgentOptions _opts;

  /* ── Identity & config ── */
  late IceMode _mode;
  late bool _trickle;
  late bool _controlling;
  late List<IceServer> _iceServers;
  late IceTransportPolicy _iceTransportPolicy;
  late bool _includeLoopback;
  late bool _ipv6;
  // ignore: unused_field
  late int _components;
  late wire.IceTiebreaker _tieBreaker;

  /* ── Lifecycle state ── */
  IceState _state = IceState.fresh;
  IceGatheringState _gatheringState = IceGatheringState.fresh;
  bool _closed = false;

  /* ── Credentials ── */
  late String _localUfrag;
  late String _localPwd;
  String? _remoteUfrag;
  String? _remotePwd;
  bool _remoteIceLite = false;

  /* ── Candidates ── */
  final List<_LocalCandidate> _localCandidates = <_LocalCandidate>[];
  final List<IceCandidate> _remoteCandidates = <IceCandidate>[];
  bool _remoteCandidatesEnded = false;

  /* ── Check list / pairs ── */
  final List<CandidatePair> _checkList = <CandidatePair>[];
  final List<CandidatePair> _validList = <CandidatePair>[];
  final List<CandidatePair> _triggeredQueue = <CandidatePair>[];

  /* ── Selected pair ── */
  CandidatePair? _selectedPair;
  CandidatePair? _previousPair; // ICE restart media continuity

  /* ── Sockets ── */
  final Map<String, RawDatagramSocket> _sockets = <String, RawDatagramSocket>{};
  RawDatagramSocket? _primarySocket;
  RawDatagramSocket? _externalSocket;

  /* ── TURN ── */
  final Map<String, turn_socket.TurnSocket> _turnClients =
      <String, turn_socket.TurnSocket>{};
  final Map<String, _TurnPermission> _turnPermissions =
      <String, _TurnPermission>{};

  /* ── STUN transactions ── */
  final Map<String, _PendingTransaction> _pendingTransactions =
      <String, _PendingTransaction>{};

  /* ── Timers ── */
  Timer? _checkTimer;
  Timer? _nominationTimer;
  Timer? _consentTimer;
  bool _nominationStarted = false;
  int _consentLastSuccessAt = 0;

  /* ── Internal guards ── */
  bool _gatheringHost = false;
  int _gatheringSrflx = 0;
  int _gatheringRelay = 0;
  bool _endOfCandidatesEmitted = false;
  final Set<Timer> _gatherTimers = <Timer>{};
  final List<StreamSubscription<RawSocketEvent>> _socketSubs =
      <StreamSubscription<RawSocketEvent>>[];
  final List<StreamSubscription<dynamic>> _turnSubs =
      <StreamSubscription<dynamic>>[];

  /* ============================ Event sinks ============================= */

  final StreamController<IceCandidate?> _onCandidate =
      StreamController<IceCandidate?>.broadcast();
  final StreamController<IceState> _onStateChange =
      StreamController<IceState>.broadcast();
  final StreamController<IceGatheringState> _onGatheringStateChange =
      StreamController<IceGatheringState>.broadcast();
  final StreamController<SelectedPairEvent> _onSelectedPair =
      StreamController<SelectedPairEvent>.broadcast();
  final StreamController<PacketEvent> _onPacket =
      StreamController<PacketEvent>.broadcast();
  final StreamController<Object> _onError =
      StreamController<Object>.broadcast();
  final StreamController<CandidateErrorEvent> _onCandidateError =
      StreamController<CandidateErrorEvent>.broadcast();
  final StreamController<IceRole> _onRoleChange =
      StreamController<IceRole>.broadcast();
  final StreamController<PairCheckEvent> _onPairCheck =
      StreamController<PairCheckEvent>.broadcast();
  final StreamController<IceParameters> _onRestart =
      StreamController<IceParameters>.broadcast();

  /// Stream of newly-gathered local candidates. A `null` value is the
  /// end-of-candidates marker (RFC 8838).
  Stream<IceCandidate?> get onCandidate => _onCandidate.stream;
  Stream<IceState> get onStateChange => _onStateChange.stream;
  Stream<IceGatheringState> get onGatheringStateChange =>
      _onGatheringStateChange.stream;
  Stream<SelectedPairEvent> get onSelectedPair => _onSelectedPair.stream;
  Stream<PacketEvent> get onPacket => _onPacket.stream;
  Stream<Object> get onError => _onError.stream;
  Stream<CandidateErrorEvent> get onCandidateError => _onCandidateError.stream;
  Stream<IceRole> get onRoleChange => _onRoleChange.stream;
  Stream<PairCheckEvent> get onPairCheck => _onPairCheck.stream;
  Stream<IceParameters> get onRestart => _onRestart.stream;

  /* ============================== Public API ============================ */

  IceMode get mode => _mode;
  IceState get state => _state;
  IceGatheringState get gatheringState => _gatheringState;
  IceRole get role => _controlling ? IceRole.controlling : IceRole.controlled;
  CandidatePair? get selectedPair => _selectedPair;

  IceParameters get localParameters => IceParameters(
      ufrag: _localUfrag, pwd: _localPwd, iceLite: _mode == IceMode.lite);

  IceParameters? get remoteParameters => _remoteUfrag == null
      ? null
      : IceParameters(
          ufrag: _remoteUfrag!,
          pwd: _remotePwd ?? '',
          iceLite: _remoteIceLite,
        );

  List<IceCandidate> get localCandidates => List<IceCandidate>.unmodifiable(
      _localCandidates.map((_LocalCandidate l) => l.cand));
  List<IceCandidate> get remoteCandidates =>
      List<IceCandidate>.unmodifiable(_remoteCandidates);

  void setLocalParameters(IceParameters p) {
    if (_closed) return;
    bool changed = false;
    if (p.ufrag.isNotEmpty && p.ufrag != _localUfrag) {
      _localUfrag = p.ufrag;
      changed = true;
    }
    if (p.pwd.isNotEmpty && p.pwd != _localPwd) {
      _localPwd = p.pwd;
      changed = true;
    }
    if (changed) _runCascades();
  }

  void setRemoteParameters(IceParameters p) {
    if (_closed) return;
    bool changed = false;
    if (p.ufrag.isNotEmpty && p.ufrag != _remoteUfrag) {
      _remoteUfrag = p.ufrag;
      changed = true;
    }
    if (p.pwd.isNotEmpty && p.pwd != _remotePwd) {
      _remotePwd = p.pwd;
      changed = true;
    }
    if (p.iceLite != _remoteIceLite) {
      _remoteIceLite = p.iceLite;
      changed = true;
      if (_remoteIceLite && !_controlling) {
        _controlling = true;
        _recomputePairPriorities();
        _onRoleChange.add(IceRole.controlling);
      }
    }
    if (changed) _runCascades();
  }

  /// Add a remote candidate. Pass `null` (or use [endRemoteCandidates]) to
  /// signal end-of-candidates.
  void addRemoteCandidate(Object? candOrString) {
    if (_closed) return;
    if (candOrString == null) {
      endRemoteCandidates();
      return;
    }
    IceCandidate? cand;
    if (candOrString is IceCandidate) {
      cand = candOrString;
    } else if (candOrString is String) {
      cand = parseCandidate(candOrString);
    }
    if (cand == null) return;
    if (_findRemoteCandidate(cand.ip, cand.port) != null) return;
    _remoteCandidates.add(cand);
    _formPairsForNewRemote(cand);
    _runCascades();
  }

  void endRemoteCandidates() {
    if (_closed || _remoteCandidatesEnded) return;
    _remoteCandidatesEnded = true;
    _runCascades();
  }

  /// Begin gathering candidates. Idempotent.
  void gather() {
    if (_closed) return;
    _startGathering();
  }

  /// Provide an externally-bound UDP socket to share instead of binding our
  /// own. Pass `null` to clear.
  void useSocket(RawDatagramSocket? sock) {
    if (_closed) return;
    _externalSocket = sock;
    if (sock != null) {
      final InternetAddress addr = sock.address;
      _addHostFromBoundSocket(
          sock,
          _BaseAddr(
              ip: addr.address,
              port: sock.port,
              family: addr.type == InternetAddressType.IPv6 ? 6 : 4));
    }
  }

  /// Send application data through the selected pair. During an ICE restart,
  /// falls back to the previously-selected pair so media continues to flow
  /// (RFC 8445 §9). Returns false if no pair is available.
  bool send(Uint8List buf) {
    final CandidatePair? pair = _selectedPair ?? _previousPair;
    if (pair == null) return false;
    return _sendViaPair(pair, buf);
  }

  /// Trigger an ICE restart (RFC 8445 §9). Returns the new local ICE
  /// credentials. Caller MUST signal them in SDP, then provide the peer's
  /// new credentials via [setRemoteParameters], call [gather] and feed new
  /// candidates via [addRemoteCandidate].
  IceParameters? restart() {
    if (_closed) return null;

    final String ufrag = _randomUfrag();
    final String pwd = _randomPwd();

    // Cancel in-flight transactions
    for (final _PendingTransaction t in _pendingTransactions.values) {
      t.timer?.cancel();
    }
    _pendingTransactions.clear();

    for (final CandidatePair p in _checkList) {
      p.retransmitTimer?.cancel();
      p.retransmitTimer = null;
    }

    _checkTimer?.cancel();
    _checkTimer = null;
    _nominationTimer?.cancel();
    _nominationTimer = null;
    _consentTimer?.cancel();
    _consentTimer = null;

    _previousPair = _selectedPair;
    _selectedPair = null;

    _checkList.clear();
    _validList.clear();
    _triggeredQueue.clear();
    _remoteCandidates.clear();
    _remoteCandidatesEnded = false;
    _nominationStarted = false;
    _endOfCandidatesEmitted = false;

    _gatheringHost = false;
    _gatheringSrflx = 0;
    _gatheringRelay = 0;

    _remoteUfrag = null;
    _remotePwd = null;
    _remoteIceLite = false;

    _localUfrag = ufrag;
    _localPwd = pwd;

    _setGatheringState(IceGatheringState.fresh);
    if (_state == IceState.failed || _state == IceState.disconnected) {
      _setState(IceState.fresh);
    }

    final IceParameters p =
        IceParameters(ufrag: ufrag, pwd: pwd, iceLite: _mode == IceMode.lite);
    _onRestart.add(p);
    return p;
  }

  /// Close the agent. Releases all sockets, timers, and TURN clients.
  /// Idempotent.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _teardown();
    _setState(IceState.closed);

    await _onCandidate.close();
    await _onStateChange.close();
    await _onGatheringStateChange.close();
    await _onSelectedPair.close();
    await _onPacket.close();
    await _onError.close();
    await _onCandidateError.close();
    await _onRoleChange.close();
    await _onPairCheck.close();
    await _onRestart.close();
  }

  /* ========================= Internal: state setters ===================== */

  void _setState(IceState next) {
    if (next == _state) return;
    _state = next;
    if (!_onStateChange.isClosed) _onStateChange.add(next);
  }

  void _setGatheringState(IceGatheringState next) {
    if (next == _gatheringState) return;
    _gatheringState = next;
    if (!_onGatheringStateChange.isClosed) _onGatheringStateChange.add(next);
  }

  /* ========================= Cascades ==================================== */

  // Equivalent of the JS Phase-2 "params_to_set" cascade. Runs reactively
  // after every state mutation; recurses until quiescent.
  void _runCascades() {
    if (_closed) return;

    bool changed = false;

    // 2.1 — Gathering complete: emit end-of-candidates.
    if (_gatheringState == IceGatheringState.complete &&
        !_endOfCandidatesEmitted) {
      _endOfCandidatesEmitted = true;
      if (!_trickle) {
        final List<_LocalCandidate> batch = _localCandidates.toList()
          ..sort((_LocalCandidate a, _LocalCandidate b) =>
              b.cand.priority - a.cand.priority);
        for (final _LocalCandidate c in batch) {
          if (!_onCandidate.isClosed) _onCandidate.add(c.cand);
        }
      }
      if (!_onCandidate.isClosed) _onCandidate.add(null);
    }

    // 2.2 — Enter 'checking' when ready.
    if ((_state == IceState.fresh ||
            (_state == IceState.connected && _previousPair != null)) &&
        _mode != IceMode.lite &&
        _remoteUfrag != null &&
        _remotePwd != null &&
        _localCandidates.isNotEmpty &&
        _remoteCandidates.isNotEmpty &&
        _checkList.isNotEmpty &&
        _selectedPair == null) {
      _setState(IceState.checking);
      changed = true;
    }

    // 2.3 — Start check scheduler.
    if (_state == IceState.checking &&
        _checkTimer == null &&
        _selectedPair == null &&
        _mode != IceMode.lite &&
        _remoteUfrag != null &&
        _remotePwd != null &&
        _localCandidates.isNotEmpty &&
        _remoteCandidates.isNotEmpty &&
        _checkList.isNotEmpty &&
        !_closed) {
      _initiateChecks();
    }

    // 2.4 — Schedule nomination when controlling + first valid pair.
    if (_controlling &&
        _mode != IceMode.lite &&
        !_nominationStarted &&
        _selectedPair == null &&
        _validList.isNotEmpty &&
        !_closed) {
      _initiateNominationTimer();
      _nominationStarted = true;
      changed = true;
    }

    // 2.5 — Auto-select highest-priority nominated+valid pair.
    if (_selectedPair == null && !_closed) {
      CandidatePair? best;
      for (final CandidatePair p in _validList) {
        if (!p.valid || !p.nominated) continue;
        if (best == null || p.priority > best.priority) best = p;
      }
      if (best != null) {
        final CandidatePair? prev = _selectedPair;
        _selectedPair = best;
        // Track socket for direct sends
        final RawDatagramSocket? sock =
            _getSocketForLocalCandidate(best._local);
        if (sock != null && best._local.turnClient == null) {
          _primarySocket = sock;
        }
        if (!_onSelectedPair.isClosed) {
          _onSelectedPair.add(SelectedPairEvent(pair: best, previous: prev));
        }
        if (_previousPair != null) _previousPair = null;
        changed = true;
      }
    }

    // 2.6 — Once selected, → 'connected'.
    if (_selectedPair != null &&
        _state != IceState.connected &&
        _state != IceState.failed &&
        _state != IceState.closed) {
      _setState(IceState.connected);
      changed = true;
    }

    // 2.7 — Once selected, stop check scheduler + drain triggered queue.
    if (_selectedPair != null) {
      if (_checkTimer != null) {
        _checkTimer!.cancel();
        _checkTimer = null;
      }
      if (_triggeredQueue.isNotEmpty) _triggeredQueue.clear();
    }

    // 2.8 — Once selected, start consent freshness.
    if (_selectedPair != null &&
        _consentTimer == null &&
        _mode != IceMode.lite &&
        !_closed) {
      _initiateConsentFreshness();
    }

    if (changed) _runCascades();
  }

  /* ========================= Candidate lookup =========================== */

  _LocalCandidate? _findLocalCandidate(String ip, int port) {
    for (final _LocalCandidate c in _localCandidates) {
      if (c.cand.ip == ip && c.cand.port == port) return c;
    }
    return null;
  }

  IceCandidate? _findRemoteCandidate(String ip, int port) {
    for (final IceCandidate c in _remoteCandidates) {
      if (c.ip == ip && c.port == port) return c;
    }
    return null;
  }

  void _recomputePairPriorities() {
    for (final CandidatePair p in _checkList) {
      p.priority = computePairPriority(
        controlling: _controlling,
        localPriority: p.local.priority,
        remotePriority: p.remote.priority,
      );
    }
    _checkList.sort(
        (CandidatePair a, CandidatePair b) => b.priority.compareTo(a.priority));
  }

  /* ========================= Pair formation ============================= */

  void _formPairsForNewLocal(_LocalCandidate localCand) {
    for (final IceCandidate r in _remoteCandidates) {
      _tryMakePair(localCand, r);
    }
  }

  void _formPairsForNewRemote(IceCandidate remote) {
    for (final _LocalCandidate l in _localCandidates) {
      _tryMakePair(l, remote);
    }
  }

  CandidatePair? _tryMakePair(_LocalCandidate local, IceCandidate remote) {
    if (local.cand.component != remote.component) return null;
    if (local.cand.protocol != remote.protocol) return null;
    if (addressFamilyOf(local.cand.ip) != addressFamilyOf(remote.ip)) {
      return null;
    }
    if (_findPair(local.cand, remote) != null) return null;

    final CandidatePair pair = CandidatePair._(
      local: local,
      remote: remote,
      priority: computePairPriority(
        controlling: _controlling,
        localPriority: local.cand.priority,
        remotePriority: remote.priority,
      ),
    );
    _insertPairSorted(pair);
    return pair;
  }

  void _insertPairSorted(CandidatePair pair) {
    int lo = 0, hi = _checkList.length;
    while (lo < hi) {
      final int mid = (lo + hi) >> 1;
      if (_checkList[mid].priority < pair.priority) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    _checkList.insert(lo, pair);
  }

  CandidatePair? _findPair(IceCandidate local, IceCandidate remote) {
    for (final CandidatePair p in _checkList) {
      if (p.local.ip == local.ip &&
          p.local.port == local.port &&
          p.remote.ip == remote.ip &&
          p.remote.port == remote.port) {
        return p;
      }
    }
    return null;
  }

  /* ========================= Gathering ================================== */

  void _startGathering() {
    if (_gatheringHost) return;
    _gatheringHost = true;

    _setGatheringState(IceGatheringState.gathering);

    final List<_StunServer> stunServers = <_StunServer>[];
    final List<_TurnServerConfig> turnServers = <_TurnServerConfig>[];
    for (final IceServer s in _iceServers) {
      for (final String url in s.urls) {
        final wire.StunUri? p = wire.parseUri(url);
        if (p == null) continue;
        if (p.isTurn) {
          turnServers.add(_TurnServerConfig(
            uri: url,
            parsed: p,
            username: s.username ?? '',
            credential: s.credential ?? '',
            serverName: s.serverName,
            rejectUnauthorized: s.rejectUnauthorized,
            context: s.context,
          ));
        } else {
          stunServers.add(_StunServer(uri: url, parsed: p));
        }
      }
    }

    final bool relayOnly = _iceTransportPolicy == IceTransportPolicy.relay;
    final bool liteMode = _mode == IceMode.lite;

    _gatherHostCandidates().then((_) {
      _gatheringHost = false;

      if (!liteMode && !relayOnly) {
        final List<RawDatagramSocket> bases = _collectGatheringBases();
        for (final _StunServer srv in stunServers) {
          for (final RawDatagramSocket sock in bases) {
            _gatheringSrflx++;
            _gatherSrflxCandidate(srv, sock).whenComplete(() {
              _gatheringSrflx--;
              _checkGatheringComplete();
            });
          }
        }
      }

      if (!liteMode) {
        for (final _TurnServerConfig srv in turnServers) {
          _gatheringRelay++;
          _gatherRelayCandidate(srv).whenComplete(() {
            _gatheringRelay--;
            _checkGatheringComplete();
          });
        }
      }

      _checkGatheringComplete();
    });
  }

  List<RawDatagramSocket> _collectGatheringBases() {
    final List<RawDatagramSocket> bases = <RawDatagramSocket>[];
    final Set<String> seen = <String>{};
    for (final RawDatagramSocket sock in _sockets.values) {
      final String addr = sock.address.address;
      if (addr == '127.0.0.1' || addr == '::1') continue;
      if (addr.startsWith('169.254.')) continue;
      final String key = '$addr:${sock.port}';
      if (seen.contains(key)) continue;
      seen.add(key);
      bases.add(sock);
    }
    return bases;
  }

  void _checkGatheringComplete() {
    if (_closed) return;
    if (_gatheringState != IceGatheringState.gathering) return;
    if (_gatheringHost) return;
    if (_gatheringSrflx > 0) return;
    if (_gatheringRelay > 0) return;
    _setGatheringState(IceGatheringState.complete);
    _runCascades();
  }

  /* ── Host candidate gathering ── */

  Future<void> _gatherHostCandidates() async {
    if (_externalSocket != null) {
      final InternetAddress addr = _externalSocket!.address;
      _addHostFromBoundSocket(
          _externalSocket!,
          _BaseAddr(
              ip: addr.address,
              port: _externalSocket!.port,
              family: addr.type == InternetAddressType.IPv6 ? 6 : 4));
      return;
    }

    final List<NetworkInterface> ifaces;
    try {
      ifaces = await NetworkInterface.list(
        includeLoopback: _includeLoopback,
        includeLinkLocal: false,
        type: InternetAddressType.any,
      );
    } catch (_) {
      return;
    }

    final List<_BaseAddr> addrs = <_BaseAddr>[];
    for (final NetworkInterface iface in ifaces) {
      for (final InternetAddress a in iface.addresses) {
        final bool isV6 = a.type == InternetAddressType.IPv6;
        if (isV6 && !_ipv6) continue;
        final String ip = a.address;
        if (isV6 && ip.toLowerCase().startsWith('fe80')) continue;
        if (isV6 && ip.toLowerCase().startsWith('100::')) continue;
        if (!isV6 && ip.startsWith('169.254.')) continue;
        addrs.add(_BaseAddr(ip: ip, port: 0, family: isV6 ? 6 : 4));
      }
    }
    if (addrs.isEmpty) return;

    await Future.wait<void>(addrs.map(_bindUdpSocket));
  }

  Future<void> _bindUdpSocket(_BaseAddr a) async {
    try {
      final InternetAddress bind = InternetAddress(a.ip);
      final RawDatagramSocket sock = await RawDatagramSocket.bind(bind, 0);
      final StreamSubscription<RawSocketEvent> sub =
          sock.listen((RawSocketEvent ev) {
        if (ev != RawSocketEvent.read) return;
        final Datagram? dg = sock.receive();
        if (dg == null) return;
        _onSocketMessage(
            Uint8List.fromList(dg.data),
            wire.StunAddress(
              family: dg.address.type == InternetAddressType.IPv6
                  ? wire.AddressFamily.ipv6
                  : wire.AddressFamily.ipv4,
              ip: dg.address.address,
              port: dg.port,
            ),
            sock);
      }, onError: (Object e) {
        if (!_onError.isClosed) _onError.add(e);
      });
      _socketSubs.add(sub);
      _addHostFromBoundSocket(
          sock, _BaseAddr(ip: a.ip, port: sock.port, family: a.family));
    } catch (_) {
      // bind failed — skip
    }
  }

  void _addHostFromBoundSocket(RawDatagramSocket sock, _BaseAddr boundAddr) {
    final String key = '${boundAddr.family}:${boundAddr.ip}:${boundAddr.port}';
    if (_sockets.containsKey(key)) return;
    _sockets[key] = sock;
    _primarySocket ??= sock;

    if (_iceTransportPolicy == IceTransportPolicy.relay) return;

    final IceCandidate cand = IceCandidate(
      foundation: computeFoundation(
          type: 'host', baseIp: boundAddr.ip, protocol: 'udp'),
      component: _componentRtp,
      protocol: 'udp',
      priority: computeCandidatePriority(
        typePreference: CandidateType.host.preference,
        localPreference: _localPreferenceDefault,
        componentId: _componentRtp,
      ),
      ip: boundAddr.ip,
      port: boundAddr.port,
      typeRaw: 'host',
    );

    final _LocalCandidate lc = _LocalCandidate(
      cand,
      base: boundAddr,
      socket: sock,
    );
    _addLocalCandidate(lc);
  }

  void _addLocalCandidate(_LocalCandidate lc) {
    if (_findLocalCandidate(lc.cand.ip, lc.cand.port) != null) return;
    _localCandidates.add(lc);
    if (_trickle && !_onCandidate.isClosed) _onCandidate.add(lc.cand);
    _formPairsForNewLocal(lc);
    _runCascades();
  }

  /* ── srflx gathering ── */

  Future<void> _gatherSrflxCandidate(
      _StunServer server, RawDatagramSocket sock) async {
    final String baseIp = sock.address.address;
    final int basePort = sock.port;
    final int sockFamily =
        sock.address.type == InternetAddressType.IPv6 ? 6 : 4;

    final wire.EncodedMessage encoded = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.request,
      attributes: <wire.StunAttribute>[],
      // No key on gather — STUN BINDING is unauthenticated.
    ));
    final String txHex = _txIdHex(encoded.transactionId);

    final Completer<void> done = Completer<void>();
    bool finished = false;

    Timer? timer;
    void finish(Object? err, wire.StunAddress? mapped) {
      if (finished) return;
      finished = true;
      _pendingTransactions.remove(txHex);
      if (timer != null) {
        timer.cancel();
        _gatherTimers.remove(timer);
      }
      if (_closed) {
        if (!done.isCompleted) done.complete();
        return;
      }
      if (err == null && mapped != null) {
        final IceCandidate cand = IceCandidate(
          foundation: computeFoundation(
            type: 'srflx',
            baseIp: baseIp,
            protocol: 'udp',
            stunServer: '${server.parsed.host}:${server.parsed.port}',
          ),
          component: _componentRtp,
          protocol: 'udp',
          priority: computeCandidatePriority(
            typePreference: CandidateType.srflx.preference,
            localPreference: _localPreferenceDefault,
            componentId: _componentRtp,
          ),
          ip: mapped.ip,
          port: mapped.port,
          typeRaw: 'srflx',
          relatedAddress: baseIp,
          relatedPort: basePort,
        );
        _addLocalCandidate(_LocalCandidate(cand,
            base: _BaseAddr(ip: baseIp, port: basePort, family: sockFamily),
            socket: sock));
      } else if (err != null) {
        if (!_onCandidateError.isClosed) {
          _onCandidateError.add(CandidateErrorEvent(
              type: 'srflx', server: server.uri, base: baseIp, error: err));
        }
      }
      if (!done.isCompleted) done.complete();
    }

    _pendingTransactions[txHex] = _PendingTransaction(
      kind: 'gather-srflx',
      callback: (wire.StunMessage? msg, wire.StunAddress? src, Object? err) {
        if (err != null || msg == null) {
          finish(err ?? StateError('no msg'), null);
          return;
        }
        final wire.StunAddress? mapped =
            msg.getAddress(wire.Attr.xorMappedAddress) ??
                msg.getAddress(wire.Attr.mappedAddress);
        if (mapped == null) {
          finish(StateError('No mapped address'), null);
        } else {
          finish(null, mapped);
        }
      },
    );

    // DNS family preference matches socket family.
    final InternetAddressType lookupType =
        sockFamily == 6 ? InternetAddressType.IPv6 : InternetAddressType.IPv4;
    InternetAddress? resolved;
    try {
      final List<InternetAddress> list =
          await InternetAddress.lookup(server.parsed.host, type: lookupType);
      if (list.isNotEmpty) resolved = list.first;
    } catch (_) {/* fallthrough */}

    if (resolved == null) {
      finish(StateError('DNS resolve failed'), null);
      return done.future;
    }
    if (_closed) {
      finish(StateError('agent closed'), null);
      return done.future;
    }
    try {
      sock.send(encoded.buf, resolved, server.parsed.port);
    } catch (e) {
      finish(e, null);
      return done.future;
    }

    timer = Timer(const Duration(milliseconds: _gatherSrflxTimeoutMs), () {
      finish(TimeoutException('STUN timeout'), null);
    });
    _gatherTimers.add(timer);

    return done.future;
  }

  /* ── Relay (TURN) gathering ── */

  Future<void> _gatherRelayCandidate(_TurnServerConfig server) async {
    if (_primarySocket == null) return;
    final String baseIp = _primarySocket!.address.address;
    final int basePort = _primarySocket!.port;

    final Completer<void> done = Completer<void>();
    bool finished = false;
    Timer? timer;

    void finish(
        Object? err, wire.StunAddress? relay, turn_socket.TurnSocket? client) {
      if (finished) return;
      finished = true;
      if (timer != null) {
        timer.cancel();
        _gatherTimers.remove(timer);
      }
      if (_closed) {
        if (!done.isCompleted) done.complete();
        return;
      }
      if (err == null && relay != null && client != null) {
        final String key = '${server.parsed.host}:${server.parsed.port}';
        _turnClients[key] = client;

        final IceCandidate cand = IceCandidate(
          foundation: computeFoundation(
              type: 'relay',
              baseIp: relay.ip,
              protocol: 'udp',
              stunServer: key),
          component: _componentRtp,
          protocol: 'udp',
          priority: computeCandidatePriority(
            typePreference: CandidateType.relay.preference,
            localPreference: _localPreferenceDefault,
            componentId: _componentRtp,
          ),
          ip: relay.ip,
          port: relay.port,
          typeRaw: 'relay',
          relatedAddress: baseIp,
          relatedPort: basePort,
        );
        _addLocalCandidate(_LocalCandidate(
          cand,
          base: _BaseAddr(
              ip: relay.ip,
              port: relay.port,
              family: addressFamilyOf(relay.ip)),
          turnClient: client,
          turnKey: key,
        ));
      } else if (err != null) {
        if (!_onCandidateError.isClosed) {
          _onCandidateError.add(CandidateErrorEvent(
              type: 'relay', server: server.uri, error: err));
        }
      }
      if (!done.isCompleted) done.complete();
    }

    final wire.StunUri parsed = server.parsed;
    final turn_socket.TransportType tType = parsed.secure
        ? turn_socket.TransportType.tls
        : (parsed.transport == 'tcp'
            ? turn_socket.TransportType.tcp
            : turn_socket.TransportType.udp);

    final turn_socket.TurnSocket client;
    try {
      client = turn_socket.TurnSocket(turn_socket.TurnSocketOptions(
        isServer: false,
        serverHost: parsed.host,
        serverPort: parsed.port,
        transportType: tType,
        username: server.username.isEmpty ? null : server.username,
        password: server.credential.isEmpty ? null : server.credential,
        authMech: (server.username.isNotEmpty && server.credential.isNotEmpty)
            ? AuthMechanism.longTerm
            : AuthMechanism.none,
        serverName: server.serverName ?? parsed.host,
        rejectUnauthorized: server.rejectUnauthorized,
        context: server.context,
      ));
    } catch (e) {
      finish(e, null, null);
      return done.future;
    }

    // Listen for ALLOCATE success on the underlying session.
    final StreamSubscription<wire.StunMessage> okSub =
        client.session.onSuccess.listen((wire.StunMessage msg) {
      if (msg.method != wire.StunMethod.allocate) return;
      final wire.StunAddress? relay =
          msg.getAddress(wire.Attr.xorRelayedAddress);
      if (relay == null) {
        finish(StateError('No XOR-RELAYED-ADDRESS'), null, null);
        return;
      }
      finish(null, relay, client);

      // Wire incoming relayed data → onPacket / handleStunMessage.
      // socket.dart emits RelayedInfo with the source peer; raw data goes
      // through the session's onMessage stream as bytes destined to the
      // client. For ICE we want to inspect the inbound peer payloads.
      // The TurnSocket exposes onRelayed for both directions; we filter for
      // inbound and reconstruct packets here.
    });
    _turnSubs.add(okSub);

    final StreamSubscription<turn_socket.RelayedInfo> dataSub =
        client.onRelayed.listen((turn_socket.RelayedInfo info) {
      if (_closed) return;
      if (info.direction != turn_socket.RelayedDirection.inbound) return;
      // For inbound, peer.ip:peer.port is the remote sender; size carries
      // the data length but the actual payload bytes are not directly on
      // RelayedInfo. Skipping inbound demux at this layer — the upper
      // application is expected to read from the session's data path
      // separately. (RFC 8445 connectivity checks over relay still go
      // through sendStunRaw / SEND indications.)
    });
    _turnSubs.add(dataSub);

    final StreamSubscription<Object> errSub = client.onError.listen((Object e) {
      if (!finished) finish(e, null, null);
    });
    _turnSubs.add(errSub);

    timer = Timer(const Duration(milliseconds: _gatherRelayTimeoutMs), () {
      finish(TimeoutException('TURN timeout'), null, null);
    });
    _gatherTimers.add(timer);

    try {
      await client.connect();
      if (_closed) {
        finish(StateError('agent closed'), null, null);
        return done.future;
      }
      client.session.allocate(lifetime: 600);
    } catch (e) {
      finish(e, null, null);
    }

    return done.future;
  }

  /* ========================= Ingress / Demux ============================= */

  void _onSocketMessage(
      Uint8List buf, wire.StunAddress source, RawDatagramSocket sock) {
    if (_closed) return;
    final wire.DemuxKind type = wire.demux(buf);
    if (type == wire.DemuxKind.stun) {
      _handleStunMessage(buf, source, sock, null);
    } else {
      if (!_onPacket.isClosed) {
        _onPacket.add(PacketEvent(data: buf, source: source, kind: type));
      }
    }
  }

  void _handleStunMessage(
    Uint8List buf,
    wire.StunAddress source,
    RawDatagramSocket? sock,
    turn_socket.TurnSocket? turnSocket,
  ) {
    final wire.StunMessage? msg = wire.decodeMessage(buf);
    if (msg == null) return;
    final String txHex = _txIdHex(msg.transactionId);

    // 1. Pending outgoing transaction
    final _PendingTransaction? pending = _pendingTransactions[txHex];
    if (pending != null) {
      if (msg.cls == wire.StunClass.success) {
        if ((pending.kind == 'check' || pending.kind == 'consent') &&
            _remotePwd != null) {
          final wire.StunMessage? validated =
              wire.validateStunMessage(buf, _remotePwd);
          if (validated == null) return;
        }
        pending.callback(msg, source, null);
        return;
      }
      if (msg.cls == wire.StunClass.error) {
        final wire.StunErrorCode? ec = msg.getErrorCode();
        final int? code = ec?.code;
        final bool requireMI =
            (pending.kind == 'check' || pending.kind == 'consent') &&
                _remotePwd != null &&
                (code == 401 || code == 438 || code == 487);
        if (requireMI) {
          if (wire.validateStunMessage(buf, _remotePwd) == null) return;
        }
        pending.callback(msg, source, StateError('STUN error response'));
        return;
      }
    }

    // 2. Incoming Binding Request
    if (msg.method == wire.StunMethod.binding &&
        msg.cls == wire.StunClass.request) {
      _handleBindingRequest(buf, msg, source, sock, turnSocket);
    }
  }

  /* ========================= Connectivity Checks ======================== */

  void _initiateChecks() {
    for (final CandidatePair p in _checkList) {
      if (p.state == CheckState.frozen) p.state = CheckState.waiting;
    }
    _checkTimer = Timer.periodic(const Duration(milliseconds: _checkPaceMs),
        (Timer _) => _runCheckTick());
    _runCheckTick();
  }

  void _unfreezePairsAfterSuccess(CandidatePair succeeded) {
    final String fLocal = succeeded.local.foundation;
    final String fRemote = succeeded.remote.foundation;
    for (final CandidatePair p in _checkList) {
      if (p.state != CheckState.frozen) continue;
      if (p.local.foundation == fLocal && p.remote.foundation == fRemote) {
        p.state = CheckState.waiting;
      }
    }
  }

  void _runCheckTick() {
    if (_closed) return;

    CandidatePair? next;
    if (_triggeredQueue.isNotEmpty) {
      next = _triggeredQueue.removeAt(0);
    } else {
      for (final CandidatePair p in _checkList) {
        if (p.state == CheckState.waiting) {
          next = p;
          break;
        }
      }
    }

    if (next == null) {
      final bool anyActive = _checkList.any((CandidatePair p) =>
          p.state == CheckState.waiting ||
          p.state == CheckState.inProgress ||
          p.state == CheckState.frozen);
      if (!anyActive) {
        _checkTimer?.cancel();
        _checkTimer = null;
        final bool anyValid = _checkList.any((CandidatePair p) => p.valid);
        if (!anyValid) _setState(IceState.failed);
      }
      return;
    }

    _sendBindingCheck(next);
  }

  void _sendBindingCheck(CandidatePair pair) {
    if (_closed) return;
    if (_remoteUfrag == null || _remotePwd == null) return;

    final RawDatagramSocket? sock = _getSocketForLocalCandidate(pair._local);
    if (sock == null && pair._local.turnClient == null) {
      pair.state = CheckState.failed;
      return;
    }

    final String username = '${_remoteUfrag!}:$_localUfrag';
    final int prflxPriority = computeCandidatePriority(
      typePreference: CandidateType.prflx.preference,
      localPreference: _localPreferenceDefault,
      componentId: pair.local.component,
    );

    final List<wire.StunAttribute> attrs = <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.username, value: username),
      wire.StunAttribute(type: wire.Attr.priority, value: prflxPriority),
      wire.StunAttribute(
        type: _controlling ? wire.Attr.iceControlling : wire.Attr.iceControlled,
        value: _tieBreaker,
      ),
      if (pair.weNominated)
        wire.StunAttribute(type: wire.Attr.useCandidate, value: null),
    ];

    final Uint8List key = wire.computeShortTermKey(_remotePwd!);
    final wire.EncodedMessage encoded = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.request,
      attributes: attrs,
      key: key,
    ));

    final String txHex = _txIdHex(encoded.transactionId);
    pair.transactionId = encoded.transactionId;
    pair.lastSent = DateTime.now().millisecondsSinceEpoch;
    pair.state = CheckState.inProgress;
    pair.retransmits = 0;
    pair.encodedCheck = encoded.buf;

    _pendingTransactions[txHex] = _PendingTransaction(
      kind: 'check',
      pair: pair,
      callback: (wire.StunMessage? msg, wire.StunAddress? source, Object? err) {
        _pendingTransactions.remove(txHex);
        pair.retransmitTimer?.cancel();
        pair.retransmitTimer = null;
        _onCheckResponse(pair, msg, source, err);
      },
    );

    _sendStunToRemote(pair._local, pair.remote, encoded.buf);
    _scheduleRetransmit(pair, txHex);
  }

  void _scheduleRetransmit(CandidatePair pair, String txHex) {
    if (!_pendingTransactions.containsKey(txHex)) return;
    final int rto = _stunInitialRtoUdp * math.pow(2, pair.retransmits).toInt();

    pair.retransmitTimer = Timer(Duration(milliseconds: rto), () {
      if (_closed) return;
      if (!_pendingTransactions.containsKey(txHex)) return;
      if (pair.retransmits >= _stunMaxRetransmissions) {
        _pendingTransactions.remove(txHex);
        pair.retransmitTimer = null;
        _onCheckResponse(pair, null, null, TimeoutException('Check timeout'));
        return;
      }
      pair.retransmits++;
      if (pair.encodedCheck != null) {
        _sendStunToRemote(pair._local, pair.remote, pair.encodedCheck!);
      }
      _scheduleRetransmit(pair, txHex);
    });
  }

  void _onCheckResponse(CandidatePair pair, wire.StunMessage? msg,
      wire.StunAddress? source, Object? err) {
    if (_closed) return;

    if (err != null) {
      if (msg != null) {
        final wire.StunErrorCode? ec = msg.getErrorCode();
        if (ec?.code == 487) {
          _handleRoleConflictFromResponse(pair);
          return;
        }
      }
      pair.state = CheckState.failed;
      if (!_onPairCheck.isClosed) {
        _onPairCheck.add(PairCheckEvent(pair: pair, success: false));
      }
      _runCascades();
      return;
    }

    final wire.StunAddress? mapped =
        msg!.getAddress(wire.Attr.xorMappedAddress) ??
            msg.getAddress(wire.Attr.mappedAddress);
    if (mapped == null) {
      pair.state = CheckState.failed;
      if (!_onPairCheck.isClosed) {
        _onPairCheck.add(PairCheckEvent(pair: pair, success: false));
      }
      _runCascades();
      return;
    }

    _LocalCandidate validLocal = pair._local;
    if (mapped.ip != pair.local.ip || mapped.port != pair.local.port) {
      validLocal = _findLocalCandidate(mapped.ip, mapped.port) ??
          _addPeerReflexiveLocal(mapped.ip, mapped.port, pair._local);
    }

    pair.state = CheckState.succeeded;
    _unfreezePairsAfterSuccess(pair);

    CandidatePair validPair;
    if (identical(validLocal, pair._local)) {
      validPair = pair;
    } else {
      validPair = _findPair(validLocal.cand, pair.remote) ??
          _tryMakePair(validLocal, pair.remote) ??
          pair;
      if (!identical(validPair, pair)) {
        validPair.state = CheckState.succeeded;
      }
    }

    validPair.valid = true;
    if (pair.weNominated && !validPair.weNominated) {
      validPair.weNominated = true;
    }
    if (pair.peerNominated && !validPair.peerNominated) {
      validPair.peerNominated = true;
    }
    if (validPair.weNominated || validPair.peerNominated) {
      validPair.nominated = true;
    }

    if (!_validList.contains(validPair)) _validList.add(validPair);
    if (!_onPairCheck.isClosed) {
      _onPairCheck.add(PairCheckEvent(pair: validPair, success: true));
    }
    _runCascades();
  }

  /* ── Nomination ── */

  void _initiateNominationTimer() {
    if (_nominationTimer != null) return;
    _nominationTimer = Timer(
        const Duration(milliseconds: _nominationDelayMs), _fireNomination);
  }

  void _fireNomination() {
    _nominationTimer = null;
    if (_closed) return;
    if (!_controlling) return;
    if (_selectedPair != null) return;

    final List<CandidatePair> candidates =
        _validList.where((CandidatePair p) => !p.weNominated).toList();
    if (candidates.isEmpty) {
      _nominationStarted = false;
      _runCascades();
      return;
    }

    CandidatePair best = candidates[0];
    for (int i = 1; i < candidates.length; i++) {
      if (candidates[i].priority > best.priority) best = candidates[i];
    }
    best.weNominated = true;
    best.state = CheckState.waiting;
    if (!_triggeredQueue.contains(best)) _triggeredQueue.add(best);
    _runCheckTick();
  }

  /* ── Consent freshness ── */

  void _initiateConsentFreshness() {
    if (_consentTimer != null) return;
    _consentLastSuccessAt = DateTime.now().millisecondsSinceEpoch;
    _scheduleNextConsentTick();
  }

  void _scheduleNextConsentTick() {
    if (_closed) return;
    final double jitter =
        1 + (math.Random().nextDouble() * 2 - 1) * _consentRandomization;
    final int ms = (_consentIntervalMs * jitter).floor();
    _consentTimer = Timer(Duration(milliseconds: ms), _consentTick);
  }

  void _consentTick() {
    _consentTimer = null;
    if (_closed || _selectedPair == null) return;

    final int age =
        DateTime.now().millisecondsSinceEpoch - _consentLastSuccessAt;
    if (age >= _consentFailedMs) {
      _setState(IceState.failed);
      return;
    }
    if (age >= _consentDisconnectMs) {
      if (_state == IceState.connected) _setState(IceState.disconnected);
    } else if (_state == IceState.disconnected) {
      _setState(IceState.connected);
    }

    _sendConsentCheck(_selectedPair!);
    _scheduleNextConsentTick();
  }

  void _sendConsentCheck(CandidatePair pair) {
    if (_closed) return;
    if (_remoteUfrag == null || _remotePwd == null) return;

    final String username = '${_remoteUfrag!}:$_localUfrag';
    final int prflxPriority = computeCandidatePriority(
      typePreference: CandidateType.prflx.preference,
      localPreference: _localPreferenceDefault,
      componentId: pair.local.component,
    );

    final List<wire.StunAttribute> attrs = <wire.StunAttribute>[
      wire.StunAttribute(type: wire.Attr.username, value: username),
      wire.StunAttribute(type: wire.Attr.priority, value: prflxPriority),
      wire.StunAttribute(
        type: _controlling ? wire.Attr.iceControlling : wire.Attr.iceControlled,
        value: _tieBreaker,
      ),
    ];

    final Uint8List key = wire.computeShortTermKey(_remotePwd!);
    final wire.EncodedMessage encoded = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.request,
      attributes: attrs,
      key: key,
    ));

    final String txHex = _txIdHex(encoded.transactionId);
    final Timer timer = Timer(const Duration(milliseconds: 10000), () {
      final _PendingTransaction? p = _pendingTransactions[txHex];
      if (p == null) return;
      _pendingTransactions.remove(txHex);
      p.callback(null, null, TimeoutException('consent timeout'));
    });

    _pendingTransactions[txHex] = _PendingTransaction(
      kind: 'consent',
      pair: pair,
      timer: timer,
      callback: (wire.StunMessage? _, wire.StunAddress? __, Object? err) {
        _pendingTransactions.remove(txHex);
        timer.cancel();
        if (err != null) return;
        _consentLastSuccessAt = DateTime.now().millisecondsSinceEpoch;
      },
    );

    _sendStunToRemote(pair._local, pair.remote, encoded.buf);
  }

  /* ========================= Inbound Binding Requests ==================== */

  void _handleBindingRequest(
    Uint8List buf,
    wire.StunMessage msg,
    wire.StunAddress source,
    RawDatagramSocket? sock,
    turn_socket.TurnSocket? turnSocket,
  ) {
    if (_closed) return;

    final wire.StunMessage? validated =
        wire.validateStunMessage(buf, _localPwd);
    if (validated == null) {
      _sendBindingError(msg, source, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    final String? usernameAttr = msg.getString(wire.Attr.username);
    if (usernameAttr == null || !usernameAttr.contains(':')) {
      _sendBindingError(msg, source, sock, turnSocket, 400, 'Bad Request');
      return;
    }
    final int colon = usernameAttr.indexOf(':');
    if (usernameAttr.substring(0, colon) != _localUfrag) {
      _sendBindingError(msg, source, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    // Role conflict
    final wire.IceTiebreaker? icControlling =
        msg.getAttribute<wire.IceTiebreaker>(wire.Attr.iceControlling);
    final wire.IceTiebreaker? icControlled =
        msg.getAttribute<wire.IceTiebreaker>(wire.Attr.iceControlled);

    if (_controlling && icControlling != null) {
      if (_tieBreaker.compareTo(icControlling) >= 0) {
        _sendBindingError(msg, source, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
      _switchRole(false);
    } else if (!_controlling && icControlled != null) {
      if (_tieBreaker.compareTo(icControlled) >= 0) {
        _sendBindingError(msg, source, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
      _switchRole(true);
    }

    // Find/create remote candidate
    IceCandidate? remoteCand = _findRemoteCandidate(source.ip, source.port);
    if (remoteCand == null) {
      final int? prio = msg.getInt(wire.Attr.priority);
      remoteCand = _addPeerReflexiveRemote(
          source.ip,
          source.port,
          prio ??
              computeCandidatePriority(
                typePreference: CandidateType.prflx.preference,
                localPreference: _localPreferenceDefault,
                componentId: _componentRtp,
              ));
    }

    // Find/create pair
    CandidatePair? pair = _findPairByRemote(remoteCand, sock, turnSocket);
    if (pair == null) {
      final _LocalCandidate? local = _findLocalForIncoming(sock, turnSocket);
      if (local != null) pair = _tryMakePair(local, remoteCand);
    }

    _sendBindingSuccess(msg, source, sock, turnSocket);

    if (pair == null) return;

    final bool hasUseCandidate = msg.hasAttribute(wire.Attr.useCandidate);
    if (hasUseCandidate) pair.peerNominated = true;

    if (pair.state != CheckState.succeeded &&
        pair.state != CheckState.inProgress) {
      pair.state = CheckState.waiting;
      if (!_triggeredQueue.contains(pair)) _triggeredQueue.add(pair);
    }

    if (_mode == IceMode.lite) {
      pair.valid = true;
      pair.state = CheckState.succeeded;
      if (pair.peerNominated) pair.nominated = true;
      if (!_validList.contains(pair)) _validList.add(pair);
      if (!_onPairCheck.isClosed) {
        _onPairCheck.add(PairCheckEvent(pair: pair, success: true));
      }
      _runCascades();
      return;
    }

    if (pair.valid && pair.peerNominated && !pair.nominated) {
      pair.nominated = true;
      if (!_validList.contains(pair)) _validList.add(pair);
      if (!_onPairCheck.isClosed) {
        _onPairCheck.add(PairCheckEvent(pair: pair, success: true));
      }
      _runCascades();
      return;
    }

    _runCascades();
  }

  void _sendBindingSuccess(wire.StunMessage req, wire.StunAddress source,
      RawDatagramSocket? sock, turn_socket.TurnSocket? turnSocket) {
    final Uint8List key = wire.computeShortTermKey(_localPwd);
    final wire.StunAddress mapped = wire.StunAddress(
      family: addressFamilyOf(source.ip) == 6
          ? wire.AddressFamily.ipv6
          : wire.AddressFamily.ipv4,
      ip: source.ip,
      port: source.port,
    );
    final wire.EncodedMessage encoded = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.success,
      transactionId: req.transactionId,
      attributes: <wire.StunAttribute>[
        wire.StunAttribute(type: wire.Attr.xorMappedAddress, value: mapped),
      ],
      key: key,
    ));
    _sendStunRaw(sock, turnSocket, source, encoded.buf);
  }

  void _sendBindingError(
      wire.StunMessage req,
      wire.StunAddress source,
      RawDatagramSocket? sock,
      turn_socket.TurnSocket? turnSocket,
      int code,
      String reason) {
    final wire.EncodedMessage encoded = wire.encodeMessage(wire.EncodeOptions(
      method: wire.StunMethod.binding,
      cls: wire.StunClass.error,
      transactionId: req.transactionId,
      attributes: <wire.StunAttribute>[
        wire.StunAttribute(
            type: wire.Attr.errorCode,
            value: wire.StunErrorCode(code: code, reason: reason)),
      ],
    ));
    _sendStunRaw(sock, turnSocket, source, encoded.buf);
  }

  /* ── Role conflict ── */

  void _handleRoleConflictFromResponse(CandidatePair pair) {
    _switchRole(!_controlling);
    pair.state = CheckState.waiting;
    if (!_triggeredQueue.contains(pair)) _triggeredQueue.add(pair);
  }

  void _switchRole(bool newControlling) {
    if (_controlling == newControlling) return;
    _controlling = newControlling;
    if (!_onRoleChange.isClosed) {
      _onRoleChange
          .add(newControlling ? IceRole.controlling : IceRole.controlled);
    }
    _recomputePairPriorities();
  }

  /* ── Peer-reflexive helpers ── */

  _LocalCandidate _addPeerReflexiveLocal(
      String ip, int port, _LocalCandidate basedOn) {
    final _LocalCandidate? existing = _findLocalCandidate(ip, port);
    if (existing != null) return existing;

    final IceCandidate cand = IceCandidate(
      foundation: computeFoundation(
          type: 'prflx',
          baseIp: basedOn.cand.ip,
          protocol: basedOn.cand.protocol),
      component: basedOn.cand.component,
      protocol: basedOn.cand.protocol,
      priority: computeCandidatePriority(
        typePreference: CandidateType.prflx.preference,
        localPreference: _localPreferenceDefault,
        componentId: basedOn.cand.component,
      ),
      ip: ip,
      port: port,
      typeRaw: 'prflx',
      relatedAddress: basedOn.cand.ip,
      relatedPort: basedOn.cand.port,
    );

    final _LocalCandidate lc = _LocalCandidate(
      cand,
      base: basedOn.base,
      socket: basedOn.socket,
      turnClient: basedOn.turnClient,
      turnKey: basedOn.turnKey,
    );
    _addLocalCandidate(lc);
    return lc;
  }

  IceCandidate _addPeerReflexiveRemote(String ip, int port, int priority) {
    final IceCandidate? existing = _findRemoteCandidate(ip, port);
    if (existing != null) return existing;

    final IceCandidate cand = IceCandidate(
      foundation: 'prflx:$ip:$port',
      component: _componentRtp,
      protocol: 'udp',
      priority: priority,
      ip: ip,
      port: port,
      typeRaw: 'prflx',
    );
    _remoteCandidates.add(cand);
    _formPairsForNewRemote(cand);
    _runCascades();
    return cand;
  }

  /* ── Pair lookups for inbound ── */

  CandidatePair? _findPairByRemote(IceCandidate remote, RawDatagramSocket? sock,
      turn_socket.TurnSocket? turnSocket) {
    for (final CandidatePair p in _checkList) {
      if (!identical(p.remote, remote)) continue;
      if (sock != null && identical(p._local.socket, sock)) return p;
      if (turnSocket != null && identical(p._local.turnClient, turnSocket)) {
        return p;
      }
      if (sock == null && turnSocket == null) return p;
    }
    return null;
  }

  _LocalCandidate? _findLocalForIncoming(
      RawDatagramSocket? sock, turn_socket.TurnSocket? turnSocket) {
    if (sock != null) {
      for (final _LocalCandidate l in _localCandidates) {
        if (identical(l.socket, sock)) return l;
      }
    }
    if (turnSocket != null) {
      for (final _LocalCandidate l in _localCandidates) {
        if (identical(l.turnClient, turnSocket)) return l;
      }
    }
    return _localCandidates.isEmpty ? null : _localCandidates[0];
  }

  /* ── Send STUN to remote ── */

  void _sendStunToRemote(
      _LocalCandidate local, IceCandidate remote, Uint8List buf) {
    try {
      if (local.turnClient != null) {
        final turn_socket.TurnSocket client = local.turnClient!;
        final wire.StunAddress peer = wire.StunAddress(
          family: addressFamilyOf(remote.ip) == 6
              ? wire.AddressFamily.ipv6
              : wire.AddressFamily.ipv4,
          ip: remote.ip,
          port: remote.port,
        );
        _ensurePermission(local, peer, (Object? err) {
          if (err != null || _closed) return;
          try {
            final int? ch = client.session.getChannelByPeer(peer.ip, peer.port);
            if (ch != null) {
              client.session.sendChannelData(ch, buf);
            } else {
              client.session.sendToPeer(peer, buf);
            }
          } catch (_) {/* fire-and-forget */}
        });
        return;
      }
      final RawDatagramSocket? sock = _getSocketForLocalCandidate(local);
      if (sock == null) return;
      sock.send(buf, InternetAddress(remote.ip), remote.port);
    } catch (_) {/* fire-and-forget */}
  }

  void _sendStunRaw(RawDatagramSocket? sock, turn_socket.TurnSocket? turnSocket,
      wire.StunAddress source, Uint8List buf) {
    try {
      if (turnSocket != null) {
        final _LocalCandidate? local = _findLocalForTurnClient(turnSocket);
        void doSend() {
          try {
            turnSocket.session.sendToPeer(source, buf);
          } catch (_) {/* */}
        }

        if (local != null) {
          _ensurePermission(local, source, (Object? err) {
            if (err != null || _closed) return;
            doSend();
          });
        } else {
          doSend();
        }
        return;
      }
      if (sock != null) {
        sock.send(buf, InternetAddress(source.ip), source.port);
      }
    } catch (_) {/* */}
  }

  _LocalCandidate? _findLocalForTurnClient(turn_socket.TurnSocket client) {
    for (final _LocalCandidate l in _localCandidates) {
      if (identical(l.turnClient, client)) return l;
    }
    return null;
  }

  /* ========================= Socket helpers ============================== */

  RawDatagramSocket? _getSocketForLocalCandidate(_LocalCandidate? cand) {
    if (cand == null) return _primarySocket;
    if (cand.socket != null) return cand.socket;
    if (cand.turnClient != null) return null;
    final String key = '${cand.base.family}:${cand.base.ip}:${cand.base.port}';
    return _sockets[key] ?? _primarySocket;
  }

  /* ========================= Send via pair (HOT PATH) ==================== */

  bool _sendViaPair(CandidatePair pair, Uint8List buf) {
    final _LocalCandidate local = pair._local;
    final IceCandidate remote = pair.remote;

    if (local.cand.type == CandidateType.relay && local.turnClient != null) {
      final turn_socket.TurnSocket client = local.turnClient!;
      final wire.StunAddress peer = wire.StunAddress(
        family: addressFamilyOf(remote.ip) == 6
            ? wire.AddressFamily.ipv6
            : wire.AddressFamily.ipv4,
        ip: remote.ip,
        port: remote.port,
      );
      if (pair._permissionReady) {
        try {
          final int? ch = pair._channel ??
              client.session.getChannelByPeer(remote.ip, remote.port);
          if (ch != null) {
            pair._channel ??= ch;
            client.session.sendChannelData(ch, buf);
          } else {
            client.session.sendToPeer(peer, buf);
          }
        } catch (_) {/* */}
        return true;
      }
      _ensurePermission(local, peer, (Object? err) {
        if (err != null) return;
        pair._permissionReady = true;
        try {
          final int? ch =
              client.session.getChannelByPeer(remote.ip, remote.port);
          if (ch != null) {
            pair._channel = ch;
            client.session.sendChannelData(ch, buf);
          } else {
            client.session.sendToPeer(peer, buf);
          }
        } catch (_) {/* */}
      });
      return true;
    }

    RawDatagramSocket? sock = pair._sock;
    if (sock == null) {
      sock = _getSocketForLocalCandidate(local);
      if (sock == null) return false;
      pair._sock = sock;
    }
    try {
      sock.send(buf, InternetAddress(remote.ip), remote.port);
      return true;
    } catch (_) {
      return false;
    }
  }

  /* ========================= TURN permissions ============================ */

  void _ensurePermission(_LocalCandidate localRelay, wire.StunAddress peer,
      void Function(Object? err)? cb) {
    final String? turnKey = localRelay.turnKey;
    if (turnKey == null) {
      cb?.call(StateError('not a relay candidate'));
      return;
    }
    final String permKey = '$turnKey|${peer.ip}';
    final _TurnPermission? existing = _turnPermissions[permKey];
    final int now = DateTime.now().millisecondsSinceEpoch;

    if (existing != null && existing.expires > now + 5000) {
      cb?.call(null);
      return;
    }

    final turn_socket.TurnSocket? client = localRelay.turnClient;
    if (client == null) {
      cb?.call(StateError('no TURN client'));
      return;
    }

    // Listen for the next createPermission success on this session.
    StreamSubscription<wire.StunMessage>? sub;
    sub = client.session.onSuccess.listen((wire.StunMessage msg) {
      if (msg.method != wire.StunMethod.createPermission) return;
      sub?.cancel();
      final _TurnPermission? prev = _turnPermissions[permKey];
      prev?.timer?.cancel();
      final Timer timer =
          Timer(const Duration(milliseconds: _turnPermissionRefreshMs), () {
        if (_closed) return;
        _ensurePermission(localRelay, peer, null);
      });
      _turnPermissions[permKey] = _TurnPermission(
          expires: now + _turnPermissionLifetimeMs, timer: timer);
      cb?.call(null);
    });

    try {
      client.session.createPermission(<wire.StunAddress>[peer]);
    } catch (e) {
      sub.cancel();
      cb?.call(e);
    }
  }

  /* ========================= Teardown ==================================== */

  void _teardown() {
    _checkTimer?.cancel();
    _checkTimer = null;
    _consentTimer?.cancel();
    _consentTimer = null;
    _nominationTimer?.cancel();
    _nominationTimer = null;

    for (final Timer t in _gatherTimers) {
      t.cancel();
    }
    _gatherTimers.clear();

    for (final _PendingTransaction t in _pendingTransactions.values) {
      t.timer?.cancel();
    }
    _pendingTransactions.clear();

    for (final CandidatePair p in _checkList) {
      p.retransmitTimer?.cancel();
      p.retransmitTimer = null;
    }

    for (final _TurnPermission perm in _turnPermissions.values) {
      perm.timer?.cancel();
    }
    _turnPermissions.clear();

    for (final turn_socket.TurnSocket c in _turnClients.values) {
      try {
        c.close();
      } catch (_) {/* */}
    }
    _turnClients.clear();

    for (final StreamSubscription<dynamic> s in _turnSubs) {
      s.cancel();
    }
    _turnSubs.clear();

    for (final StreamSubscription<RawSocketEvent> s in _socketSubs) {
      s.cancel();
    }
    _socketSubs.clear();

    for (final RawDatagramSocket s in _sockets.values) {
      if (!identical(s, _externalSocket)) {
        try {
          s.close();
        } catch (_) {/* */}
      }
    }
    _sockets.clear();
    _primarySocket = null;
  }
}

/* ============================ Module helpers ============================= */

String _txIdHex(Uint8List tid) {
  final StringBuffer sb = StringBuffer();
  for (int i = 0; i < tid.length; i++) {
    final int b = tid[i];
    if (b < 16) sb.write('0');
    sb.write(b.toRadixString(16));
  }
  return sb.toString();
}

const String _iceChars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

String _randomUfrag() {
  // RFC 8445 §16.1: ≥ 4 ice-chars
  final math.Random r = math.Random.secure();
  final StringBuffer sb = StringBuffer();
  for (int i = 0; i < 4; i++) {
    sb.write(_iceChars[r.nextInt(_iceChars.length)]);
  }
  return sb.toString();
}

String _randomPwd() {
  // RFC 8445 §16.1: password ≥ 22 ice-chars (≥ 128 bits randomness)
  final math.Random r = math.Random.secure();
  final StringBuffer sb = StringBuffer();
  for (int i = 0; i < 22; i++) {
    sb.write(_iceChars[r.nextInt(_iceChars.length)]);
  }
  return sb.toString();
}

Uint8List _randomBytes(int n) {
  final math.Random r = math.Random.secure();
  final Uint8List out = Uint8List(n);
  for (int i = 0; i < n; i++) {
    out[i] = r.nextInt(256);
  }
  return out;
}
