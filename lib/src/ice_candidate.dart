// Pure ICE candidate primitives — no state, no sockets, no agent.
// Type-safe Dart port of `src/ice_candidate.js`.
//
// Spec references:
//   RFC 8445 §5.1.2   — priority formula
//   RFC 8445 §5.1.1.3 — foundation rules
//   RFC 8445 §6.1.2.3 — pair priority
//   RFC 8839 §B.1     — SDP candidate-attribute ABNF grammar
//   RFC 8839 §5.3     — end-of-candidates attribute
//   RFC 6544 §4.5     — tcptype values (active / passive / so)

import 'dart:convert' show utf8;

import 'package:crypto/crypto.dart' show md5;

/* ========================= Type preferences ========================= */
// RFC 8445 §5.1.2.2 — recommended preferences

/// Well-known ICE candidate types (RFC 8445 §5.1.1.1).
///
/// The wire/SDP value is the lowercase enum name. Non-standard tokens are
/// also legal per the RFC 8839 ABNF — for those, use [parseCandidate] with
/// the resulting [IceCandidate.type] kept as the literal string in
/// [IceCandidate.typeRaw].
enum CandidateType {
  host(126),
  prflx(110),
  srflx(100),
  relay(0);

  const CandidateType(this.preference);

  /// RFC 8445 §5.1.2.2 type preference value.
  final int preference;

  static CandidateType? tryParse(String value) {
    switch (value.toLowerCase()) {
      case 'host':
        return CandidateType.host;
      case 'prflx':
        return CandidateType.prflx;
      case 'srflx':
        return CandidateType.srflx;
      case 'relay':
        return CandidateType.relay;
    }
    return null;
  }
}

/// RFC 6544 §4.5 — TCP candidate types.
enum TcpCandidateType {
  active,
  passive,
  so;

  static TcpCandidateType? tryParse(String value) {
    switch (value.toLowerCase()) {
      case 'active':
        return TcpCandidateType.active;
      case 'passive':
        return TcpCandidateType.passive;
      case 'so':
        return TcpCandidateType.so;
    }
    return null;
  }
}

/// SDP trickle ICE end-of-candidates marker (RFC 8839 §5.3).
const String endOfCandidatesLine = 'a=end-of-candidates';

/* ========================= Priority ========================= */

/// Compute a candidate priority.
///
///   priority = 2^24 * typePref + 2^8 * localPref + (256 − componentId)
///
/// RFC 8445 §5.1.2.1.
///
/// * [typePreference] — the type preference (use [CandidateType.preference]
///   for standard types, or 0 for unknown types).
/// * [localPreference] — 0..65535; defaults to 65535.
/// * [componentId] — 1..256; defaults to 1.
///
/// Returns an integer in `[0, 2^31 - 1]`.
int computeCandidatePriority({
  required int typePreference,
  int localPreference = 65535,
  int componentId = 1,
}) {
  return (typePreference * 0x01000000) +
      (localPreference * 0x100) +
      (256 - componentId);
}

/// Convenience: compute priority from a [CandidateType].
int computeCandidatePriorityFromType(
  CandidateType type, {
  int localPreference = 65535,
  int componentId = 1,
}) {
  return computeCandidatePriority(
    typePreference: type.preference,
    localPreference: localPreference,
    componentId: componentId,
  );
}

/// Compute a candidate-pair priority.
///
///   priority = 2^32 * min(G,D) + 2 * max(G,D) + (G>D ? 1 : 0)
///
/// where G = controlling priority, D = controlled priority.
/// RFC 8445 §6.1.2.3.
///
/// NOTE: For realistic candidate priorities (~2^31), the result exceeds the
/// 53-bit JS `Number` safe range. On the Dart VM (64-bit ints) the value is
/// exact; on the Web (which uses doubles) the same precision loss as JS
/// applies — sort ordering is preserved, exact tie-breaking on identical
/// `min` may lose a few low bits.
int computePairPriority({
  required bool controlling,
  required int localPriority,
  required int remotePriority,
}) {
  final int g = controlling ? localPriority : remotePriority;
  final int d = controlling ? remotePriority : localPriority;
  final int min = g < d ? g : d;
  final int max = g > d ? g : d;
  return (min * 0x100000000) + (max * 2) + (g > d ? 1 : 0);
}

/* ========================= Foundation ========================= */

/// Compute an ICE foundation.
///
///   Same foundation ⇔ same type + same base + same STUN/TURN server + same protocol.
///
/// RFC 8445 §5.1.1.3.
///
/// Output: 8-char lowercase hex (from MD5 prefix). All chars are valid
/// ice-chars and the result fits the `1*32 ice-char` rule.
///
/// * [stunServer] — identifying string for the STUN/TURN server used to obtain
///   this candidate. Pass an empty string for `host` and `prflx` candidates.
String computeFoundation({
  required String type,
  required String baseIp,
  String protocol = 'udp',
  String stunServer = '',
}) {
  final String input = '$type|$baseIp|$protocol|$stunServer';
  final List<int> digest = md5.convert(utf8.encode(input)).bytes;
  final StringBuffer sb = StringBuffer();
  for (int i = 0; i < 4; i++) {
    final int b = digest[i];
    if (b < 16) sb.write('0');
    sb.write(b.toRadixString(16));
  }
  return sb.toString();
}

/* ========================= Candidate model ========================= */

/// Immutable ICE candidate — RFC 8839 §B.1.
///
/// Constructed via [IceCandidate.new] or [parseCandidate]. Serialise with
/// [formatCandidate] (no prefix) or [buildCandidateAttr] (`candidate:` prefix).
class IceCandidate {
  IceCandidate({
    required this.foundation,
    required this.component,
    required this.protocol,
    required this.priority,
    required this.ip,
    required this.port,
    required this.typeRaw,
    this.relatedAddress,
    this.relatedPort,
    this.tcpType,
    Map<String, String>? extensions,
  })  : type = CandidateType.tryParse(typeRaw),
        extensions = extensions == null
            ? const <String, String>{}
            : Map<String, String>.unmodifiable(extensions);

  /// Convenience constructor when the type is one of the standard four.
  IceCandidate.standard({
    required this.foundation,
    required this.component,
    required this.protocol,
    required this.priority,
    required this.ip,
    required this.port,
    required CandidateType type,
    this.relatedAddress,
    this.relatedPort,
    this.tcpType,
    Map<String, String>? extensions,
  })   // The parameter type (non-null `CandidateType`) is narrower than the
  // field type (`CandidateType?`), so an initializing formal cannot be
  // used here.
  // ignore: prefer_initializing_formals
  : type = type,
        typeRaw = type.name,
        extensions = extensions == null
            ? const <String, String>{}
            : Map<String, String>.unmodifiable(extensions);

  final String foundation;
  final int component;
  final String protocol;
  final int priority;
  final String ip;
  final int port;

  /// Parsed standard type, or `null` if the wire value was non-standard.
  /// In that case [typeRaw] holds the original string.
  final CandidateType? type;

  /// Raw lowercase type token from the wire/SDP. Always populated.
  final String typeRaw;

  final String? relatedAddress;
  final int? relatedPort;
  final TcpCandidateType? tcpType;
  final Map<String, String> extensions;

  @override
  String toString() => 'IceCandidate(${formatCandidate(this)})';
}

/* ========================= Formatting / parsing ========================= */

/// Serialize a candidate into an SDP attribute value (without `a=candidate:`).
/// Returns an empty string when required fields are invalid.
String formatCandidate(IceCandidate c) {
  if (c.foundation.isEmpty) return '';
  if (c.component < 1 || c.component > 256) return '';
  if (c.protocol.isEmpty) return '';
  if (c.priority < 0) return '';
  if (c.ip.isEmpty) return '';
  if (c.port < 0 || c.port > 65535) return '';
  if (c.typeRaw.isEmpty) return '';

  final String protocol = c.protocol.toLowerCase();
  final String type = c.typeRaw.toLowerCase();

  final StringBuffer sb = StringBuffer()
    ..write(c.foundation)
    ..write(' ')
    ..write(c.component)
    ..write(' ')
    ..write(protocol)
    ..write(' ')
    ..write(c.priority)
    ..write(' ')
    ..write(c.ip)
    ..write(' ')
    ..write(c.port)
    ..write(' typ ')
    ..write(type);

  if (c.relatedAddress != null && c.relatedAddress!.isNotEmpty) {
    sb
      ..write(' raddr ')
      ..write(c.relatedAddress);
  }
  if (c.relatedPort != null) {
    sb
      ..write(' rport ')
      ..write(c.relatedPort);
  }
  if (c.tcpType != null) {
    sb
      ..write(' tcptype ')
      ..write(c.tcpType!.name);
  }
  for (final MapEntry<String, String> e in c.extensions.entries) {
    final String v = e.value.replaceAll(RegExp(r'\s+'), '');
    if (v.isEmpty) continue;
    sb
      ..write(' ')
      ..write(e.key)
      ..write(' ')
      ..write(v);
  }
  return sb.toString();
}

/// Build a full SDP candidate line (with `candidate:` prefix, no `a=`).
String buildCandidateAttr(IceCandidate c) {
  final String v = formatCandidate(c);
  return v.isEmpty ? '' : 'candidate:$v';
}

/// Parse an SDP candidate line into an [IceCandidate].
///
/// Accepts `a=candidate:...`, `candidate:...`, or the raw value.
/// Returns `null` on parse failure.
///
/// Lenient — only rejects structurally malformed input. Does NOT enforce
/// semantic constraints (component 1-256, priority range, etc.).
IceCandidate? parseCandidate(String? str) {
  if (str == null || str.isEmpty) return null;

  String s = str.trim();
  if (s.startsWith('a=') || s.startsWith('A=')) s = s.substring(2);
  if (s.startsWith('candidate:')) s = s.substring(10);
  s = s.trim();

  final List<String> p = s.split(RegExp(r'\s+'));
  if (p.length < 8) return null;

  final int? component = int.tryParse(p[1]);
  final int? priority = int.tryParse(p[3]);
  final int? port = int.tryParse(p[5]);
  if (component == null || priority == null || port == null) return null;
  if (p[6] != 'typ') return null;

  final String typeRaw = p[7].toLowerCase();
  if (typeRaw.isEmpty) return null;

  String? relatedAddress;
  int? relatedPort;
  TcpCandidateType? tcpType;
  Map<String, String>? extensions;

  for (int i = 8; i + 1 < p.length; i += 2) {
    final String k = p[i];
    final String v = p[i + 1];
    switch (k) {
      case 'raddr':
        relatedAddress = _stripZoneId(v);
      case 'rport':
        relatedPort = int.tryParse(v);
      case 'tcptype':
        tcpType = TcpCandidateType.tryParse(v);
      default:
        (extensions ??= <String, String>{})[k] = v;
    }
  }

  return IceCandidate(
    foundation: p[0],
    component: component,
    protocol: p[2].toLowerCase(),
    priority: priority,
    ip: _stripZoneId(p[4]),
    port: port,
    typeRaw: typeRaw,
    relatedAddress: relatedAddress,
    relatedPort: relatedPort,
    tcpType: tcpType,
    extensions: extensions,
  );
}

/// Is this line the end-of-candidates marker? RFC 8839 §5.3.
bool isEndOfCandidatesLine(String? line) {
  if (line == null) return false;
  final String s = line.trim();
  return s == 'a=end-of-candidates' || s == 'end-of-candidates';
}

/// Strip an IPv6 zone-id suffix (`fe80::1%eth0` → `fe80::1`).
String _stripZoneId(String ip) {
  final int idx = ip.indexOf('%');
  return idx < 0 ? ip : ip.substring(0, idx);
}

/* ========================= Pair / candidate keys ========================= */

/// Stable string key identifying a (transport, ip, port) tuple — used as a
/// `Map` key in the agent's candidate / pair tables.
String candidateKey(String protocol, String ip, int port) =>
    '${protocol.toLowerCase()}:$ip:$port';

/// Stable string key for a (local, remote) candidate pair.
String pairKey(IceCandidate local, IceCandidate remote) =>
    '${candidateKey(local.protocol, local.ip, local.port)}|'
    '${candidateKey(remote.protocol, remote.ip, remote.port)}';

/// IP address family detection — `4` for IPv4, `6` for IPv6.
int addressFamilyOf(String ip) => ip.contains(':') ? 6 : 4;
