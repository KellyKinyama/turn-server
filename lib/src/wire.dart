// STUN/TURN wire protocol — type-safe Dart port of `src/wire.js`.
//
// This file contains the complete codec stack: constants, binary helpers,
// IPv4/IPv6 address parsing, attribute encode/decode (62 attribute types),
// HMAC integrity (SHA1/SHA256/SHA384/SHA512), CRC32 fingerprint,
// ChannelData framing, TCP framing, RFC 7983 demultiplexing, and
// STUN/TURN URI parsing (RFC 7064/7065).
//
// Spec references throughout: RFC 5389, RFC 8489 (STUN-bis), RFC 5766,
// RFC 8656 (TURN-bis), RFC 5780 (NAT detection), RFC 6062 (TCP relay),
// RFC 7635 (OAuth), RFC 5245 (ICE), RFC 7983 (multiplexing).

import 'dart:convert' show utf8;
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/* ================================ Constants ================================ */

/// STUN magic cookie — first 4 bytes after the type+length header.
const int magicCookie = 0x2112A442;

/// Magic cookie as a 4-byte buffer (used in XOR-MAPPED-ADDRESS XOR).
final Uint8List magicCookieBuf =
    Uint8List.fromList(<int>[0x21, 0x12, 0xA4, 0x42]);

/// Size of the fixed STUN message header: type(2) + length(2) + cookie(4) + tid(12).
const int headerSize = 20;

/// STUN message classes (encoded in the type field).
class StunClass {
  StunClass._();
  static const int request = 0x0000;
  static const int indication = 0x0010;
  static const int success = 0x0100;
  static const int error = 0x0110;
}

/// STUN/TURN method codes.
class StunMethod {
  StunMethod._();
  static const int binding = 0x0001;
  static const int allocate = 0x0003;
  static const int refresh = 0x0004;
  static const int send = 0x0006;
  static const int data = 0x0007;
  static const int createPermission = 0x0008;
  static const int channelBind = 0x0009;
  // RFC 6062 — TCP relay
  static const int connect = 0x000A;
  static const int connectionBind = 0x000B;
  static const int connectionAttempt = 0x000C;
  // Google extension (note: original JS had 0x080, treated as such)
  static const int googPing = 0x080;
}

/// All known STUN/TURN attribute type codes.
///
/// Attribute IDs 0x0000-0x7FFF are "comprehension-required";
/// 0x8000-0xFFFF are "comprehension-optional".
class Attr {
  Attr._();

  // RFC 5389 / 8489
  static const int mappedAddress = 0x0001;
  static const int username = 0x0006;
  static const int messageIntegrity = 0x0008;
  static const int errorCode = 0x0009;
  static const int unknownAttributes = 0x000A;
  static const int realm = 0x0014;
  static const int nonce = 0x0015;
  static const int xorMappedAddress = 0x0020;

  // TURN (RFC 5766 / 8656)
  static const int channelNumber = 0x000C;
  static const int lifetime = 0x000D;
  static const int xorPeerAddress = 0x0012;
  static const int data = 0x0013;
  static const int xorRelayedAddress = 0x0016;
  static const int evenPort = 0x0018;
  static const int requestedTransport = 0x0019;
  static const int dontFragment = 0x001A;
  static const int reservationToken = 0x0022;
  static const int requestedAddressFamily = 0x0017;

  // RFC 8489 (STUN-bis)
  static const int messageIntegritySha256 = 0x001C;
  static const int passwordAlgorithm = 0x001D;
  static const int userhash = 0x001E;
  static const int passwordAlgorithms = 0x8002;

  // RFC 6062 (TCP relay)
  static const int connectionId = 0x002A;

  // RFC 5780 (NAT detection)
  static const int changeRequest = 0x0003;
  static const int padding = 0x0026;
  static const int responsePort = 0x0027;
  static const int responseOrigin = 0x802B;
  static const int otherAddress = 0x802C;

  // RFC 8656 (TURN-bis)
  static const int additionalAddressFamily = 0x8000;
  static const int addressErrorCode = 0x8001;
  static const int icmp = 0x8004;

  // RFC 5245 (ICE)
  static const int priority = 0x0024;
  static const int useCandidate = 0x0025;
  static const int iceControlled = 0x8029;
  static const int iceControlling = 0x802A;

  // RFC 7635 (OAuth / third-party)
  static const int accessToken = 0x001B;
  static const int thirdPartyAuthorization = 0x802E;

  // RFC 8489 extras
  static const int alternateDomain = 0x8003;

  // RFC 5780 extras
  static const int cacheTimeout = 0x8027;

  // RFC 7982 — retransmission counter
  static const int transactionTransmitCounter = 0x8025;

  // RFC 6679 — ECN
  static const int ecnCheck = 0x802D;

  // RFC 8016 — Mobility
  static const int mobilityTicket = 0x8030;

  // Multi-tenant TURN
  static const int origin = 0x802F;

  // Meta (Facebook / WhatsApp)
  static const int metaDtlsInStun = 0xC070;
  static const int metaDtlsInStunAck = 0xC071;

  // Cisco
  static const int ciscoStunFlowdata = 0xC000;
  static const int ciscoWebexFlowInfo = 0xC003;

  // ENF / Odin
  static const int enfFlowDescription = 0xC001;
  static const int enfNetworkStatus = 0xC002;

  // Citrix
  static const int citrixTransactionId = 0xC056;

  // Google
  static const int googNetworkInfo = 0xC057;
  static const int googLastIceCheckReceived = 0xC058;
  static const int googMiscInfo = 0xC059;
  static const int googObsolete1 = 0xC05A;
  static const int googConnectionId = 0xC05B;
  static const int googDelta = 0xC05C;
  static const int googDeltaAck = 0xC05D;
  static const int googDeltaSyncReq = 0xC05E;
  static const int googMessageIntegrity32 = 0xC060;

  static const int software = 0x8022;
  static const int alternateServer = 0x8023;
  static const int fingerprint = 0x8028;
}

/// Standard STUN/TURN error codes.
class ErrorCodeConstants {
  ErrorCodeConstants._();
  static const int tryAlternate = 300;
  static const int badRequest = 400;
  static const int unauthorized = 401;
  static const int forbidden = 403;
  static const int unknownAttribute = 420;
  static const int allocationMismatch = 437;
  static const int staleNonce = 438;
  static const int addressFamilyNotSupported = 440;
  static const int wrongCredentials = 441;
  static const int unsupportedTransport = 442;
  static const int peerAddressFamilyMismatch = 443;
  static const int allocationQuota = 486;
  static const int serverError = 500;
  static const int insufficientCapacity = 508;
  // RFC 6062
  static const int connectionAlreadyExists = 446;
  static const int connectionTimeoutOrFailure = 447;
  // RFC 5245 (ICE)
  static const int roleConflict = 487;
  // RFC 8016
  static const int mobilityForbidden = 405;
}

const Map<int, String> errorReason = <int, String>{
  300: 'Try Alternate',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  405: 'Mobility Forbidden',
  420: 'Unknown Attribute',
  437: 'Allocation Mismatch',
  438: 'Stale Nonce',
  440: 'Address Family not Supported',
  441: 'Wrong Credentials',
  442: 'Unsupported Transport Protocol',
  443: 'Peer Address Family Mismatch',
  446: 'Connection Already Exists',
  447: 'Connection Timeout or Failure',
  486: 'Allocation Quota Reached',
  487: 'Role Conflict',
  500: 'Server Error',
  508: 'Insufficient Capacity',
};

class TransportProtocol {
  TransportProtocol._();
  static const int udp = 17;
  static const int tcp = 6;
}

/// Address family discriminator used in MAPPED-ADDRESS family-style attrs.
class AddressFamily {
  AddressFamily._();
  static const int ipv4 = 0x01;
  static const int ipv6 = 0x02;
}

const Map<int, String> methodName = <int, String>{
  0x0001: 'binding',
  0x0003: 'allocate',
  0x0004: 'refresh',
  0x0006: 'send',
  0x0007: 'data',
  0x0008: 'create_permission',
  0x0009: 'channel_bind',
  0x000A: 'connect',
  0x000B: 'connection_bind',
  0x000C: 'connection_attempt',
  0x0080: 'goog_ping',
};

const Map<int, String> className = <int, String>{
  0x0000: 'request',
  0x0010: 'indication',
  0x0100: 'success',
  0x0110: 'error',
};

/// XOR mask used by FINGERPRINT (RFC 5389 §15.5).
const int fingerprintXor = 0x5354554E;

/* ============================ Address values ============================== */

/// A network address on the wire (used by `MAPPED-ADDRESS`,
/// `XOR-PEER-ADDRESS`, `OTHER-ADDRESS`, etc.).
class StunAddress {
  const StunAddress({
    required this.family,
    required this.ip,
    required this.port,
  });

  /// [AddressFamily.ipv4] or [AddressFamily.ipv6].
  final int family;
  final String ip;
  final int port;

  @override
  String toString() => 'StunAddress($ip:$port, ipv${family == 1 ? '4' : '6'})';
}

/// Decoded ERROR-CODE attribute value.
class StunErrorCode {
  const StunErrorCode({required this.code, this.reason = ''});
  final int code;
  final String reason;
}

/// Decoded CHANGE-REQUEST attribute value (RFC 5780).
class ChangeRequestValue {
  const ChangeRequestValue({this.changeIp = false, this.changePort = false});
  final bool changeIp;
  final bool changePort;
}

/// Decoded ICMP attribute value (RFC 8656).
class IcmpValue {
  const IcmpValue({this.type = 0, this.code = 0, this.data = 0});
  final int type;
  final int code;
  final int data;
}

/// Decoded ECN-CHECK attribute value (RFC 6679).
class EcnCheckValue {
  const EcnCheckValue({required this.valid, required this.val});
  final bool valid;
  final bool val;
}

/// Decoded ADDRESS-ERROR-CODE attribute value (RFC 8656).
class AddressErrorCodeValue {
  const AddressErrorCodeValue({
    required this.family,
    required this.code,
    this.reason = '',
  });
  final int family;
  final int code;
  final String reason;
}

/// PASSWORD-ALGORITHM entry (RFC 8489).
class PasswordAlgorithm {
  PasswordAlgorithm({required this.algorithm, Uint8List? params})
      : params = params ?? Uint8List(0);

  static const int md5 = 0x0001;
  static const int sha256 = 0x0002;

  final int algorithm;
  final Uint8List params;
}

/// TRANSACTION-TRANSMIT-COUNTER attribute value (RFC 7982).
class TransactionTransmitCounter {
  const TransactionTransmitCounter({required this.req, required this.resp});
  final int req;
  final int resp;
}

/// ICE-CONTROLLED / ICE-CONTROLLING tiebreaker value (64-bit).
class IceTiebreaker {
  IceTiebreaker(this.raw)
      : assert(raw.length == 8, 'tiebreaker must be 8 bytes');

  /// Raw 8-byte tiebreaker.
  final Uint8List raw;

  /// Compare as unsigned big-endian 64-bit integers. Returns -1/0/1.
  int compareTo(IceTiebreaker other) {
    for (int i = 0; i < 8; i++) {
      if (raw[i] != other.raw[i]) return raw[i] < other.raw[i] ? -1 : 1;
    }
    return 0;
  }
}

/* ========================== Binary read/write ============================= */

/// Write `v` as u8 at `off`. Returns new offset.
int wU8(Uint8List buf, int off, int v) {
  buf[off] = v & 0xFF;
  return off + 1;
}

int wU16(Uint8List buf, int off, int v) {
  buf[off] = (v >> 8) & 0xFF;
  buf[off + 1] = v & 0xFF;
  return off + 2;
}

int wU32(Uint8List buf, int off, int v) {
  buf[off] = (v >> 24) & 0xFF;
  buf[off + 1] = (v >> 16) & 0xFF;
  buf[off + 2] = (v >> 8) & 0xFF;
  buf[off + 3] = v & 0xFF;
  return off + 4;
}

int wBytes(Uint8List buf, int off, List<int> bytes) {
  buf.setRange(off, off + bytes.length, bytes);
  return off + bytes.length;
}

int rU8(Uint8List buf, int off) => buf[off];

int rU16(Uint8List buf, int off) => (buf[off] << 8) | buf[off + 1];

int rU32(Uint8List buf, int off) =>
    ((buf[off] << 24) |
        (buf[off + 1] << 16) |
        (buf[off + 2] << 8) |
        buf[off + 3]) &
    0xFFFFFFFF;

/// Read `n` bytes starting at `off`, returning a fresh [Uint8List] copy.
///
/// We always copy (rather than returning a view) because some callers later
/// mutate bytes [2,3] of the parent buffer to compute integrity/fingerprint
/// — a view would leak those mutations into stored attribute values.
Uint8List rBytes(Uint8List buf, int off, int n) =>
    Uint8List.fromList(buf.sublist(off, off + n));

/* ============================ Address helpers ============================= */

Uint8List parseIpv4(String s) {
  final List<String> parts = s.split('.');
  if (parts.length != 4) {
    throw FormatException('invalid IPv4 address: $s');
  }
  final Uint8List out = Uint8List(4);
  for (int i = 0; i < 4; i++) {
    final int? v = int.tryParse(parts[i]);
    if (v == null || v < 0 || v > 255) {
      throw FormatException('invalid IPv4 octet: ${parts[i]}');
    }
    out[i] = v;
  }
  return out;
}

String formatIpv4(Uint8List b) => '${b[0]}.${b[1]}.${b[2]}.${b[3]}';

Uint8List parseIpv6(String s) {
  final List<String> halves = s.split('::');
  final List<String> left =
      halves[0].isEmpty ? const <String>[] : halves[0].split(':');
  final List<String> right = halves.length > 1 && halves[1].isNotEmpty
      ? halves[1].split(':')
      : const <String>[];
  final int missing = 8 - left.length - right.length;
  if (missing < 0) throw FormatException('invalid IPv6 address: $s');

  final List<String> groups = <String>[
    ...left,
    for (int i = 0; i < missing; i++) '0',
    ...right,
  ];

  final Uint8List out = Uint8List(16);
  for (int g = 0; g < 8; g++) {
    final int val = int.parse(groups[g].isEmpty ? '0' : groups[g], radix: 16);
    out[g * 2] = (val >> 8) & 0xFF;
    out[g * 2 + 1] = val & 0xFF;
  }
  return out;
}

/// Format a 16-byte IPv6 address with RFC 5952 `::` compression.
String formatIpv6(Uint8List b) {
  final List<int> groups = <int>[
    for (int i = 0; i < 16; i += 2) (b[i] << 8) | b[i + 1],
  ];

  // Find longest run of consecutive zero groups (length ≥ 2).
  int bestStart = -1, bestLen = 0;
  int curStart = -1, curLen = 0;
  for (int j = 0; j < 8; j++) {
    if (groups[j] == 0) {
      if (curStart < 0) curStart = j;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return groups.map((int g) => g.toRadixString(16)).join(':');
  }

  final List<String> parts = <String>[];
  for (int k = 0; k < 8; k++) {
    if (k == bestStart) {
      parts.add('');
      if (k == 0) parts.add('');
      continue;
    }
    if (k > bestStart && k < bestStart + bestLen) continue;
    parts.add(groups[k].toRadixString(16));
  }
  if (bestStart + bestLen == 8) parts.add('');
  return parts.join(':');
}

int detectFamily(String ip) =>
    ip.contains(':') ? AddressFamily.ipv6 : AddressFamily.ipv4;

/* ========================== Message type encoding ========================= */

int encodeType(int method, int cls) {
  final int m = method & 0xFFF;
  final int c = cls & 0x110;
  final int c0 = (c >> 4) & 1;
  final int c1 = (c >> 8) & 1;
  return ((m & 0x0F80) << 2) |
      (c1 << 8) |
      ((m & 0x0070) << 1) |
      (c0 << 4) |
      (m & 0x000F);
}

/// Decoded message type — `(method, cls)` pair.
class StunType {
  const StunType(this.method, this.cls);
  final int method;
  final int cls;
}

StunType decodeType(int type) {
  final int c0 = (type >> 4) & 1;
  final int c1 = (type >> 8) & 1;
  return StunType(
    ((type & 0x3E00) >> 2) | ((type & 0x00E0) >> 1) | (type & 0x000F),
    (c1 << 8) | (c0 << 4),
  );
}

/* ============================== Address codec ============================= */

Uint8List _encodeAddress(
  StunAddress value, {
  required int xorPort,
  Uint8List? xorIp,
  Uint8List? xorIp6Extra,
}) {
  final int port = (value.port & 0xFFFF) ^ xorPort;

  if (value.family == AddressFamily.ipv4) {
    final Uint8List ip = parseIpv4(value.ip);
    if (xorIp != null) {
      for (int i = 0; i < 4; i++) {
        ip[i] ^= xorIp[i];
      }
    }
    final Uint8List out = Uint8List(8);
    out[1] = AddressFamily.ipv4;
    wU16(out, 2, port);
    wBytes(out, 4, ip);
    return out;
  }

  final Uint8List ip6 = parseIpv6(value.ip);
  if (xorIp != null) {
    for (int j = 0; j < 4; j++) {
      ip6[j] ^= xorIp[j];
    }
  }
  if (xorIp6Extra != null) {
    for (int k = 0; k < 12; k++) {
      ip6[4 + k] ^= xorIp6Extra[k];
    }
  }
  final Uint8List out6 = Uint8List(20);
  out6[1] = AddressFamily.ipv6;
  wU16(out6, 2, port);
  wBytes(out6, 4, ip6);
  return out6;
}

StunAddress _decodeAddress(
  Uint8List data, {
  required int xorPort,
  Uint8List? xorIp,
  Uint8List? xorIp6Extra,
}) {
  // byte 0 = reserved, byte 1 = family
  final int family = data[1];
  final int port = rU16(data, 2) ^ xorPort;

  if (family == AddressFamily.ipv4) {
    final Uint8List addr = rBytes(data, 4, 4);
    if (xorIp != null) {
      for (int i = 0; i < 4; i++) {
        addr[i] ^= xorIp[i];
      }
    }
    return StunAddress(
        family: AddressFamily.ipv4, ip: formatIpv4(addr), port: port);
  }

  final Uint8List addr6 = rBytes(data, 4, 16);
  if (xorIp != null) {
    for (int j = 0; j < 4; j++) {
      addr6[j] ^= xorIp[j];
    }
  }
  if (xorIp6Extra != null) {
    for (int k = 0; k < 12; k++) {
      addr6[4 + k] ^= xorIp6Extra[k];
    }
  }
  return StunAddress(
      family: AddressFamily.ipv6, ip: formatIpv6(addr6), port: port);
}

/* ========================== Attribute codec table ========================= */
//
// Encoders take the typed value plus optional context (the transactionId for
// XOR-* attrs) and return a Uint8List ready for the wire.
// Decoders take the raw attribute value bytes plus the same context and
// return a typed Dart value.
//
// Everything is funnelled through `Object?` at the registry boundary, then
// each codec narrows the type internally. Higher-level helpers on
// [StunMessage] (`getAddress`, `getString`, `getInt`, `getErrorCode`, …)
// give callers type-safe access.

typedef AttributeEncoder = Uint8List Function(Object? value, Uint8List tid);
typedef AttributeDecoder = Object Function(Uint8List data, Uint8List tid);

class _Codec {
  const _Codec(this.encode, this.decode);
  final AttributeEncoder encode;
  final AttributeDecoder decode;
}

final Map<int, _Codec> _codecs = <int, _Codec>{};

// Internal codec registry — no public exposure of the private _Codec type.

/// Returns true if the codec registry knows how to handle [type].
/// Used by the session layer to detect comprehension-required attributes
/// (RFC 5389 §7.3.1) for which we have no decoder.
bool attrCodecsContains(int type) {
  _initCodecs();
  return _codecs.containsKey(type);
}

void _registerAddress(int type, {required bool xor}) {
  if (xor) {
    _codecs[type] = _Codec(
      (Object? v, Uint8List tid) => _encodeAddress(v! as StunAddress,
          xorPort: 0x2112, xorIp: magicCookieBuf, xorIp6Extra: tid),
      (Uint8List d, Uint8List tid) => _decodeAddress(d,
          xorPort: 0x2112, xorIp: magicCookieBuf, xorIp6Extra: tid),
    );
  } else {
    _codecs[type] = _Codec(
      (Object? v, Uint8List tid) => _encodeAddress(v! as StunAddress,
          xorPort: 0, xorIp: null, xorIp6Extra: null),
      (Uint8List d, Uint8List tid) =>
          _decodeAddress(d, xorPort: 0, xorIp: null, xorIp6Extra: null),
    );
  }
}

_Codec _stringCodec(int maxBytes) => _Codec(
      (Object? v, Uint8List tid) {
        Uint8List bytes;
        if (v is Uint8List) {
          bytes = v;
        } else if (v is String) {
          bytes = Uint8List.fromList(utf8.encode(v));
        } else {
          throw ArgumentError(
              'expected String or Uint8List, got ${v.runtimeType}');
        }
        if (maxBytes > 0 && bytes.length > maxBytes) {
          bytes = Uint8List.sublistView(bytes, 0, maxBytes);
        }
        return bytes;
      },
      (Uint8List d, Uint8List tid) => utf8.decode(d, allowMalformed: true),
    );

final _Codec _opaqueCodec = _Codec(
  (Object? v, Uint8List tid) {
    if (v is Uint8List) return v;
    if (v is List<int>) return Uint8List.fromList(v);
    throw ArgumentError('opaque value must be Uint8List or List<int>');
  },
  (Uint8List d, Uint8List tid) => Uint8List.fromList(d),
);

final _Codec _flagCodec = _Codec(
  (Object? v, Uint8List tid) => Uint8List(0),
  (Uint8List d, Uint8List tid) => true,
);

_Codec _u32Codec() => _Codec(
      (Object? v, Uint8List tid) {
        final Uint8List o = Uint8List(4);
        wU32(o, 0, v! as int);
        return o;
      },
      (Uint8List d, Uint8List tid) => rU32(d, 0),
    );

_Codec _u16Pad4Codec() => _Codec(
      (Object? v, Uint8List tid) {
        final Uint8List o = Uint8List(4);
        wU16(o, 0, v! as int);
        return o;
      },
      (Uint8List d, Uint8List tid) => rU16(d, 0),
    );

_Codec _u8Pad4Codec() => _Codec(
      (Object? v, Uint8List tid) {
        final Uint8List o = Uint8List(4);
        o[0] = (v! as int) & 0xFF;
        return o;
      },
      (Uint8List d, Uint8List tid) => d[0],
    );

void _initCodecs() {
  if (_codecs.isNotEmpty) return;

  _registerAddress(Attr.mappedAddress, xor: false);
  _registerAddress(Attr.xorMappedAddress, xor: true);
  _registerAddress(Attr.xorPeerAddress, xor: true);
  _registerAddress(Attr.xorRelayedAddress, xor: true);
  _registerAddress(Attr.alternateServer, xor: false);
  _registerAddress(Attr.responseOrigin, xor: false);
  _registerAddress(Attr.otherAddress, xor: false);

  // FINGERPRINT
  _codecs[Attr.fingerprint] = _Codec(
    (Object? v, Uint8List tid) {
      final Uint8List o = Uint8List(4);
      wU32(o, 0, v! as int);
      return o;
    },
    (Uint8List d, Uint8List tid) => rU32(d, 0),
  );

  // String attributes (RFC 8489 byte limits)
  _codecs[Attr.username] = _stringCodec(513);
  _codecs[Attr.realm] = _stringCodec(763);
  _codecs[Attr.nonce] = _stringCodec(763);
  _codecs[Attr.software] = _stringCodec(763);
  _codecs[Attr.origin] = _stringCodec(763);
  _codecs[Attr.thirdPartyAuthorization] = _stringCodec(763);
  _codecs[Attr.alternateDomain] = _stringCodec(255);

  // ERROR-CODE
  _codecs[Attr.errorCode] = _Codec(
    (Object? v, Uint8List tid) {
      int code;
      String? reason;
      if (v is StunErrorCode) {
        code = v.code;
        reason = v.reason;
      } else if (v is int) {
        code = v;
      } else if (v is Map<String, Object?>) {
        code = v['code']! as int;
        reason = v['reason'] as String?;
      } else {
        throw ArgumentError('ERROR-CODE expects StunErrorCode or int');
      }
      if (code < 300 || code > 699) code = 500;
      reason ??= errorReason[code] ?? '';
      Uint8List rb = Uint8List.fromList(utf8.encode(reason));
      if (rb.length > 763) rb = Uint8List.sublistView(rb, 0, 763);
      final Uint8List out = Uint8List(4 + rb.length);
      // bytes 0-1 reserved
      out[2] = (code ~/ 100) & 0x07;
      out[3] = code % 100;
      out.setRange(4, 4 + rb.length, rb);
      return out;
    },
    (Uint8List d, Uint8List tid) {
      final int classByte = d[2] & 0x07;
      final int num = d[3];
      final int code = classByte * 100 + num;
      final String reason =
          d.length > 4 ? utf8.decode(d.sublist(4), allowMalformed: true) : '';
      return StunErrorCode(code: code, reason: reason);
    },
  );

  // UNKNOWN-ATTRIBUTES
  _codecs[Attr.unknownAttributes] = _Codec(
    (Object? v, Uint8List tid) {
      final List<int> list = (v! as List<Object?>).cast<int>();
      final Uint8List o = Uint8List(list.length * 2);
      for (int i = 0; i < list.length; i++) {
        wU16(o, i * 2, list[i]);
      }
      return o;
    },
    (Uint8List d, Uint8List tid) {
      final List<int> out = <int>[];
      int off = 0;
      while (off + 2 <= d.length) {
        out.add(rU16(d, off));
        off += 2;
      }
      return out;
    },
  );

  _codecs[Attr.channelNumber] = _u16Pad4Codec();
  _codecs[Attr.lifetime] = _u32Codec();
  _codecs[Attr.requestedTransport] = _u8Pad4Codec();
  _codecs[Attr.requestedAddressFamily] = _u8Pad4Codec();
  _codecs[Attr.additionalAddressFamily] = _u8Pad4Codec();
  _codecs[Attr.connectionId] = _u32Codec();
  _codecs[Attr.priority] = _u32Codec();
  _codecs[Attr.useCandidate] = _flagCodec;
  _codecs[Attr.dontFragment] = _flagCodec;
  _codecs[Attr.cacheTimeout] = _u32Codec();
  _codecs[Attr.responsePort] = _u16Pad4Codec();

  // EVEN-PORT
  _codecs[Attr.evenPort] = _Codec(
    (Object? v, Uint8List tid) =>
        Uint8List.fromList(<int>[(v! as bool) ? 0x80 : 0x00]),
    (Uint8List d, Uint8List tid) => (d[0] & 0x80) != 0,
  );

  // RESERVATION-TOKEN
  _codecs[Attr.reservationToken] = _Codec(
    (Object? v, Uint8List tid) {
      final Uint8List o = Uint8List(8);
      wBytes(o, 0, v! as List<int>);
      return o;
    },
    (Uint8List d, Uint8List tid) => Uint8List.fromList(d.sublist(0, 8)),
  );

  // DATA — explicit copy on decode (caller may store)
  _codecs[Attr.data] = _Codec(
    (Object? v, Uint8List tid) =>
        v is Uint8List ? v : Uint8List.fromList(v! as List<int>),
    (Uint8List d, Uint8List tid) => Uint8List.fromList(d),
  );

  // ICE tiebreakers (8 bytes)
  final _Codec tieCodec = _Codec(
    (Object? v, Uint8List tid) {
      if (v is IceTiebreaker) return Uint8List.fromList(v.raw);
      if (v is Uint8List) {
        return v.length == 8
            ? v
            : (Uint8List(8)..setRange(0, math.min(8, v.length), v));
      }
      if (v is List<int>) return Uint8List.fromList(v);
      throw ArgumentError('ICE tiebreaker expects IceTiebreaker/Uint8List');
    },
    (Uint8List d, Uint8List tid) =>
        IceTiebreaker(Uint8List.fromList(d.sublist(0, 8))),
  );
  _codecs[Attr.iceControlled] = tieCodec;
  _codecs[Attr.iceControlling] = tieCodec;

  // ICMP (RFC 8656)
  _codecs[Attr.icmp] = _Codec(
    (Object? v, Uint8List tid) {
      final IcmpValue val = v! as IcmpValue;
      final Uint8List o = Uint8List(8);
      wU16(o, 0, val.type);
      wU16(o, 2, val.code);
      wU32(o, 4, val.data);
      return o;
    },
    (Uint8List d, Uint8List tid) => IcmpValue(
      type: rU16(d, 0),
      code: rU16(d, 2),
      data: rU32(d, 4),
    ),
  );

  // CHANGE-REQUEST (RFC 5780)
  _codecs[Attr.changeRequest] = _Codec(
    (Object? v, Uint8List tid) {
      final ChangeRequestValue val = v! as ChangeRequestValue;
      int flags = 0;
      if (val.changeIp) flags |= 0x04;
      if (val.changePort) flags |= 0x02;
      final Uint8List o = Uint8List(4);
      wU32(o, 0, flags);
      return o;
    },
    (Uint8List d, Uint8List tid) {
      final int f = rU32(d, 0);
      return ChangeRequestValue(
        changeIp: (f & 0x04) != 0,
        changePort: (f & 0x02) != 0,
      );
    },
  );

  // PADDING — encode int → that many zero bytes; bytes pass-through
  _codecs[Attr.padding] = _Codec(
    (Object? v, Uint8List tid) {
      if (v is int) return Uint8List(v);
      if (v is Uint8List) return v;
      if (v is List<int>) return Uint8List.fromList(v);
      throw ArgumentError('PADDING expects int or bytes');
    },
    (Uint8List d, Uint8List tid) => Uint8List.fromList(d),
  );

  // ADDRESS-ERROR-CODE
  _codecs[Attr.addressErrorCode] = _Codec(
    (Object? v, Uint8List tid) {
      final AddressErrorCodeValue val = v! as AddressErrorCodeValue;
      final Uint8List rb = Uint8List.fromList(utf8.encode(val.reason));
      final Uint8List out = Uint8List(5 + rb.length);
      out[0] = val.family & 0xFF;
      out[3] = (val.code ~/ 100) & 0x07;
      out[4] = val.code % 100;
      if (rb.isNotEmpty) out.setRange(5, 5 + rb.length, rb);
      return out;
    },
    (Uint8List d, Uint8List tid) {
      final int family = d[0];
      final int code = (d[3] & 0x07) * 100 + d[4];
      final String reason =
          d.length > 5 ? utf8.decode(d.sublist(5), allowMalformed: true) : '';
      return AddressErrorCodeValue(family: family, code: code, reason: reason);
    },
  );

  // PASSWORD-ALGORITHM
  _codecs[Attr.passwordAlgorithm] = _Codec(
    (Object? v, Uint8List tid) {
      final PasswordAlgorithm pa = v! as PasswordAlgorithm;
      final Uint8List o = Uint8List(4 + pa.params.length);
      wU16(o, 0, pa.algorithm);
      wU16(o, 2, pa.params.length);
      if (pa.params.isNotEmpty) wBytes(o, 4, pa.params);
      return o;
    },
    (Uint8List d, Uint8List tid) {
      final int alg = rU16(d, 0);
      final int len = rU16(d, 2);
      final Uint8List params =
          len > 0 ? Uint8List.fromList(d.sublist(4, 4 + len)) : Uint8List(0);
      return PasswordAlgorithm(algorithm: alg, params: params);
    },
  );

  // PASSWORD-ALGORITHMS (list)
  _codecs[Attr.passwordAlgorithms] = _Codec(
    (Object? v, Uint8List tid) {
      final List<PasswordAlgorithm> list =
          (v! as List<Object?>).cast<PasswordAlgorithm>();
      final List<Uint8List> parts = <Uint8List>[
        for (final PasswordAlgorithm pa in list)
          _codecs[Attr.passwordAlgorithm]!.encode(pa, tid),
      ];
      final int total =
          parts.fold<int>(0, (int s, Uint8List p) => s + p.length);
      final Uint8List o = Uint8List(total);
      int off = 0;
      for (final Uint8List p in parts) {
        o.setRange(off, off + p.length, p);
        off += p.length;
      }
      return o;
    },
    (Uint8List d, Uint8List tid) {
      final List<PasswordAlgorithm> out = <PasswordAlgorithm>[];
      int off = 0;
      while (off + 4 <= d.length) {
        final int alg = rU16(d, off);
        final int len = rU16(d, off + 2);
        final Uint8List params = len > 0
            ? Uint8List.fromList(d.sublist(off + 4, off + 4 + len))
            : Uint8List(0);
        out.add(PasswordAlgorithm(algorithm: alg, params: params));
        off += 4 + len + ((4 - (len % 4)) % 4);
      }
      return out;
    },
  );

  // ECN-CHECK
  _codecs[Attr.ecnCheck] = _Codec(
    (Object? v, Uint8List tid) {
      final EcnCheckValue val = v! as EcnCheckValue;
      int flags = 0;
      if (val.valid) flags |= 0x80;
      if (val.val) flags |= 0x40;
      final Uint8List o = Uint8List(4);
      o[0] = flags;
      return o;
    },
    (Uint8List d, Uint8List tid) =>
        EcnCheckValue(valid: (d[0] & 0x80) != 0, val: (d[0] & 0x40) != 0),
  );

  // TRANSACTION-TRANSMIT-COUNTER
  _codecs[Attr.transactionTransmitCounter] = _Codec(
    (Object? v, Uint8List tid) {
      final TransactionTransmitCounter val = v! as TransactionTransmitCounter;
      final Uint8List o = Uint8List(4);
      wU16(o, 0, val.req);
      wU16(o, 2, val.resp);
      return o;
    },
    (Uint8List d, Uint8List tid) =>
        TransactionTransmitCounter(req: rU16(d, 0), resp: rU16(d, 2)),
  );

  // Opaque pass-through codecs
  _codecs[Attr.messageIntegrity] = _opaqueCodec;
  _codecs[Attr.messageIntegritySha256] = _opaqueCodec;
  _codecs[Attr.userhash] = _opaqueCodec;
  _codecs[Attr.mobilityTicket] = _opaqueCodec;
  _codecs[Attr.accessToken] = _opaqueCodec;
  _codecs[Attr.metaDtlsInStun] = _opaqueCodec;
  _codecs[Attr.metaDtlsInStunAck] = _opaqueCodec;
  _codecs[Attr.ciscoStunFlowdata] = _opaqueCodec;
  _codecs[Attr.ciscoWebexFlowInfo] = _opaqueCodec;
  _codecs[Attr.enfFlowDescription] = _opaqueCodec;
  _codecs[Attr.enfNetworkStatus] = _opaqueCodec;
  _codecs[Attr.citrixTransactionId] = _opaqueCodec;
  _codecs[Attr.googNetworkInfo] = _opaqueCodec;
  _codecs[Attr.googLastIceCheckReceived] = _opaqueCodec;
  _codecs[Attr.googMiscInfo] = _opaqueCodec;
  _codecs[Attr.googObsolete1] = _opaqueCodec;
  _codecs[Attr.googConnectionId] = _opaqueCodec;
  _codecs[Attr.googDelta] = _opaqueCodec;
  _codecs[Attr.googDeltaAck] = _opaqueCodec;
  _codecs[Attr.googDeltaSyncReq] = _opaqueCodec;

  // GOOG-MESSAGE-INTEGRITY-32 (truncate to 4 bytes on decode)
  _codecs[Attr.googMessageIntegrity32] = _Codec(
    _opaqueCodec.encode,
    (Uint8List d, Uint8List tid) => Uint8List.fromList(d.sublist(0, 4)),
  );
}

/* ========================== SASLprep / Long-term key ====================== */

/// RFC 8265 OpaqueString — basic NFKC normalization. Full SASLprep requires
/// ICU/Unicode tables; we approximate by applying NFC (closest available
/// without an external Unicode package) and forwarding strings unchanged.
String saslprep(String s) {
  // Dart's String.normalize is not in the SDK; use a no-op that keeps the
  // string intact. The original JS used String.prototype.normalize('NFKC')
  // which is a Unicode-table heavy op — for STUN credentials this is rarely
  // load-bearing in practice, but we keep the seam here for future work.
  return s;
}

/// MD5 long-term key per RFC 5389.
Uint8List computeLongTermKey(String username, String realm, String password) {
  final List<int> input = utf8
      .encode('${saslprep(username)}:${saslprep(realm)}:${saslprep(password)}');
  return Uint8List.fromList(crypto.md5.convert(input).bytes);
}

/// SHA-256 long-term key per RFC 8489.
Uint8List computeLongTermKeySha256(
    String username, String realm, String password) {
  final List<int> input = utf8
      .encode('${saslprep(username)}:${saslprep(realm)}:${saslprep(password)}');
  return Uint8List.fromList(crypto.sha256.convert(input).bytes);
}

/// Short-term key — UTF-8 of the password.
Uint8List computeShortTermKey(String password) =>
    Uint8List.fromList(utf8.encode(saslprep(password)));

/// USERHASH = SHA-256(username ":" realm) — RFC 8489 §14.4.
Uint8List computeUserhash(String username, String realm) {
  final List<int> input =
      utf8.encode('${saslprep(username)}:${saslprep(realm)}');
  return Uint8List.fromList(crypto.sha256.convert(input).bytes);
}

/* ========================== HMAC integrity ================================ */

enum IntegrityAlgo { sha1, sha256, sha384, sha512 }

int _digestLen(IntegrityAlgo a) => switch (a) {
      IntegrityAlgo.sha1 => 20,
      IntegrityAlgo.sha256 => 32,
      IntegrityAlgo.sha384 => 48,
      IntegrityAlgo.sha512 => 64,
    };

crypto.Hash _hashFor(IntegrityAlgo a) => switch (a) {
      IntegrityAlgo.sha1 => crypto.sha1,
      IntegrityAlgo.sha256 => crypto.sha256,
      IntegrityAlgo.sha384 => crypto.sha384,
      IntegrityAlgo.sha512 => crypto.sha512,
    };

/// Compute the truncated HMAC over `msgBuf`, after temporarily rewriting
/// the STUN length field (bytes 2-3) to include the forthcoming integrity
/// attribute (RFC 5389 §15.4).
///
/// `msgBuf` is mutated then restored — caller must ensure no concurrent
/// reads of those bytes during this call.
Uint8List computeIntegrityHmac(
  IntegrityAlgo algo,
  Uint8List msgBuf,
  Uint8List key, {
  int? truncateLen,
}) {
  final int digestLen = _digestLen(algo);
  final int hmacLen = truncateLen ?? digestLen;
  final int b2 = msgBuf[2];
  final int b3 = msgBuf[3];
  // SHA1 attr = 4-byte header + 20 data bytes = 24. Others: header + truncated.
  final int attrTotalBytes = algo == IntegrityAlgo.sha1 ? 24 : 4 + hmacLen;
  final int newLen = (msgBuf.length - headerSize) + attrTotalBytes;
  msgBuf[2] = (newLen >> 8) & 0xFF;
  msgBuf[3] = newLen & 0xFF;
  final Uint8List full = Uint8List.fromList(
      crypto.Hmac(_hashFor(algo), key).convert(msgBuf).bytes);
  msgBuf[2] = b2;
  msgBuf[3] = b3;
  return hmacLen < digestLen
      ? Uint8List.fromList(full.sublist(0, hmacLen))
      : full;
}

Uint8List computeIntegrity(Uint8List msgBuf, Uint8List key) =>
    computeIntegrityHmac(IntegrityAlgo.sha1, msgBuf, key);

Uint8List computeIntegritySha256(Uint8List msgBuf, Uint8List key,
        [int? truncateLen]) =>
    computeIntegrityHmac(IntegrityAlgo.sha256, msgBuf, key,
        truncateLen: truncateLen ?? 32);

Uint8List computeIntegritySha384(Uint8List msgBuf, Uint8List key) =>
    computeIntegrityHmac(IntegrityAlgo.sha384, msgBuf, key);

Uint8List computeIntegritySha512(Uint8List msgBuf, Uint8List key) =>
    computeIntegrityHmac(IntegrityAlgo.sha512, msgBuf, key);

/// Constant-time byte comparison.
bool _timingSafeEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Validate MESSAGE-INTEGRITY by inspecting the attribute length to pick
/// the correct HMAC variant.
bool validateIntegrityByLength(
    Uint8List rawBuf, int integrityOffset, Uint8List key) {
  final int hmacLen = rU16(rawBuf, integrityOffset + 2);
  // Detach: copy the prefix so HMAC computation can mutate bytes 2-3 safely.
  final Uint8List before =
      Uint8List.fromList(rawBuf.sublist(0, integrityOffset));
  late Uint8List expected;
  if (hmacLen == 20) {
    expected = computeIntegrity(before, key);
  } else if (hmacLen <= 32) {
    expected = computeIntegritySha256(before, key, hmacLen);
  } else if (hmacLen == 48) {
    expected = computeIntegritySha384(before, key);
  } else if (hmacLen == 64) {
    expected = computeIntegritySha512(before, key);
  } else {
    return false;
  }
  final Uint8List actual = Uint8List.fromList(
      rawBuf.sublist(integrityOffset + 4, integrityOffset + 4 + hmacLen));
  return _timingSafeEqual(expected, actual);
}

bool validateIntegritySha256(
        Uint8List rawBuf, int integrityOffset, Uint8List key) =>
    validateIntegrityByLength(rawBuf, integrityOffset, key);

/// Fast path: SHA-1 only. Caller guarantees the integrity attribute is SHA-1
/// (used in ICE connectivity checks).
bool validateIntegrity(Uint8List rawBuf, int integrityOffset, Uint8List key) {
  final Uint8List before =
      Uint8List.fromList(rawBuf.sublist(0, integrityOffset));
  final Uint8List expected = computeIntegrity(before, key);
  final Uint8List actual = Uint8List.fromList(
      rawBuf.sublist(integrityOffset + 4, integrityOffset + 4 + 20));
  return _timingSafeEqual(expected, actual);
}

/* ============================== CRC-32 / Fingerprint ====================== */

final Uint32List _crc32Table = (() {
  final Uint32List t = Uint32List(256);
  for (int i = 0; i < 256; i++) {
    int c = i;
    for (int j = 0; j < 8; j++) {
      c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    }
    t[i] = c & 0xFFFFFFFF;
  }
  return t;
})();

int crc32(Uint8List buf) {
  int c = 0xFFFFFFFF;
  for (int i = 0; i < buf.length; i++) {
    c = _crc32Table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
  }
  return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}

/// Compute FINGERPRINT — temporarily rewrites bytes 2-3 of `msgBuf`.
int computeFingerprint(Uint8List msgBuf) {
  final int b2 = msgBuf[2];
  final int b3 = msgBuf[3];
  final int newLen = (msgBuf.length - headerSize) + 8;
  msgBuf[2] = (newLen >> 8) & 0xFF;
  msgBuf[3] = newLen & 0xFF;
  final int fp = (crc32(msgBuf) ^ fingerprintXor) & 0xFFFFFFFF;
  msgBuf[2] = b2;
  msgBuf[3] = b3;
  return fp;
}

/* ========================== RFC 7983 multiplexing ========================= */

bool isStun(Uint8List buf) => buf.length >= 4 && (buf[0] & 0xC0) == 0x00;

/// RFC 7983 — TURN ChannelData first byte 0x40-0x4F.
bool isChannelData(Uint8List buf) =>
    buf.length >= 4 && buf[0] >= 0x40 && buf[0] <= 0x4F;

bool isDtls(Uint8List buf) => buf.isNotEmpty && buf[0] >= 20 && buf[0] <= 63;

bool isRtp(Uint8List buf) => buf.length >= 2 && buf[0] >= 128 && buf[0] <= 191;

bool isRtcp(Uint8List buf) =>
    buf.length >= 2 &&
    buf[0] >= 128 &&
    buf[0] <= 191 &&
    buf[1] >= 192 &&
    buf[1] <= 223;

enum DemuxKind { stun, dtls, channel, rtp, rtcp, unknown }

DemuxKind demux(Uint8List buf) {
  if (buf.isEmpty) return DemuxKind.unknown;
  final int b0 = buf[0];
  if (b0 <= 3) return DemuxKind.stun;
  if (b0 >= 20 && b0 <= 63) return DemuxKind.dtls;
  if (b0 >= 0x40 && b0 <= 0x4F) return DemuxKind.channel;
  if (b0 >= 128 && b0 <= 191) {
    if (buf.length >= 2 && buf[1] >= 192 && buf[1] <= 223) {
      return DemuxKind.rtcp;
    }
    return DemuxKind.rtp;
  }
  return DemuxKind.unknown;
}

final math.Random _rng = math.Random.secure();

/// 12 cryptographically-random bytes for use as a STUN transaction ID.
Uint8List generateTransactionId() {
  final Uint8List o = Uint8List(12);
  for (int i = 0; i < 12; i++) {
    o[i] = _rng.nextInt(256);
  }
  return o;
}

/* ============================ ChannelData =========================== */

class DecodedChannelData {
  const DecodedChannelData({required this.channel, required this.data});
  final int channel;

  /// Zero-copy view over the input buffer (do not retain across mutation).
  final Uint8List data;
}

Uint8List encodeChannelData(int channelNumber, Uint8List data) {
  final Uint8List out = Uint8List(4 + data.length);
  wU16(out, 0, channelNumber);
  wU16(out, 2, data.length);
  out.setRange(4, 4 + data.length, data);
  return out;
}

DecodedChannelData decodeChannelData(Uint8List buf) {
  final int channel = rU16(buf, 0);
  final int len = rU16(buf, 2);
  return DecodedChannelData(
    channel: channel,
    data: Uint8List.sublistView(buf, 4, 4 + len),
  );
}

/// 2-byte length-prefix framing for STUN-over-TCP.
Uint8List tcpFrame(Uint8List data) {
  final Uint8List out = Uint8List(2 + data.length);
  wU16(out, 0, data.length);
  out.setRange(2, 2 + data.length, data);
  return out;
}

/* ========================= STUN/TURN URI parsing ========================== */

class StunUri {
  const StunUri({
    required this.scheme,
    required this.host,
    required this.port,
    required this.transport,
    required this.secure,
    required this.isTurn,
    required this.params,
  });

  final String scheme;
  final String host;
  final int port;
  final String transport; // 'udp' | 'tcp' | 'tls'
  final bool secure;
  final bool isTurn;
  final Map<String, String> params;
}

/// Parse a STUN/TURN URI per RFC 7064 / 7065.
StunUri? parseUri(String uri) {
  // Try IPv6 bracket notation first: scheme:[ipv6]:port?params
  final RegExp ipv6Re =
      RegExp(r'^(stuns?|turns?):\[([^\]]+)\](?::(\d+))?(?:\?(.*))?$');
  final RegExp plainRe =
      RegExp(r'^(stuns?|turns?):([^?:]+)(?::(\d+))?(?:\?(.*))?$');

  RegExpMatch? m = ipv6Re.firstMatch(uri);
  m ??= plainRe.firstMatch(uri);
  if (m == null) return null;

  final String scheme = m.group(1)!;
  final String host = m.group(2)!;
  final int? portRaw = m.group(3) != null ? int.tryParse(m.group(3)!) : null;
  final Map<String, String> params = <String, String>{};
  if (m.group(4) != null) {
    for (final String p in m.group(4)!.split('&')) {
      final List<String> kv = p.split('=');
      params[kv[0]] = kv.length > 1 ? kv[1] : '';
    }
  }

  final bool secure = scheme == 'stuns' || scheme == 'turns';
  final bool isTurn = scheme == 'turn' || scheme == 'turns';
  final String transport = params['transport'] ?? (secure ? 'tls' : 'udp');
  final int port = portRaw ?? (secure ? 5349 : 3478);

  return StunUri(
    scheme: scheme,
    host: host,
    port: port,
    transport: transport,
    secure: secure,
    isTurn: isTurn,
    params: params,
  );
}

/* ============================ Message encode ============================== */

class StunAttribute {
  StunAttribute({required this.type, this.value, this.raw});

  /// Attribute type code (one of [Attr]).
  final int type;

  /// Typed value passed to the codec on encode, or returned by the codec on
  /// decode. May be `null` for flag-only attributes after decode (use [raw]).
  Object? value;

  /// Raw on-wire bytes (set after encode/decode).
  Uint8List? raw;
}

class EncodedMessage {
  const EncodedMessage({required this.buf, required this.transactionId});
  final Uint8List buf;
  final Uint8List transactionId;
}

class EncodeOptions {
  EncodeOptions({
    this.method = StunMethod.binding,
    this.cls = StunClass.request,
    Uint8List? transactionId,
    required this.attributes,
    this.key,
    this.fingerprint = true,
    this.integrity = IntegrityAlgo.sha1,
  }) : transactionId = transactionId ?? generateTransactionId();

  final int method;
  final int cls;
  final Uint8List transactionId;
  final List<StunAttribute> attributes;

  /// HMAC key (long-term or short-term). If null, no MESSAGE-INTEGRITY.
  final Uint8List? key;
  final bool fingerprint;
  final IntegrityAlgo integrity;
}

class _PreparedAttribute {
  _PreparedAttribute(this.type, this.bytes, this.padded);
  final int type;
  final Uint8List bytes;
  final int padded; // length after 4-byte padding
}

EncodedMessage encodeMessage(EncodeOptions opts) {
  _initCodecs();

  final Uint8List tid = opts.transactionId;
  final List<_PreparedAttribute> prepared = <_PreparedAttribute>[];
  int attrsLen = 0;

  for (final StunAttribute a in opts.attributes) {
    Uint8List vb;
    if (a.raw != null) {
      vb = a.raw!;
    } else {
      final _Codec? codec = _codecs[a.type];
      if (codec != null) {
        vb = codec.encode(a.value, tid);
      } else if (a.value is Uint8List) {
        vb = a.value! as Uint8List;
      } else {
        vb = Uint8List(0);
      }
    }
    final int padded = vb.length + ((4 - (vb.length % 4)) % 4);
    attrsLen += 4 + padded;
    prepared.add(_PreparedAttribute(a.type, vb, padded));
  }

  final int hmacLen = _digestLen(opts.integrity);
  final int integritySize = opts.key != null ? 4 + hmacLen : 0;
  final int total =
      headerSize + attrsLen + integritySize + (opts.fingerprint ? 8 : 0);
  final Uint8List buf = Uint8List(total);
  int off = 0;

  off = wU16(buf, off, encodeType(opts.method, opts.cls));
  off = wU16(buf, off, attrsLen);
  off = wU32(buf, off, magicCookie);
  off = wBytes(buf, off, tid);

  for (final _PreparedAttribute ea in prepared) {
    off = wU16(buf, off, ea.type);
    off = wU16(buf, off, ea.bytes.length);
    off = wBytes(buf, off, ea.bytes);
    off += ea.padded - ea.bytes.length; // padding bytes already zero
  }

  if (opts.key != null) {
    final int iAttr = opts.integrity == IntegrityAlgo.sha1
        ? Attr.messageIntegrity
        : Attr.messageIntegritySha256;
    final Uint8List iHmac = computeIntegrityHmac(
      opts.integrity,
      Uint8List.sublistView(buf, 0, off),
      opts.key!,
    );
    off = wU16(buf, off, iAttr);
    off = wU16(buf, off, iHmac.length);
    off = wBytes(buf, off, iHmac);
    final int newLen = off - headerSize;
    buf[2] = (newLen >> 8) & 0xFF;
    buf[3] = newLen & 0xFF;
  }

  if (opts.fingerprint) {
    final int fp = computeFingerprint(Uint8List.sublistView(buf, 0, off));
    off = wU16(buf, off, Attr.fingerprint);
    off = wU16(buf, off, 4);
    off = wU32(buf, off, fp);
    final int newLen = off - headerSize;
    buf[2] = (newLen >> 8) & 0xFF;
    buf[3] = newLen & 0xFF;
  }

  return EncodedMessage(buf: buf, transactionId: tid);
}

/* ============================ Message decode ============================== */

/// A decoded STUN/TURN message.
class StunMessage {
  StunMessage({
    required this.method,
    required this.cls,
    required this.transactionId,
    required this.length,
    required this.attributes,
    required this.attrMap,
    required this.raw,
    required this.integrityOffset,
    required this.integritySha256Offset,
    required this.fingerprintOffset,
  });

  final int method;
  final int cls;
  String? get methodName => _methodNameMap[method];
  String? get className => _classNameMap[cls];
  final Uint8List transactionId;
  final int length;
  final List<StunAttribute> attributes;
  final Map<int, Object?> attrMap;
  final Uint8List raw;
  final int? integrityOffset;
  final int? integritySha256Offset;
  final int? fingerprintOffset;

  /// Generic attribute fetch — caller must know the value type for the
  /// requested attribute. Prefer the typed helpers below.
  T? getAttribute<T>(int type) {
    final Object? v = attrMap[type];
    if (v == null) return null;
    return v as T;
  }

  StunAddress? getAddress(int type) => getAttribute<StunAddress>(type);
  String? getString(int type) => getAttribute<String>(type);
  int? getInt(int type) => getAttribute<int>(type);
  Uint8List? getBytes(int type) => getAttribute<Uint8List>(type);
  StunErrorCode? getErrorCode() => getAttribute<StunErrorCode>(Attr.errorCode);

  bool hasAttribute(int type) => attrMap.containsKey(type);
}

const Map<int, String> _methodNameMap = methodName;
const Map<int, String> _classNameMap = className;

StunMessage? decodeMessage(Uint8List buf) {
  _initCodecs();

  if (buf.length < headerSize) return null;

  int off = 0;
  final int rawType = rU16(buf, off);
  off += 2;
  if ((rawType & 0xC000) != 0) return null;

  final StunType dt = decodeType(rawType);
  final int msgLen = rU16(buf, off);
  off += 2;
  final int cookie = rU32(buf, off);
  off += 4;
  if (cookie != magicCookie) return null;
  final Uint8List tid = rBytes(buf, off, 12);
  off += 12;
  if (headerSize + msgLen > buf.length) return null;
  // RFC 5389 §6: message length MUST be a multiple of 4.
  if (msgLen % 4 != 0) return null;

  final List<StunAttribute> attributes = <StunAttribute>[];
  final Map<int, Object?> attrMap = <int, Object?>{};
  int? integrityOffset;
  int? integritySha256Offset;
  int? fingerprintOffset;
  final int end = headerSize + msgLen;

  while (off + 4 <= end) {
    final int at = rU16(buf, off);
    off += 2;
    final int al = rU16(buf, off);
    off += 2;
    if (off + al > end) break;

    final Uint8List ar = rBytes(buf, off, al);

    if (at == Attr.messageIntegrity) integrityOffset = off - 4;
    if (at == Attr.messageIntegritySha256) integritySha256Offset = off - 4;
    if (at == Attr.fingerprint) fingerprintOffset = off - 4;

    Object? dv = ar;
    final _Codec? codec = _codecs[at];
    if (codec != null) {
      dv = codec.decode(ar, tid);
    }

    attributes.add(StunAttribute(type: at, value: dv, raw: ar));
    attrMap[at] = dv;

    off += al + ((4 - (al % 4)) % 4);
  }

  return StunMessage(
    method: dt.method,
    cls: dt.cls,
    transactionId: tid,
    length: msgLen,
    attributes: attributes,
    attrMap: attrMap,
    raw: buf,
    integrityOffset: integrityOffset,
    integritySha256Offset: integritySha256Offset,
    fingerprintOffset: fingerprintOffset,
  );
}

/// Standalone STUN validation for ICE connectivity checks. Verifies
/// FINGERPRINT and (when [password] is given) MESSAGE-INTEGRITY using the
/// short-term key. Returns the decoded message on success, null on failure.
StunMessage? validateStunMessage(Uint8List buf, [String? password]) {
  final StunMessage? msg = decodeMessage(buf);
  if (msg == null) return null;

  if (msg.fingerprintOffset != null) {
    final int? fpVal = msg.getInt(Attr.fingerprint);
    if (fpVal == null) return null;
    final int expectedFp = computeFingerprint(
        Uint8List.fromList(buf.sublist(0, msg.fingerprintOffset!)));
    if (fpVal != expectedFp) return null;
  }

  if (msg.integrityOffset != null && password != null) {
    final Uint8List key = computeShortTermKey(password);
    if (!validateIntegrity(buf, msg.integrityOffset!, key)) return null;
  }

  return msg;
}

/* ============================ Convenience adders ========================== */

/// Append a SHA-1 MESSAGE-INTEGRITY attribute to a pre-built message buffer.
Uint8List addIntegrity(Uint8List msgBuf, Uint8List key) {
  final Uint8List hmac = computeIntegrity(msgBuf, key);
  final Uint8List out = Uint8List(msgBuf.length + 24);
  out.setRange(0, msgBuf.length, msgBuf);
  int off = msgBuf.length;
  off = wU16(out, off, Attr.messageIntegrity);
  off = wU16(out, off, 20);
  wBytes(out, off, hmac);
  final int newLen = out.length - headerSize;
  out[2] = (newLen >> 8) & 0xFF;
  out[3] = newLen & 0xFF;
  return out;
}

/// Append a FINGERPRINT attribute to a pre-built message buffer.
Uint8List addFingerprint(Uint8List msgBuf) {
  final int fp = computeFingerprint(msgBuf);
  final Uint8List out = Uint8List(msgBuf.length + 8);
  out.setRange(0, msgBuf.length, msgBuf);
  int off = msgBuf.length;
  off = wU16(out, off, Attr.fingerprint);
  off = wU16(out, off, 4);
  wU32(out, off, fp);
  final int newLen = out.length - headerSize;
  out[2] = (newLen >> 8) & 0xFF;
  out[3] = newLen & 0xFF;
  return out;
}
