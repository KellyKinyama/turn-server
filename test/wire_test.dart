import 'dart:convert' show utf8;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:turn_server/turn_server.dart';

void main() {
  group('binary helpers', () {
    test('u16/u32 roundtrip', () {
      final Uint8List b = Uint8List(4);
      wU16(b, 0, 0xABCD);
      expect(rU16(b, 0), 0xABCD);
      wU32(b, 0, 0x12345678);
      expect(rU32(b, 0), 0x12345678);
    });
  });

  group('IPv4', () {
    test('roundtrip', () {
      final Uint8List b = parseIpv4('192.168.1.10');
      expect(formatIpv4(b), '192.168.1.10');
    });
  });

  group('IPv6', () {
    test('compress longest zero run', () {
      // 2001:db8::1
      final Uint8List b = parseIpv6('2001:db8::1');
      expect(formatIpv6(b), '2001:db8::1');
    });

    test('full address', () {
      final Uint8List b = parseIpv6('2001:db8:0:0:0:0:0:1');
      expect(formatIpv6(b), '2001:db8::1');
    });

    test('loopback', () {
      expect(formatIpv6(parseIpv6('::1')), '::1');
    });
  });

  group('CRC32', () {
    test('matches known vector', () {
      // CRC32 of "123456789" = 0xCBF43926
      expect(crc32(Uint8List.fromList(utf8.encode('123456789'))), 0xCBF43926);
    });
  });

  group('parseUri', () {
    test('stun host:port', () {
      final StunUri? u = parseUri('stun:stun.example.com:3478');
      expect(u, isNotNull);
      expect(u!.scheme, 'stun');
      expect(u.host, 'stun.example.com');
      expect(u.port, 3478);
      expect(u.transport, 'udp');
      expect(u.secure, false);
      expect(u.isTurn, false);
    });

    test('turns default port', () {
      final StunUri? u = parseUri('turns:example.com');
      expect(u!.port, 5349);
      expect(u.secure, true);
      expect(u.transport, 'tls');
      expect(u.isTurn, true);
    });

    test('turn with transport=tcp', () {
      final StunUri? u = parseUri('turn:turn.example.com:3478?transport=tcp');
      expect(u!.transport, 'tcp');
      expect(u.port, 3478);
    });

    test('IPv6 bracket notation', () {
      final StunUri? u = parseUri('stun:[2001:db8::1]:3478');
      expect(u!.host, '2001:db8::1');
      expect(u.port, 3478);
    });

    test('rejects garbage', () {
      expect(parseUri('http://example.com'), isNull);
      expect(parseUri(''), isNull);
    });
  });

  group('encode/decode roundtrip', () {
    test('Binding request with USERNAME', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(type: Attr.username, value: 'alice'),
        ],
        fingerprint: false,
      ));
      final StunMessage? dec = decodeMessage(enc.buf);
      expect(dec, isNotNull);
      expect(dec!.method, StunMethod.binding);
      expect(dec.cls, StunClass.request);
      expect(dec.getString(Attr.username), 'alice');
    });

    test('Binding response with XOR-MAPPED-ADDRESS (IPv4)', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.success,
        attributes: <StunAttribute>[
          StunAttribute(
            type: Attr.xorMappedAddress,
            value: const StunAddress(
              family: AddressFamily.ipv4,
              ip: '203.0.113.42',
              port: 54321,
            ),
          ),
        ],
        fingerprint: true,
      ));
      final StunMessage? dec = decodeMessage(enc.buf);
      expect(dec, isNotNull);
      final StunAddress? a = dec!.getAddress(Attr.xorMappedAddress);
      expect(a, isNotNull);
      expect(a!.ip, '203.0.113.42');
      expect(a.port, 54321);
      expect(a.family, AddressFamily.ipv4);
    });

    test('Binding response with XOR-MAPPED-ADDRESS (IPv6)', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.success,
        attributes: <StunAttribute>[
          StunAttribute(
            type: Attr.xorMappedAddress,
            value: const StunAddress(
              family: AddressFamily.ipv6,
              ip: '2001:db8::1',
              port: 12345,
            ),
          ),
        ],
      ));
      final StunMessage dec = decodeMessage(enc.buf)!;
      final StunAddress a = dec.getAddress(Attr.xorMappedAddress)!;
      expect(a.ip, '2001:db8::1');
      expect(a.port, 12345);
      expect(a.family, AddressFamily.ipv6);
    });

    test('ERROR-CODE roundtrip', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.error,
        attributes: <StunAttribute>[
          StunAttribute(
            type: Attr.errorCode,
            value: const StunErrorCode(code: 401, reason: 'Unauthorized'),
          ),
        ],
        fingerprint: false,
      ));
      final StunErrorCode? ec = decodeMessage(enc.buf)!.getErrorCode();
      expect(ec!.code, 401);
      expect(ec.reason, 'Unauthorized');
    });

    test('CHANGE-REQUEST encode/decode', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(
            type: Attr.changeRequest,
            value: const ChangeRequestValue(changeIp: true, changePort: true),
          ),
        ],
        fingerprint: false,
      ));
      final ChangeRequestValue cr = decodeMessage(enc.buf)!
          .getAttribute<ChangeRequestValue>(Attr.changeRequest)!;
      expect(cr.changeIp, true);
      expect(cr.changePort, true);
    });

    test('LIFETIME (u32) encode/decode', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.allocate,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(type: Attr.lifetime, value: 600),
        ],
        fingerprint: false,
      ));
      expect(decodeMessage(enc.buf)!.getInt(Attr.lifetime), 600);
    });
  });

  group('integrity (HMAC)', () {
    test('SHA-1 integrity validates', () {
      final Uint8List key =
          computeLongTermKey('alice', 'example.org', 'password');
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(type: Attr.username, value: 'alice'),
          StunAttribute(type: Attr.realm, value: 'example.org'),
          StunAttribute(type: Attr.nonce, value: 'abcdef'),
        ],
        key: key,
        integrity: IntegrityAlgo.sha1,
        fingerprint: false,
      ));
      final StunMessage dec = decodeMessage(enc.buf)!;
      expect(dec.integrityOffset, isNotNull);
      expect(validateIntegrity(enc.buf, dec.integrityOffset!, key), isTrue);

      // Wrong key fails.
      final Uint8List badKey =
          computeLongTermKey('alice', 'example.org', 'wrong');
      expect(validateIntegrity(enc.buf, dec.integrityOffset!, badKey), isFalse);
    });

    test('SHA-256 integrity validates', () {
      final Uint8List key =
          computeLongTermKeySha256('bob', 'example.org', 'pw');
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(type: Attr.username, value: 'bob'),
        ],
        key: key,
        integrity: IntegrityAlgo.sha256,
        fingerprint: false,
      ));
      final StunMessage dec = decodeMessage(enc.buf)!;
      expect(dec.integritySha256Offset, isNotNull);
      expect(
        validateIntegrityByLength(enc.buf, dec.integritySha256Offset!, key),
        isTrue,
      );
    });
  });

  group('FINGERPRINT', () {
    test('encode populates and validates', () {
      final EncodedMessage enc = encodeMessage(EncodeOptions(
        method: StunMethod.binding,
        cls: StunClass.request,
        attributes: <StunAttribute>[
          StunAttribute(type: Attr.username, value: 'alice'),
        ],
        fingerprint: true,
      ));
      final StunMessage dec = decodeMessage(enc.buf)!;
      expect(dec.fingerprintOffset, isNotNull);
      final int? fpVal = dec.getInt(Attr.fingerprint);
      final int expected = computeFingerprint(
          Uint8List.fromList(enc.buf.sublist(0, dec.fingerprintOffset!)));
      expect(fpVal, expected);
    });
  });

  group('ChannelData', () {
    test('encode/decode', () {
      final Uint8List payload = Uint8List.fromList(<int>[1, 2, 3, 4, 5]);
      final Uint8List framed = encodeChannelData(0x4000, payload);
      expect(isChannelData(framed), isTrue);
      expect(isStun(framed), isFalse);
      final DecodedChannelData d = decodeChannelData(framed);
      expect(d.channel, 0x4000);
      expect(d.data, orderedEquals(<int>[1, 2, 3, 4, 5]));
    });
  });

  group('demux', () {
    test('classifies first bytes', () {
      expect(
          demux(Uint8List.fromList(<int>[0x00, 0x01, 0, 0])), DemuxKind.stun);
      expect(
          demux(Uint8List.fromList(<int>[0x40, 0, 0, 0])), DemuxKind.channel);
      expect(demux(Uint8List.fromList(<int>[20, 0])), DemuxKind.dtls);
      expect(demux(Uint8List.fromList(<int>[0x80, 0x60])), DemuxKind.rtp);
      expect(demux(Uint8List.fromList(<int>[0x80, 200])), DemuxKind.rtcp);
    });
  });

  group('TCP framing', () {
    test('tcpFrame prepends length', () {
      final Uint8List inner = Uint8List.fromList(<int>[10, 20, 30]);
      final Uint8List framed = tcpFrame(inner);
      expect(framed.length, 5);
      expect(rU16(framed, 0), 3);
      expect(framed.sublist(2), orderedEquals(<int>[10, 20, 30]));
    });
  });
}
