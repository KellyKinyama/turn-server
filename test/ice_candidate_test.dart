import 'package:test/test.dart';
import 'package:turn_server/turn_server.dart';

void main() {
  group('computeCandidatePriority', () {
    test('host > srflx > relay', () {
      final int host = computeCandidatePriorityFromType(CandidateType.host);
      final int srflx = computeCandidatePriorityFromType(CandidateType.srflx);
      final int relay = computeCandidatePriorityFromType(CandidateType.relay);
      expect(host, greaterThan(srflx));
      expect(srflx, greaterThan(relay));
    });

    test('matches RFC 8445 §5.1.2.1 formula', () {
      // type=host(126), localPref=65535, comp=1
      //   = 126*2^24 + 65535*256 + 255
      //   = 2113929216 + 16776960 + 255 = 2130706431
      expect(
        computeCandidatePriorityFromType(CandidateType.host),
        2113929216 + 16776960 + 255,
      );
    });
  });

  group('computeFoundation', () {
    test('same inputs → same foundation', () {
      final String a = computeFoundation(
        type: 'host',
        baseIp: '192.168.1.10',
      );
      final String b = computeFoundation(
        type: 'host',
        baseIp: '192.168.1.10',
      );
      expect(a, b);
      expect(a.length, 8);
    });

    test('different STUN server → different foundation', () {
      final String a = computeFoundation(
        type: 'srflx',
        baseIp: '10.0.0.1',
        stunServer: 'stun1.example.com',
      );
      final String b = computeFoundation(
        type: 'srflx',
        baseIp: '10.0.0.1',
        stunServer: 'stun2.example.com',
      );
      expect(a, isNot(b));
    });
  });

  group('format/parse round-trip', () {
    test('host candidate', () {
      final IceCandidate cand = IceCandidate.standard(
        foundation: 'abcd1234',
        component: 1,
        protocol: 'udp',
        priority: 2113929471,
        ip: '192.168.1.10',
        port: 54321,
        type: CandidateType.host,
      );
      final String line = formatCandidate(cand);
      expect(line, 'abcd1234 1 udp 2113929471 192.168.1.10 54321 typ host');

      final IceCandidate? parsed = parseCandidate('a=candidate:$line');
      expect(parsed, isNotNull);
      expect(parsed!.foundation, 'abcd1234');
      expect(parsed.component, 1);
      expect(parsed.protocol, 'udp');
      expect(parsed.priority, 2113929471);
      expect(parsed.ip, '192.168.1.10');
      expect(parsed.port, 54321);
      expect(parsed.type, CandidateType.host);
    });

    test('srflx with raddr/rport', () {
      final IceCandidate cand = IceCandidate.standard(
        foundation: 'f1',
        component: 1,
        protocol: 'udp',
        priority: 1694498815,
        ip: '203.0.113.5',
        port: 41200,
        type: CandidateType.srflx,
        relatedAddress: '192.168.1.10',
        relatedPort: 54321,
      );
      final String line = formatCandidate(cand);
      expect(line, contains('raddr 192.168.1.10'));
      expect(line, contains('rport 54321'));

      final IceCandidate? parsed = parseCandidate(line);
      expect(parsed!.relatedAddress, '192.168.1.10');
      expect(parsed.relatedPort, 54321);
      expect(parsed.type, CandidateType.srflx);
    });

    test('TCP passive', () {
      final IceCandidate cand = IceCandidate.standard(
        foundation: 't1',
        component: 1,
        protocol: 'tcp',
        priority: 100,
        ip: '10.0.0.1',
        port: 9,
        type: CandidateType.host,
        tcpType: TcpCandidateType.passive,
      );
      final IceCandidate? p = parseCandidate(formatCandidate(cand));
      expect(p!.tcpType, TcpCandidateType.passive);
    });

    test('end-of-candidates marker', () {
      expect(isEndOfCandidatesLine('a=end-of-candidates'), isTrue);
      expect(isEndOfCandidatesLine('end-of-candidates'), isTrue);
      expect(isEndOfCandidatesLine('a=candidate:foo'), isFalse);
    });
  });

  group('parseCandidate', () {
    test('rejects malformed input', () {
      expect(parseCandidate(null), isNull);
      expect(parseCandidate(''), isNull);
      expect(parseCandidate('candidate:foo'), isNull);
      expect(parseCandidate('1 2 udp 3 ip 4 NOT-typ host'), isNull);
    });

    test('accepts unknown candidate type (typeRaw populated)', () {
      final IceCandidate? p =
          parseCandidate('f 1 udp 100 1.2.3.4 5 typ custom-type');
      expect(p, isNotNull);
      expect(p!.typeRaw, 'custom-type');
      expect(p.type, isNull);
    });

    test('strips IPv6 zone id', () {
      final IceCandidate? p =
          parseCandidate('f 1 udp 100 fe80::1%eth0 5 typ host');
      expect(p!.ip, 'fe80::1');
    });
  });

  group('pair priority', () {
    test('symmetric in (G,D) ordering', () {
      const int a = 2113929471;
      const int b = 1694498815;
      // Controlling=true → G=a, D=b   |  Controlled (other side) → G=b, D=a
      // Both sides MUST agree on the same pair priority value.
      final int p1 = computePairPriority(
        controlling: true,
        localPriority: a,
        remotePriority: b,
      );
      final int p2 = computePairPriority(
        controlling: false,
        localPriority: b,
        remotePriority: a,
      );
      expect(p1, p2);
    });
  });
}
