// Smoke tests for the top-level convenience API in lib/src/index.dart.

import 'package:test/test.dart';
import 'package:turn_server/turn_server.dart';

void main() {
  group('resolveServer', () {
    test('IP literals pass through unmodified', () async {
      final ResolvedStunServer r = await resolveServer('stun:127.0.0.1:3478');
      expect(r.scheme, 'stun');
      expect(r.host, '127.0.0.1');
      expect(r.port, 3478);
      expect(r.transport, 'udp');
      expect(r.secure, isFalse);
      expect(r.isTurn, isFalse);
    });

    test('IPv6 bracket literal passes through', () async {
      final ResolvedStunServer r = await resolveServer('stun:[::1]:3478');
      expect(r.host, '::1');
      expect(r.port, 3478);
    });

    test('turns: URI with explicit transport', () async {
      final ResolvedStunServer r =
          await resolveServer('turns:127.0.0.1:5349?transport=tcp');
      expect(r.scheme, 'turns');
      expect(r.isTurn, isTrue);
      expect(r.secure, isTrue);
      // params override defaults: tcp wins
      expect(r.transport, 'tcp');
      expect(r.port, 5349);
    });

    test('default ports are correct', () async {
      final ResolvedStunServer r1 = await resolveServer('turn:127.0.0.1');
      expect(r1.port, 3478);
      final ResolvedStunServer r2 = await resolveServer('turns:127.0.0.1');
      expect(r2.port, 5349);
    });

    test('invalid URI throws ArgumentError', () async {
      expect(() => resolveServer('http://example.com'),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('getPublicIP', () {
    test('returns mapped address against a local STUN server', () async {
      // Spin up a tiny in-process TURN server on loopback so the test
      // is hermetic (no internet dependency).
      final TurnServer server = createServer(TurnServerOptions(
        listen: <ListenConfig>[
          ListenConfig(
            transport: ServerTransport.udp,
            address: '127.0.0.1',
            port: 0,
          ),
        ],
      ));
      // Subscribe BEFORE start() so we don't miss the listening event
      // (broadcast streams drop events with no subscribers).
      final Future<ListeningEvent> firstFut = server.onListening.first;
      await server.start();
      addTearDown(() async => server.stop());

      final ListeningEvent first = await firstFut;
      final int boundPort = first.port;

      final PublicAddress? pa = await getPublicIP(
        server: 'stun:127.0.0.1:$boundPort',
        timeout: const Duration(seconds: 2),
      );
      expect(pa, isNotNull);
      expect(pa!.ip, '127.0.0.1');
      expect(pa.family, 4);
      expect(pa.port, greaterThan(0));
    });
  });
}
