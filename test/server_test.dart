import 'dart:async';

import 'package:test/test.dart';
import 'package:turn_server/src/server.dart';
import 'package:turn_server/src/session.dart';
import 'package:turn_server/src/socket.dart';
import 'package:turn_server/src/wire.dart' as wire;

void main() {
  group('TurnServer — UDP listener end-to-end', () {
    late TurnServer server;
    late int serverPort;

    setUp(() async {
      server = TurnServer(TurnServerOptions(
        listen: <ListenConfig>[
          const ListenConfig(
              transport: ServerTransport.udp, address: '127.0.0.1', port: 0),
        ],
        relay: const RelayServerConfig(
          ip: '127.0.0.1',
          externalIp: '127.0.0.1',
        ),
        allowLoopback: true,
      ));
      final Future<ListeningEvent> listening = server.onListening.first;
      await server.start();
      final ListeningEvent ev = await listening;
      serverPort = ev.port;
    });

    tearDown(() async {
      await server.stop();
    });

    test('client BINDING request returns XOR-MAPPED-ADDRESS', () async {
      final TurnSocket client = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: serverPort,
        transportType: TransportType.udp,
      ));
      addTearDown(client.close);
      await client.connect();

      final Future<wire.StunMessage> resp = client.session.onSuccess.first;
      client.session.binding();
      final wire.StunMessage r = await resp.timeout(const Duration(seconds: 2));

      expect(r.method, wire.StunMethod.binding);
      expect(r.cls, wire.StunClass.success);
      final wire.StunAddress? mapped = r.getAddress(wire.Attr.xorMappedAddress);
      expect(mapped, isNotNull);
      expect(mapped!.ip, '127.0.0.1');
    });

    test('ALLOCATE creates a relay and stats track it', () async {
      final TurnSocket client = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: serverPort,
        transportType: TransportType.udp,
      ));
      addTearDown(client.close);
      await client.connect();

      final Future<AllocateServerEvent> alloced = server.onAllocate.first;
      final Future<wire.StunMessage> resp = client.session.onSuccess.first;
      client.session.allocate();
      final wire.StunMessage r = await resp.timeout(const Duration(seconds: 2));
      await alloced.timeout(const Duration(seconds: 2));

      expect(r.cls, wire.StunClass.success);
      expect(server.getStats().totalAllocations, 1);
      expect(server.getStats().activeAllocations, 1);
      expect(server.clientCount, 1);
    });

    test('acceptHook returning false drops the packet (no client created)',
        () async {
      // Rebuild server with an acceptHook that always denies.
      await server.stop();
      server = TurnServer(TurnServerOptions(
        listen: <ListenConfig>[
          const ListenConfig(
              transport: ServerTransport.udp, address: '127.0.0.1', port: 0),
        ],
        relay: const RelayServerConfig(ip: '127.0.0.1'),
        acceptHook: (AcceptInfo _) => false,
      ));
      final Future<ListeningEvent> listening = server.onListening.first;
      await server.start();
      serverPort = (await listening).port;

      final TurnSocket client = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: serverPort,
        transportType: TransportType.udp,
      ));
      addTearDown(client.close);
      await client.connect();

      // Send a binding and expect timeout (server silently drops).
      bool got = false;
      final StreamSubscription<wire.StunMessage> sub =
          client.session.onSuccess.listen((_) => got = true);
      client.session.binding();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await sub.cancel();

      expect(got, isFalse);
      expect(server.clientCount, 0);
    });
  });

  group('TurnServer — totalQuota built-in limit', () {
    test('second allocation from a different client is rejected with 486',
        () async {
      final TurnServer server = TurnServer(TurnServerOptions(
        listen: <ListenConfig>[
          const ListenConfig(
              transport: ServerTransport.udp, address: '127.0.0.1', port: 0),
        ],
        relay: const RelayServerConfig(
          ip: '127.0.0.1',
          externalIp: '127.0.0.1',
        ),
        totalQuota: 1,
      ));
      addTearDown(server.stop);
      final Future<ListeningEvent> listening = server.onListening.first;
      await server.start();
      final int port = (await listening).port;

      // First client — succeeds.
      final TurnSocket c1 = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: port,
        transportType: TransportType.udp,
      ));
      addTearDown(c1.close);
      await c1.connect();

      final Future<wire.StunMessage> r1 = c1.session.onSuccess.first;
      c1.session.allocate();
      final wire.StunMessage m1 = await r1.timeout(const Duration(seconds: 2));
      expect(m1.cls, wire.StunClass.success);

      // Second client — must be rejected. Use a fresh UDP socket so the
      // server sees a different 5-tuple.
      final TurnSocket c2 = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: port,
        transportType: TransportType.udp,
      ));
      addTearDown(c2.close);
      await c2.connect();

      final Future<ErrorResponseEvent> r2 = c2.session.onErrorResponse.first;
      c2.session.allocate();
      final ErrorResponseEvent err =
          await r2.timeout(const Duration(seconds: 2));
      expect(err.error?.code, 486);
    });
  });
}
