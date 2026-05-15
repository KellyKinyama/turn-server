import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:turn_server/src/session.dart';
import 'package:turn_server/src/socket.dart';
import 'package:turn_server/src/wire.dart' as wire;

void main() {
  group('TurnSocket — UDP client → server end-to-end', () {
    test('BINDING request over real UDP returns XOR-MAPPED-ADDRESS', () async {
      // Server listener: bind a UDP socket and pump bytes into a TurnSocket.
      final RawDatagramSocket serverSock =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(serverSock.close);

      // Per-client TurnSocket (server side). The first packet tells us
      // the client's address — we patch context after that.
      TurnSocket? serverWrap;
      InternetAddress? clientAddr;
      int? clientPort;

      serverSock.listen((RawSocketEvent ev) {
        if (ev != RawSocketEvent.read) return;
        final Datagram? dg = serverSock.receive();
        if (dg == null) return;

        if (serverWrap == null) {
          clientAddr = dg.address;
          clientPort = dg.port;
          serverWrap = TurnSocket(TurnSocketOptions(
            isServer: true,
            source: wire.StunAddress(
              family: wire.AddressFamily.ipv4,
              ip: dg.address.address,
              port: dg.port,
            ),
            localAddress: wire.StunAddress(
              family: wire.AddressFamily.ipv4,
              ip: '127.0.0.1',
              port: serverSock.port,
            ),
            send: (Uint8List buf) {
              serverSock.send(buf, clientAddr!, clientPort!);
            },
          ));
          addTearDown(() => serverWrap!.close());
        }
        serverWrap!.feed(dg.data);
      });

      // Client TurnSocket — connect to the listener.
      final TurnSocket client = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: serverSock.port,
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
      expect(mapped.port, isNonZero);
    });
  });

  group('TurnSocket — server-side ALLOCATE + relay', () {
    test('Allocate a real relay UDP port and round-trip data via SEND',
        () async {
      // ----- Server listener -----
      final RawDatagramSocket serverSock =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(serverSock.close);

      TurnSocket? serverWrap;
      InternetAddress? clientAddr;
      int? clientPort;

      serverSock.listen((RawSocketEvent ev) {
        if (ev != RawSocketEvent.read) return;
        final Datagram? dg = serverSock.receive();
        if (dg == null) return;
        if (serverWrap == null) {
          clientAddr = dg.address;
          clientPort = dg.port;
          serverWrap = TurnSocket(TurnSocketOptions(
            isServer: true,
            source: wire.StunAddress(
              family: wire.AddressFamily.ipv4,
              ip: dg.address.address,
              port: dg.port,
            ),
            localAddress: wire.StunAddress(
              family: wire.AddressFamily.ipv4,
              ip: '127.0.0.1',
              port: serverSock.port,
            ),
            relayIp: '127.0.0.1',
            externalIp: '127.0.0.1',
            allowLoopback: true, // peer is on loopback for this test
            send: (Uint8List buf) {
              serverSock.send(buf, clientAddr!, clientPort!);
            },
          ));
          addTearDown(() => serverWrap!.close());
        }
        serverWrap!.feed(dg.data);
      });

      // ----- Client -----
      final TurnSocket client = TurnSocket(TurnSocketOptions(
        serverHost: '127.0.0.1',
        serverPort: serverSock.port,
        transportType: TransportType.udp,
        rejectUnauthorized: false,
      ));
      addTearDown(client.close);
      await client.connect();

      // ----- Peer (a plain UDP socket the server will relay to) -----
      final RawDatagramSocket peerSock =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(peerSock.close);

      // Subscribe up-front and collect every datagram. RawDatagramSocket is
      // single-subscription, so we cannot cancel & re-listen later.
      final List<Datagram> peerRecv = <Datagram>[];
      peerSock.listen((RawSocketEvent ev) {
        if (ev != RawSocketEvent.read) return;
        final Datagram? dg = peerSock.receive();
        if (dg != null) peerRecv.add(dg);
      });

      // 1. ALLOCATE
      final Future<wire.StunMessage> allocResp = client.session.onSuccess.first;
      client.session.allocate();
      final wire.StunMessage alloc =
          await allocResp.timeout(const Duration(seconds: 2));
      final wire.StunAddress? relayed =
          alloc.getAddress(wire.Attr.xorRelayedAddress);
      expect(relayed, isNotNull);
      expect(relayed!.ip, '127.0.0.1');
      expect(relayed.port, isNonZero);

      // 2. CREATE_PERMISSION for the peer
      final wire.StunAddress peer = wire.StunAddress(
        family: wire.AddressFamily.ipv4,
        ip: '127.0.0.1',
        port: peerSock.port,
      );
      final Future<wire.StunMessage> permResp = client.session.onSuccess
          .firstWhere((wire.StunMessage m) =>
              m.method == wire.StunMethod.createPermission);
      client.session.createPermission(<wire.StunAddress>[peer]);
      await permResp.timeout(const Duration(seconds: 2));

      // 3. Client sends to peer via SEND indication
      client.session
          .sendToPeer(peer, Uint8List.fromList(<int>[0xAA, 0xBB, 0xCC]));

      // Wait for the peer to receive
      await _waitUntil(() => peerRecv.isNotEmpty, const Duration(seconds: 2));
      expect(peerRecv.length, 1);
      expect(peerRecv.first.data, <int>[0xAA, 0xBB, 0xCC]);
      expect(peerRecv.first.address.address, '127.0.0.1');
      expect(peerRecv.first.port, relayed.port);

      // 4. Peer replies — must arrive on the client as a DATA indication
      final Future<DataEvent> dataEv = client.session.onData.first;
      peerSock.send(Uint8List.fromList(<int>[1, 2, 3, 4]),
          InternetAddress('127.0.0.1'), relayed.port);
      final DataEvent de = await dataEv.timeout(const Duration(seconds: 2));
      expect(de.data, <int>[1, 2, 3, 4]);
      expect(de.peer.port, peerSock.port);
    });
  });
}

/// Poll until [predicate] returns true or [timeout] elapses.
Future<void> _waitUntil(bool Function() predicate, Duration timeout) async {
  final DateTime deadline = DateTime.now().add(timeout);
  while (!predicate()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('predicate did not become true', timeout);
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}
