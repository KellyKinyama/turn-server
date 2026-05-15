import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:turn_server/src/session.dart';
import 'package:turn_server/src/wire.dart' as wire;

/// Pipe two [Session] instances together so each session's outgoing
/// messages get fed into the other's [Session.message].
void _wirePair(Session a, Session b) {
  a.onMessage.listen(b.message);
  b.onMessage.listen(a.message);
}

void main() {
  group('Session — Binding (no auth)', () {
    test('client BINDING request → server BINDING success', () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);
      final wire.StunAddress serverAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '198.51.100.1', port: 3478);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        localAddress: serverAddr,
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));

      _wirePair(client, server);

      final Future<wire.StunMessage> resp = client.onSuccess.first;
      client.binding();
      final wire.StunMessage r = await resp.timeout(const Duration(seconds: 1));

      expect(r.method, wire.StunMethod.binding);
      expect(r.cls, wire.StunClass.success);
      final wire.StunAddress? mapped = r.getAddress(wire.Attr.xorMappedAddress);
      expect(mapped, isNotNull);
      expect(mapped!.ip, '203.0.113.5');
      expect(mapped.port, 51000);

      client.close();
      server.close();
    });
  });

  group('Session — Allocate / Refresh (no auth)', () {
    test('ALLOCATE request creates allocation and returns relay address',
        () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        relayIp: '198.51.100.1',
        defaultAllocateLifetime: 600,
        maxAllocateLifetime: 3600,
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      final Future<Allocation> serverAlloc = server.onAllocate.first;
      final Future<wire.StunMessage> clientResp = client.onSuccess.first;

      client.allocate();
      final Allocation alloc =
          await serverAlloc.timeout(const Duration(seconds: 1));
      final wire.StunMessage r =
          await clientResp.timeout(const Duration(seconds: 1));

      expect(alloc.transport, wire.TransportProtocol.udp);
      expect(alloc.lifetime, 600);
      expect(server.allocation, isNotNull);

      expect(r.method, wire.StunMethod.allocate);
      expect(r.cls, wire.StunClass.success);
      final wire.StunAddress? relay = r.getAddress(wire.Attr.xorRelayedAddress);
      expect(relay, isNotNull);
      expect(relay!.ip, '198.51.100.1');
      expect(r.getInt(wire.Attr.lifetime), 600);

      // REFRESH with lifetime=0 deletes allocation.
      final Future<Allocation> expired = server.onAllocateExpired.first;
      final Future<wire.StunMessage> refreshResp =
          client.onSuccess.firstWhere(
              (wire.StunMessage m) => m.method == wire.StunMethod.refresh);
      client.refresh(0);
      await expired.timeout(const Duration(seconds: 1));
      await refreshResp.timeout(const Duration(seconds: 1));
      expect(server.allocation, isNull);

      client.close();
      server.close();
    });
  });

  group('Session — Permission + Send indication relay', () {
    test('Send indication forwards data via onRelay only with permission',
        () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);
      final wire.StunAddress peer =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '192.0.2.7', port: 9000);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        relayIp: '198.51.100.1',
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      // 1. ALLOCATE
      final Future<wire.StunMessage> a1 = client.onSuccess.first;
      client.allocate();
      await a1.timeout(const Duration(seconds: 1));

      // 2. SEND with no permission → must NOT relay
      final List<RelayEvent> relayed = <RelayEvent>[];
      final StreamSubscription<RelayEvent> sub =
          server.onRelay.listen(relayed.add);

      client.sendToPeer(peer, Uint8List.fromList(<int>[1, 2, 3]));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(relayed, isEmpty,
          reason: 'no permission yet — send must be silently dropped');

      // 3. CREATE_PERMISSION
      final Future<wire.StunMessage> p1 = client.onSuccess.firstWhere(
          (wire.StunMessage m) =>
              m.method == wire.StunMethod.createPermission);
      client.createPermission(<wire.StunAddress>[peer]);
      await p1.timeout(const Duration(seconds: 1));
      expect(server.hasPermission('192.0.2.7'), isTrue);

      // 4. SEND now → relay
      client.sendToPeer(peer, Uint8List.fromList(<int>[4, 5, 6, 7]));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(relayed.length, 1);
      expect(relayed.first.peer.ip, '192.0.2.7');
      expect(relayed.first.peer.port, 9000);
      expect(relayed.first.data, <int>[4, 5, 6, 7]);

      await sub.cancel();
      client.close();
      server.close();
    });
  });

  group('Session — Channel binding + ChannelData round-trip', () {
    test('CHANNEL_BIND then ChannelData frame relays via onRelay', () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);
      final wire.StunAddress peer =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '192.0.2.8', port: 9100);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        relayIp: '198.51.100.1',
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      // ALLOCATE
      final Future<wire.StunMessage> a1 = client.onSuccess.first;
      client.allocate();
      await a1.timeout(const Duration(seconds: 1));

      // CHANNEL_BIND
      final Future<wire.StunMessage> cb = client.onSuccess.firstWhere(
          (wire.StunMessage m) => m.method == wire.StunMethod.channelBind);
      client.channelBind(0x4001, peer);
      await cb.timeout(const Duration(seconds: 1));
      expect(server.getChannelByPeer('192.0.2.8', 9100), 0x4001);
      expect(server.getPeerByChannel(0x4001)?.ip, '192.0.2.8');

      // Client sends a ChannelData frame
      final List<RelayEvent> relayed = <RelayEvent>[];
      final StreamSubscription<RelayEvent> sub =
          server.onRelay.listen(relayed.add);

      client.sendChannelData(0x4001, Uint8List.fromList(<int>[10, 20, 30]));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(relayed.length, 1);
      expect(relayed.first.channel, 0x4001);
      expect(relayed.first.data, <int>[10, 20, 30]);

      await sub.cancel();
      client.close();
      server.close();
    });
  });

  group('Session — beforeAllocate hook can deny', () {
    test('beforeAllocate returning false → 403', () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        relayIp: '198.51.100.1',
      ));
      server.beforeAllocate = (AllocateInfo _) => false;

      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      final Future<ErrorResponseEvent> err = client.onErrorResponse.first;
      client.allocate();
      final ErrorResponseEvent e = await err.timeout(const Duration(seconds: 1));

      expect(e.error?.code, 403);
      expect(server.allocation, isNull);

      client.close();
      server.close();
    });
  });

  group('Session — blocked peer policy (CVE-2020-26262)', () {
    test('loopback peer is blocked by default', () {
      final Session s = Session(SessionOptions(isServer: true));
      expect(s.isBlockedPeer('127.0.0.1'), isTrue);
      expect(s.isBlockedPeer('127.5.5.5'), isTrue);
      expect(s.isBlockedPeer('::1'), isTrue);
      expect(s.isBlockedPeer('0.0.0.0'), isTrue);
      expect(s.isBlockedPeer('224.0.0.1'), isTrue); // multicast
      expect(s.isBlockedPeer('ff02::1'), isTrue); // v6 multicast
      expect(s.isBlockedPeer('192.0.2.1'), isFalse);
      s.close();
    });

    test('allowLoopback opens loopback', () {
      final Session s = Session(SessionOptions(
        isServer: true,
        allowLoopback: true,
      ));
      expect(s.isBlockedPeer('127.0.0.1'), isFalse);
      // 0.0.0.0 always blocked regardless
      expect(s.isBlockedPeer('0.0.0.0'), isTrue);
      s.close();
    });
  });

  group('Session — long-term auth challenge / 401', () {
    test('first allocate without creds → 401 with REALM + NONCE', () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        authMech: AuthMechanism.longTerm,
        realm: 'example.org',
        relayIp: '198.51.100.1',
        credentials: <String, String>{'alice': 'wonderland'},
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      final Future<ErrorResponseEvent> err = client.onErrorResponse.first;
      client.allocate();
      final ErrorResponseEvent e = await err.timeout(const Duration(seconds: 1));

      expect(e.error?.code, 401);
      expect(e.message.getString(wire.Attr.realm), 'example.org');
      expect(e.message.getString(wire.Attr.nonce), isNotNull);

      client.close();
      server.close();
    });

    test('client with creds completes allocate via auto-retry on 401',
        () async {
      final wire.StunAddress clientAddr =
          wire.StunAddress(family: wire.AddressFamily.ipv4, ip: '203.0.113.5', port: 51000);

      final Session server = Session(SessionOptions(
        isServer: true,
        source: clientAddr,
        authMech: AuthMechanism.longTerm,
        realm: 'example.org',
        relayIp: '198.51.100.1',
        credentials: <String, String>{'alice': 'wonderland'},
      ));
      final Session client = Session(SessionOptions(
        isServer: false,
        authMech: AuthMechanism.longTerm,
        username: 'alice',
        password: 'wonderland',
        rto: const Duration(seconds: 30),
      ));
      _wirePair(client, server);

      final Future<wire.StunMessage> ok = client.onSuccess.first;
      client.allocate();
      final wire.StunMessage r = await ok.timeout(const Duration(seconds: 2));
      expect(r.method, wire.StunMethod.allocate);
      expect(r.cls, wire.StunClass.success);
      expect(server.allocation, isNotNull);
      expect(server.allocation!.username, 'alice');

      client.close();
      server.close();
    });
  });
}
