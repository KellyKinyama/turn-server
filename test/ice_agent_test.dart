// Smoke tests for the ICE Agent (RFC 8445) Dart port.

import 'dart:async';

import 'package:test/test.dart';
import 'package:turn_server/turn_server.dart';

void main() {
  group('IceAgent — basics', () {
    test('default credentials have RFC 8445 §16.1 lengths', () async {
      final IceAgent agent = IceAgent();
      try {
        final IceParameters p = agent.localParameters;
        expect(p.ufrag.length, greaterThanOrEqualTo(4));
        expect(p.pwd.length, greaterThanOrEqualTo(22));
        expect(p.iceLite, isFalse);
        expect(agent.mode, IceMode.full);
        expect(agent.role, IceRole.controlling);
        expect(agent.state, IceState.fresh);
        expect(agent.gatheringState, IceGatheringState.fresh);
      } finally {
        await agent.close();
      }
    });

    test('options override credentials and mode', () async {
      final IceAgent agent = IceAgent(const IceAgentOptions(
        mode: IceMode.lite,
        controlling: false,
        ufrag: 'abcd',
        pwd: 'p234567890123456789012',
      ));
      try {
        expect(agent.localParameters.ufrag, 'abcd');
        expect(agent.localParameters.pwd, 'p234567890123456789012');
        expect(agent.mode, IceMode.lite);
        expect(agent.role, IceRole.controlled);
        expect(agent.localParameters.iceLite, isTrue);
      } finally {
        await agent.close();
      }
    });

    test('addRemoteCandidate(null) marks end-of-candidates', () async {
      final IceAgent agent = IceAgent();
      try {
        // Should not throw.
        agent.addRemoteCandidate(null);
        // Idempotent — repeat call is a no-op.
        agent.endRemoteCandidates();
      } finally {
        await agent.close();
      }
    });

    test('parses string remote candidates', () async {
      final IceAgent agent = IceAgent();
      try {
        agent.addRemoteCandidate(
            'candidate:1 1 udp 2113937151 192.0.2.10 51234 typ host');
        expect(agent.remoteCandidates, hasLength(1));
        final IceCandidate c = agent.remoteCandidates.first;
        expect(c.ip, '192.0.2.10');
        expect(c.port, 51234);
        expect(c.type, CandidateType.host);
      } finally {
        await agent.close();
      }
    });
  });

  group('IceAgent — gathering', () {
    test('host gathering emits candidates and end-of-candidates', () async {
      final IceAgent agent = IceAgent(const IceAgentOptions(
        includeLoopback: true,
        ipv6: false,
      ));

      final List<IceCandidate?> emitted = <IceCandidate?>[];
      final StreamSubscription<IceCandidate?> sub =
          agent.onCandidate.listen(emitted.add);

      try {
        agent.gather();

        // Wait for the null end-of-candidates sentinel on the candidate
        // stream itself (NOT the gathering-state-change event, which races
        // ahead of the queued candidate emission on broadcast streams).
        final Completer<void> done = Completer<void>();
        final Timer t = Timer(const Duration(seconds: 3), () {
          if (!done.isCompleted) done.complete();
        });
        late StreamSubscription<IceCandidate?> nullSub;
        nullSub = agent.onCandidate.listen((IceCandidate? c) {
          if (c == null) {
            t.cancel();
            if (!done.isCompleted) done.complete();
            nullSub.cancel();
          }
        });
        await done.future;

        expect(agent.gatheringState, IceGatheringState.complete);
        // Last emission must be the null end-of-candidates marker.
        expect(emitted.last, isNull);
        // At least one real candidate should have been emitted before it.
        final List<IceCandidate?> real =
            emitted.where((IceCandidate? c) => c != null).toList();
        expect(real, isNotEmpty,
            reason: 'expected at least one host candidate '
                '(loopback or local NIC)');
        // All real candidates must have type host (no STUN/TURN configured).
        for (final IceCandidate? c in real) {
          expect(c!.type, CandidateType.host);
        }
      } finally {
        await sub.cancel();
        await agent.close();
      }
    });
  });

  group('IceAgent — restart', () {
    test('restart returns new credentials and emits restart event', () async {
      final IceAgent agent = IceAgent();
      final Completer<IceParameters> restartFired = Completer<IceParameters>();
      final StreamSubscription<IceParameters> sub =
          agent.onRestart.listen((IceParameters p) {
        if (!restartFired.isCompleted) restartFired.complete(p);
      });

      try {
        final IceParameters before = agent.localParameters;
        final IceParameters? after = agent.restart();

        expect(after, isNotNull);
        expect(after!.ufrag, isNot(equals(before.ufrag)));
        expect(after.pwd, isNot(equals(before.pwd)));
        expect(after.ufrag.length, greaterThanOrEqualTo(4));
        expect(after.pwd.length, greaterThanOrEqualTo(22));

        final IceParameters fired =
            await restartFired.future.timeout(const Duration(seconds: 1));
        expect(fired.ufrag, after.ufrag);
        expect(fired.pwd, after.pwd);

        expect(agent.localParameters.ufrag, after.ufrag);
      } finally {
        await sub.cancel();
        await agent.close();
      }
    });
  });
}
