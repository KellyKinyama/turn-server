import 'package:turn_server/src/wire.dart' as wire;
import 'package:turn_server/turn_server.dart';

Future<void> main() async {
  // int serverPort = 3478;
  print('client BINDING request returns XOR-MAPPED-ADDRESS');

  // const stunServerAddress = 'stun.l.google.com';
  // const stunServerPort = 19302;

  //   final TurnSocket client = TurnSocket(TurnSocketOptions(
  //   serverHost: '127.0.0.1',
  //   serverPort: serverPort,
  //   transportType: TransportType.udp,
  // ));

  const stunServerAddress = '127.0.0.1';
  const stunServerPort = 3478;

  final TurnSocket client = TurnSocket(TurnSocketOptions(
    serverHost: stunServerAddress,
    serverPort: stunServerPort,
    transportType: TransportType.udp,
  ));
  // addTearDown(client.close);
  await client.connect();

  final Future<wire.StunMessage> resp = client.session.onSuccess.first;
  client.session.binding();
  final wire.StunMessage r = await resp.timeout(const Duration(seconds: 2));
  print('Response:');
  print(r);

  print('method:  got ${r.methodName}, expected binding');
  print('class:   got ${r.className}, expected success');
  final wire.StunAddress? mapped = r.getAddress(wire.Attr.xorMappedAddress);
  print('mapped:  got ${mapped != null}, expected true');
  print('address: got ${mapped?.ip}');
  await client.close();
}
