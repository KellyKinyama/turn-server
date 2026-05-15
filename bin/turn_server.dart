import 'package:turn_server/src/server.dart';

void main() async {
  TurnServer server = TurnServer(TurnServerOptions(
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
  int serverPort = ev.port;
}
