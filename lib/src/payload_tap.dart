import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'win32_net.dart';

class PayloadChunk {
  PayloadChunk({
    required this.at,
    required this.direction,
    required this.local,
    required this.remote,
    required this.kind,
    required this.bytes,
    required this.text,
  });

  final DateTime at;
  final String direction;
  final String local;
  final String remote;
  final String kind;
  final int bytes;
  final String text;
}

/// Captures TCP payloads for the selected process via SIO_RCVALL.
/// Needs an elevated process. HTTPS stays encrypted.
class PayloadTap {
  PayloadTap._(this._commands, this._isolate);

  final SendPort _commands;
  final Isolate _isolate;
  final List<PayloadChunk> chunks = <PayloadChunk>[];
  var maxChunks = 80;
  String status = 'starting';
  String? error;

  static Future<PayloadTap> start() async {
    final replies = ReceivePort();
    final isolate = await Isolate.spawn(_sniffMain, replies.sendPort);
    final first = await replies.first;
    if (first is! SendPort) {
      isolate.kill(priority: Isolate.immediate);
      throw StateError('Payload isolate failed to start.');
    }
    final tap = PayloadTap._(first, isolate);
    replies.listen((message) {
      if (message is! Map) {
        return;
      }
      final op = message['op'];
      if (op == 'ready') {
        tap.status = 'ok  ifaces=${message['ifaces']}';
        tap.error = null;
      } else if (op == 'error') {
        tap.status = 'error';
        tap.error = '${message['message']}';
      } else if (op == 'chunk') {
        tap.chunks.add(
          PayloadChunk(
            at: DateTime.now(),
            direction: '${message['dir']}',
            local: '${message['local']}',
            remote: '${message['remote']}',
            kind: '${message['kind']}',
            bytes: message['bytes'] as int,
            text: '${message['text']}',
          ),
        );
        if (tap.chunks.length > tap.maxChunks) {
          tap.chunks.removeRange(0, tap.chunks.length - tap.maxChunks);
        }
      }
    });
    return tap;
  }

  void setConnections(Iterable<NetEndpoint> sockets) {
    final tuples = <String>[];
    for (final socket in sockets) {
      if (socket.protocol != 'TCP' || socket.family != 4) {
        continue;
      }
      if (socket.remoteAddress.isEmpty || socket.remotePort == 0) {
        continue;
      }
      tuples.add(
        '${socket.localAddress}|${socket.localPort}|'
        '${socket.remoteAddress}|${socket.remotePort}',
      );
    }
    _commands.send({'op': 'tuples', 'items': tuples});
  }

  void stop() {
    _commands.send({'op': 'stop'});
    _isolate.kill(priority: Isolate.immediate);
  }
}

const int _afInet = 2;
const int _sockRaw = 3;
const int _ipprotoIp = 0;
const int _solSocket = 0xFFFF;
const int _soRcvTimeo = 0x1006;
const int _sioRcvAll = 0x98000001;
const int _rcvAllOn = 1;
const int _fionbio = 0x8004667E;
const int _wsaEAcces = 10013;
const int _wsaEWouldBlock = 10035;

final DynamicLibrary _ws2 = DynamicLibrary.open('ws2_32.dll');

final int Function(int af, int type, int protocol) _socket = _ws2
    .lookupFunction<
      IntPtr Function(Int32, Int32, Int32),
      int Function(int, int, int)
    >('socket');

final int Function(int s, Pointer<Void> name, int namelen) _bind = _ws2
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Void>, Int32),
      int Function(int, Pointer<Void>, int)
    >('bind');

final int Function(int s, Pointer<Uint8> buf, int len, int flags) _recv = _ws2
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Uint8>, Int32, Int32),
      int Function(int, Pointer<Uint8>, int, int)
    >('recv');

final int Function(int s) _closeSocket = _ws2
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('closesocket');

final int Function() _wsaGetLastError = _ws2
    .lookupFunction<Int32 Function(), int Function()>('WSAGetLastError');

final int Function(
  int s,
  int cmd,
  Pointer<Void> inBuf,
  int inLen,
  Pointer<Void> outBuf,
  int outLen,
  Pointer<Uint32> returned,
  Pointer<Void> overlapped,
  Pointer<Void> completion,
)
_wsaIoctl = _ws2
    .lookupFunction<
      Int32 Function(
        IntPtr,
        Uint32,
        Pointer<Void>,
        Uint32,
        Pointer<Void>,
        Uint32,
        Pointer<Uint32>,
        Pointer<Void>,
        Pointer<Void>,
      ),
      int Function(
        int,
        int,
        Pointer<Void>,
        int,
        Pointer<Void>,
        int,
        Pointer<Uint32>,
        Pointer<Void>,
        Pointer<Void>,
      )
    >('WSAIoctl');

final int Function(int s, int cmd, Pointer<Uint32> argp) _ioctlSocket = _ws2
    .lookupFunction<
      Int32 Function(IntPtr, Int32, Pointer<Uint32>),
      int Function(int, int, Pointer<Uint32>)
    >('ioctlsocket');

final class _SockAddrIn extends Struct {
  @Int16()
  external int sinFamily;
  @Uint16()
  external int sinPort;
  @Uint32()
  external int sinAddr;
  @Array(8)
  external Array<Uint8> sinZero;
}

Future<void> _sniffMain(SendPort replies) async {
  final commands = ReceivePort();
  replies.send(commands.sendPort);

  var running = true;
  var tuples = <String>{};
  commands.listen((message) {
    if (message is! Map) {
      return;
    }
    final op = message['op'];
    if (op == 'stop') {
      running = false;
    } else if (op == 'tuples') {
      tuples = {for (final item in (message['items'] as List)) '$item'};
    }
  });

  final sockets = <int>[];
  try {
    final interfaces = await NetworkInterface.list(
      includeLoopback: true,
      type: InternetAddressType.IPv4,
    );
    for (final iface in interfaces) {
      for (final address in iface.addresses) {
        final handle = _openRaw(address);
        if (handle != null) {
          sockets.add(handle);
        }
      }
    }
    if (sockets.isEmpty) {
      replies.send({
        'op': 'error',
        'message':
            'Raw socket acilamadi. Payload icin exe\'yi yonetici olarak calistir.',
      });
      return;
    }
    replies.send({'op': 'ready', 'ifaces': sockets.length});

    final buffer = calloc<Uint8>(65535);
    try {
      while (running) {
        for (final handle in sockets) {
          while (running) {
            final n = _recv(handle, buffer, 65535, 0);
            if (n <= 0) {
              final err = _wsaGetLastError();
              if (err != _wsaEWouldBlock && err != 0 && err != 10060) {
                // ignore transient errors
              }
              break;
            }
            final packet = buffer.asTypedList(n);
            final chunk = _parseTcp(packet, tuples);
            if (chunk != null) {
              replies.send(chunk);
            }
          }
        }
        await Future<void>.delayed(const Duration(milliseconds: 8));
      }
    } finally {
      calloc.free(buffer);
    }
  } finally {
    for (final handle in sockets) {
      _closeSocket(handle);
    }
    commands.close();
  }
}

int? _openRaw(InternetAddress address) {
  return using((arena) {
    final handle = _socket(_afInet, _sockRaw, _ipprotoIp);
    if (handle == 0 || handle == -1) {
      return null;
    }
    final name = arena<_SockAddrIn>();
    name.ref.sinFamily = _afInet;
    name.ref.sinPort = 0;
    final bytes = address.rawAddress;
    name.ref.sinAddr =
        bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    if (_bind(handle, name.cast(), sizeOf<_SockAddrIn>()) != 0) {
      _closeSocket(handle);
      return null;
    }
    final inBuf = arena<Uint32>();
    inBuf.value = _rcvAllOn;
    final returned = arena<Uint32>();
    if (_wsaIoctl(
          handle,
          _sioRcvAll,
          inBuf.cast(),
          4,
          nullptr,
          0,
          returned,
          nullptr,
          nullptr,
        ) !=
        0) {
      final err = _wsaGetLastError();
      _closeSocket(handle);
      if (err == _wsaEAcces) {
        return null;
      }
      return null;
    }
    final nonblock = arena<Uint32>();
    nonblock.value = 1;
    _ioctlSocket(handle, _fionbio, nonblock);
    final timeout = arena<Uint32>();
    timeout.value = 50;
    _ws2.lookupFunction<
      Int32 Function(IntPtr, Int32, Int32, Pointer<Void>, Int32),
      int Function(int, int, int, Pointer<Void>, int)
    >('setsockopt')(handle, _solSocket, _soRcvTimeo, timeout.cast(), 4);
    return handle;
  });
}

Map<String, Object>? _parseTcp(Uint8List packet, Set<String> tuples) {
  if (packet.length < 20) {
    return null;
  }
  final version = packet[0] >> 4;
  if (version != 4) {
    return null;
  }
  final ihl = (packet[0] & 0x0F) * 4;
  if (packet.length < ihl + 20) {
    return null;
  }
  if (packet[9] != 6) {
    return null;
  }
  final src = '${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}';
  final dst = '${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}';
  final tcp = packet.sublist(ihl);
  final srcPort = (tcp[0] << 8) | tcp[1];
  final dstPort = (tcp[2] << 8) | tcp[3];
  final dataOffset = ((tcp[12] >> 4) & 0x0F) * 4;
  if (tcp.length <= dataOffset) {
    return null;
  }
  final payload = tcp.sublist(dataOffset);
  if (payload.isEmpty) {
    return null;
  }

  String? direction;
  String? local;
  String? remote;
  if (tuples.contains('$src|$srcPort|$dst|$dstPort')) {
    direction = 'up';
    local = '$src:$srcPort';
    remote = '$dst:$dstPort';
  } else if (tuples.contains('$dst|$dstPort|$src|$srcPort')) {
    direction = 'down';
    local = '$dst:$dstPort';
    remote = '$src:$srcPort';
  }
  if (direction == null) {
    return null;
  }

  final preview = previewPayload(payload);
  return {
    'op': 'chunk',
    'dir': direction,
    'local': local!,
    'remote': remote!,
    'kind': preview.kind,
    'bytes': payload.length,
    'text': preview.text,
  };
}

({String kind, String text}) previewPayload(List<int> data) {
  if (data.length >= 3 && data[0] == 0x16 && data[1] == 0x03) {
    return (kind: 'TLS', text: 'TLS handshake — encrypted, no plaintext');
  }
  if (data.length >= 3 && data[0] == 0x17 && data[1] == 0x03) {
    return (kind: 'TLS', text: 'TLS application data — encrypted');
  }
  if (data.length >= 3 && data[0] == 0x15 && data[1] == 0x03) {
    return (kind: 'TLS', text: 'TLS alert — encrypted');
  }
  if (data.length >= 2 && data[0] == 0x14 && data[1] == 0x03) {
    return (kind: 'TLS', text: 'TLS change-cipher — encrypted');
  }

  final slice = data.length > 2048 ? data.sublist(0, 2048) : data;
  final raw = String.fromCharCodes(slice);
  final httpStart =
      raw.startsWith('GET ') ||
      raw.startsWith('POST ') ||
      raw.startsWith('PUT ') ||
      raw.startsWith('HEAD ') ||
      raw.startsWith('DELETE ') ||
      raw.startsWith('PATCH ') ||
      raw.startsWith('OPTIONS ') ||
      raw.startsWith('HTTP/');
  var printable = 0;
  for (final byte in slice) {
    if (byte == 9 || byte == 10 || byte == 13 || (byte >= 32 && byte < 127)) {
      printable++;
    }
  }
  if (httpStart || printable / slice.length > 0.85) {
    return (kind: httpStart ? 'HTTP' : 'text', text: _collapse(raw));
  }
  return (kind: 'bin', text: _hex(slice, 48));
}

String _collapse(String value) {
  return value
      .replaceAll('\r\n', '\n')
      .replaceAll('\r', '\n')
      .replaceAll(RegExp(r'\n{3,}'), '\n\n')
      .trimRight();
}

String _hex(List<int> data, int max) {
  final take = data.length < max ? data : data.sublist(0, max);
  final hex = [
    for (final byte in take) byte.toRadixString(16).padLeft(2, '0'),
  ].join(' ');
  return data.length > max ? '$hex …' : hex;
}
