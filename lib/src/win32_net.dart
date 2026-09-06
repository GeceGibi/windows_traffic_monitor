import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const int _afInet = 2;
const int _afInet6 = 23;
const int _tcpTableOwnerPidAll = 5;
const int _udpTableOwnerPid = 1;
const int _errorInsufficientBuffer = 122;
const int _noError = 0;
const int _processQueryLimitedInformation = 0x1000;
const int _enableVirtualTerminalProcessing = 0x0004;

final DynamicLibrary _iphlpapi = DynamicLibrary.open('iphlpapi.dll');
final DynamicLibrary _kernel32 = DynamicLibrary.open('kernel32.dll');

typedef _GetExtendedTableNative =
    Uint32 Function(
      Pointer<Void>,
      Pointer<Uint32>,
      Int32,
      Uint32,
      Int32,
      Uint32,
    );
typedef _GetExtendedTableDart =
    int Function(Pointer<Void>, Pointer<Uint32>, int, int, int, int);

final _GetExtendedTableDart _getExtendedTcpTable = _iphlpapi
    .lookupFunction<_GetExtendedTableNative, _GetExtendedTableDart>(
      'GetExtendedTcpTable',
    );

final _GetExtendedTableDart _getExtendedUdpTable = _iphlpapi
    .lookupFunction<_GetExtendedTableNative, _GetExtendedTableDart>(
      'GetExtendedUdpTable',
    );

final int Function(int desiredAccess, int inheritHandle, int processId)
_openProcess = _kernel32
    .lookupFunction<
      IntPtr Function(Uint32, Int32, Uint32),
      int Function(int, int, int)
    >('OpenProcess');

final int Function(
  int process,
  int flags,
  Pointer<Utf16> name,
  Pointer<Uint32> size,
)
_queryFullProcessImageName = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Uint32, Pointer<Utf16>, Pointer<Uint32>),
      int Function(int, int, Pointer<Utf16>, Pointer<Uint32>)
    >('QueryFullProcessImageNameW');

final int Function(int handle) _closeHandle = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');

final int Function(int) _getStdHandle = _kernel32
    .lookupFunction<IntPtr Function(Int32), int Function(int)>('GetStdHandle');

final int Function(int, Pointer<Uint32>) _getConsoleMode = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Uint32>),
      int Function(int, Pointer<Uint32>)
    >('GetConsoleMode');

final int Function(int, int) _setConsoleMode = _kernel32
    .lookupFunction<Int32 Function(IntPtr, Uint32), int Function(int, int)>(
      'SetConsoleMode',
    );

final class _MibTcpRowOwnerPid extends Struct {
  @Uint32()
  external int dwState;
  @Uint32()
  external int dwLocalAddr;
  @Uint32()
  external int dwLocalPort;
  @Uint32()
  external int dwRemoteAddr;
  @Uint32()
  external int dwRemotePort;
  @Uint32()
  external int dwOwningPid;
}

final class _MibTcp6RowOwnerPid extends Struct {
  @Array(16)
  external Array<Uint8> ucLocalAddr;
  @Uint32()
  external int dwLocalScopeId;
  @Uint32()
  external int dwLocalPort;
  @Array(16)
  external Array<Uint8> ucRemoteAddr;
  @Uint32()
  external int dwRemoteScopeId;
  @Uint32()
  external int dwRemotePort;
  @Uint32()
  external int dwState;
  @Uint32()
  external int dwOwningPid;
}

final class _MibUdpRowOwnerPid extends Struct {
  @Uint32()
  external int dwLocalAddr;
  @Uint32()
  external int dwLocalPort;
  @Uint32()
  external int dwOwningPid;
}

final class _MibUdp6RowOwnerPid extends Struct {
  @Array(16)
  external Array<Uint8> ucLocalAddr;
  @Uint32()
  external int dwLocalScopeId;
  @Uint32()
  external int dwLocalPort;
  @Uint32()
  external int dwOwningPid;
}

/// TCP connection or UDP endpoint owned by a process.
class NetEndpoint {
  const NetEndpoint({
    required this.protocol,
    required this.family,
    required this.localAddress,
    required this.localPort,
    required this.remoteAddress,
    required this.remotePort,
    required this.state,
    required this.pid,
    required this.processName,
  });

  final String protocol;
  final int family;
  final String localAddress;
  final int localPort;
  final String remoteAddress;
  final int remotePort;
  final String state;
  final int pid;
  final String processName;

  String get protoLabel => '$protocol$family';

  String get local => _formatHostPort(localAddress, localPort);

  String get remote {
    if (remoteAddress.isEmpty || _isUnspecified(remoteAddress)) {
      return remotePort == 0 ? '*' : '*:$remotePort';
    }
    return _formatHostPort(remoteAddress, remotePort);
  }

  /// Stable identity for open/close tracking. State is omitted so a
  /// SYN_SENT → ESTABLISHED transition is not treated as a new socket.
  String get key => '$pid|$protoLabel|$local|$remoteAddress:$remotePort';

  bool get isListen => state == 'LISTEN';

  bool get isEstablished => state == 'ESTABLISHED';
}

class Snapshot {
  const Snapshot({required this.endpoints, required this.capturedAt});

  final List<NetEndpoint> endpoints;
  final DateTime capturedAt;
}

/// Reads sockets owned by the target process.
class WindowsNetMonitor {
  WindowsNetMonitor() {
    if (!Platform.isWindows) {
      throw UnsupportedError('This monitor only runs on Windows.');
    }
  }

  final Map<int, String> _processCache = <int, String>{};

  Snapshot capture({bool Function(String name, int pid)? only}) {
    final endpoints =
        <NetEndpoint>[
              ..._readTcp(ipv6: false),
              ..._readTcp(ipv6: true),
              ..._readUdp(ipv6: false),
              ..._readUdp(ipv6: true),
            ]
            .where(
              (socket) => only == null || only(socket.processName, socket.pid),
            )
            .toList();

    endpoints.sort((a, b) {
      final byRank = _stateRank(a).compareTo(_stateRank(b));
      if (byRank != 0) {
        return byRank;
      }
      final byName = a.processName.toLowerCase().compareTo(
        b.processName.toLowerCase(),
      );
      if (byName != 0) {
        return byName;
      }
      return a.local.compareTo(b.local);
    });

    return Snapshot(endpoints: endpoints, capturedAt: DateTime.now());
  }

  List<NetEndpoint> _readTcp({required bool ipv6}) {
    return _readOwnerPidTable(
      getter: _getExtendedTcpTable,
      family: ipv6 ? _afInet6 : _afInet,
      tableClass: _tcpTableOwnerPidAll,
      parse: (buffer, count) {
        if (ipv6) {
          return _parseTcp6(buffer, count);
        }
        return _parseTcp4(buffer, count);
      },
    );
  }

  List<NetEndpoint> _readUdp({required bool ipv6}) {
    return _readOwnerPidTable(
      getter: _getExtendedUdpTable,
      family: ipv6 ? _afInet6 : _afInet,
      tableClass: _udpTableOwnerPid,
      parse: (buffer, count) {
        if (ipv6) {
          return _parseUdp6(buffer, count);
        }
        return _parseUdp4(buffer, count);
      },
    );
  }

  List<NetEndpoint> _readOwnerPidTable({
    required _GetExtendedTableDart getter,
    required int family,
    required int tableClass,
    required List<NetEndpoint> Function(Pointer<Uint8> buffer, int count) parse,
  }) {
    return using((arena) {
      final size = arena<Uint32>();
      var status = getter(nullptr, size, 1, family, tableClass, 0);
      if (status != _errorInsufficientBuffer && status != _noError) {
        if (family == _afInet6) {
          return const <NetEndpoint>[];
        }
        throw WindowsNetException('Table size query failed ($status).');
      }

      final buffer = arena<Uint8>(size.value);
      status = getter(buffer.cast(), size, 1, family, tableClass, 0);
      if (status != _noError) {
        if (family == _afInet6) {
          return const <NetEndpoint>[];
        }
        throw WindowsNetException('Table read failed ($status).');
      }

      return parse(buffer, buffer.cast<Uint32>().value);
    });
  }

  List<NetEndpoint> _parseTcp4(Pointer<Uint8> buffer, int count) {
    final rows = (buffer + 4).cast<_MibTcpRowOwnerPid>();
    return [
      for (var i = 0; i < count; i++)
        NetEndpoint(
          protocol: 'TCP',
          family: 4,
          localAddress: _ipv4(rows[i].dwLocalAddr),
          localPort: _ntohs(rows[i].dwLocalPort),
          remoteAddress: _ipv4(rows[i].dwRemoteAddr),
          remotePort: _ntohs(rows[i].dwRemotePort),
          state: _tcpState(rows[i].dwState),
          pid: rows[i].dwOwningPid,
          processName: processName(rows[i].dwOwningPid),
        ),
    ];
  }

  List<NetEndpoint> _parseTcp6(Pointer<Uint8> buffer, int count) {
    final rows = (buffer + 4).cast<_MibTcp6RowOwnerPid>();
    return [
      for (var i = 0; i < count; i++)
        NetEndpoint(
          protocol: 'TCP',
          family: 6,
          localAddress: _ipv6(rows[i].ucLocalAddr),
          localPort: _ntohs(rows[i].dwLocalPort),
          remoteAddress: _ipv6(rows[i].ucRemoteAddr),
          remotePort: _ntohs(rows[i].dwRemotePort),
          state: _tcpState(rows[i].dwState),
          pid: rows[i].dwOwningPid,
          processName: processName(rows[i].dwOwningPid),
        ),
    ];
  }

  List<NetEndpoint> _parseUdp4(Pointer<Uint8> buffer, int count) {
    final rows = (buffer + 4).cast<_MibUdpRowOwnerPid>();
    return [
      for (var i = 0; i < count; i++)
        NetEndpoint(
          protocol: 'UDP',
          family: 4,
          localAddress: _ipv4(rows[i].dwLocalAddr),
          localPort: _ntohs(rows[i].dwLocalPort),
          remoteAddress: '',
          remotePort: 0,
          state: 'BOUND',
          pid: rows[i].dwOwningPid,
          processName: processName(rows[i].dwOwningPid),
        ),
    ];
  }

  List<NetEndpoint> _parseUdp6(Pointer<Uint8> buffer, int count) {
    final rows = (buffer + 4).cast<_MibUdp6RowOwnerPid>();
    return [
      for (var i = 0; i < count; i++)
        NetEndpoint(
          protocol: 'UDP',
          family: 6,
          localAddress: _ipv6(rows[i].ucLocalAddr),
          localPort: _ntohs(rows[i].dwLocalPort),
          remoteAddress: '',
          remotePort: 0,
          state: 'BOUND',
          pid: rows[i].dwOwningPid,
          processName: processName(rows[i].dwOwningPid),
        ),
    ];
  }

  /// Owner of a local TCP port, used to attribute proxy clients.
  NetEndpoint? findLocalTcp(int localPort, {int? remotePort}) {
    for (final endpoint in [
      ..._readTcp(ipv6: false),
      ..._readTcp(ipv6: true),
    ]) {
      if (endpoint.localPort != localPort) {
        continue;
      }
      if (remotePort != null && endpoint.remotePort != remotePort) {
        continue;
      }
      return endpoint;
    }
    return null;
  }

  String processName(int pid) {
    if (pid == 0) {
      return 'Idle';
    }
    if (pid == 4) {
      return 'System';
    }
    final cached = _processCache[pid];
    if (cached != null) {
      return cached;
    }

    final handle = _openProcess(_processQueryLimitedInformation, 0, pid);
    if (handle == 0) {
      final fallback = 'pid-$pid';
      _processCache[pid] = fallback;
      return fallback;
    }

    return using((arena) {
      final size = arena<Uint32>();
      size.value = 32768;
      final name = arena<Uint16>(size.value).cast<Utf16>();
      final ok = _queryFullProcessImageName(handle, 0, name, size);
      _closeHandle(handle);
      if (ok == 0) {
        final fallback = 'pid-$pid';
        _processCache[pid] = fallback;
        return fallback;
      }
      final path = name.toDartString();
      final slash = path.replaceAll('/', '\\').lastIndexOf('\\');
      final base = slash == -1 ? path : path.substring(slash + 1);
      _processCache[pid] = base;
      return base;
    });
  }
}

class WindowsNetException implements Exception {
  WindowsNetException(this.message);

  final String message;

  @override
  String toString() => message;
}

void enableVirtualTerminal() {
  if (!Platform.isWindows) {
    return;
  }
  final stdoutHandle = _getStdHandle(-11);
  if (stdoutHandle == 0 || stdoutHandle == -1) {
    return;
  }
  using((arena) {
    final mode = arena<Uint32>();
    if (_getConsoleMode(stdoutHandle, mode) == 0) {
      return;
    }
    _setConsoleMode(
      stdoutHandle,
      mode.value | _enableVirtualTerminalProcessing,
    );
  });
}

int _ntohs(int value) => ((value & 0xFF) << 8) | ((value >> 8) & 0xFF);

int _stateRank(NetEndpoint endpoint) {
  if (endpoint.isEstablished) {
    return 0;
  }
  if (endpoint.isListen) {
    return 1;
  }
  if (endpoint.protocol == 'UDP') {
    return 2;
  }
  return 3;
}

bool _isUnspecified(String address) {
  return address == '0.0.0.0' ||
      address == '::' ||
      address == '0:0:0:0:0:0:0:0';
}

String _formatHostPort(String address, int port) {
  if (address.contains(':')) {
    return '[$address]:$port';
  }
  return '$address:$port';
}

String _ipv4(int addr) {
  return '${addr & 0xFF}.'
      '${(addr >> 8) & 0xFF}.'
      '${(addr >> 16) & 0xFF}.'
      '${(addr >> 24) & 0xFF}';
}

String _ipv6(Array<Uint8> bytes) {
  final parts = <String>[];
  for (var i = 0; i < 16; i += 2) {
    parts.add(((bytes[i] << 8) | bytes[i + 1]).toRadixString(16));
  }
  return parts.join(':');
}

String _tcpState(int state) {
  return switch (state) {
    1 => 'CLOSED',
    2 => 'LISTEN',
    3 => 'SYN_SENT',
    4 => 'SYN_RCVD',
    5 => 'ESTABLISHED',
    6 => 'FIN_WAIT1',
    7 => 'FIN_WAIT2',
    8 => 'CLOSE_WAIT',
    9 => 'CLOSING',
    10 => 'LAST_ACK',
    11 => 'TIME_WAIT',
    12 => 'DELETE_TCB',
    _ => 'STATE_$state',
  };
}
