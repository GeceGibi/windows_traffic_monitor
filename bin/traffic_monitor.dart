import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:windows_traffic_monitor/src/win32_net.dart';

void main(List<String> args) async {
  if (!Platform.isWindows) {
    stderr.writeln('This program only runs on Windows.');
    exitCode = 1;
    return;
  }

  final options = _Options.parse(args);
  if (options.help) {
    stdout.writeln(_usage);
    return;
  }

  enableVirtualTerminal();
  final monitor = WindowsNetMonitor();
  Snapshot? previous;
  var first = true;

  stdout.writeln(
    'Windows socket monitor — every TCP/UDP endpoint the OS exposes. '
    'No packet payloads. Ctrl+C to exit.',
  );

  Timer? timer;
  void tick() {
    try {
      final snap = monitor.capture();
      _render(snap, previous, options, clear: !first);
      previous = snap;
      first = false;
    } on WindowsNetException catch (error) {
      stderr.writeln(error);
      timer?.cancel();
      exitCode = 1;
    }
  }

  tick();
  timer = Timer.periodic(Duration(milliseconds: options.intervalMs), (_) {
    tick();
  });
}

const _usage = '''
Usage: dart run bin/traffic_monitor.dart [options]

Shows every TCP and UDP socket Windows reports (listen, established,
time-wait, bound UDP) plus adapter and IP/TCP/UDP/ICMP counters.

  --established       Only ESTABLISHED TCP
  --listen            Only listening TCP sockets
  --tcp               Hide UDP
  --process=NAME      Filter by process name (substring)
  --limit=N           Max socket rows (default 60, 0 = all)
  --interval=N        Refresh interval in seconds (default 1)
  --no-color          Disable ANSI colors
  --help              Show this help

Requires Windows. Run elevated to resolve more process names.
Metadata only — packet contents are never captured.
''';

class _Options {
  const _Options({
    required this.established,
    required this.listen,
    required this.tcpOnly,
    required this.process,
    required this.limit,
    required this.intervalMs,
    required this.color,
    required this.help,
  });

  final bool established;
  final bool listen;
  final bool tcpOnly;
  final String? process;
  final int limit;
  final int intervalMs;
  final bool color;
  final bool help;

  factory _Options.parse(List<String> args) {
    var established = false;
    var listen = false;
    var tcpOnly = false;
    String? process;
    var limit = 60;
    var intervalMs = 1000;
    var color = true;
    var help = false;

    for (final arg in args) {
      if (arg == '--established') {
        established = true;
      } else if (arg == '--listen') {
        listen = true;
      } else if (arg == '--tcp') {
        tcpOnly = true;
      } else if (arg == '--no-color') {
        color = false;
      } else if (arg == '--help' || arg == '-h') {
        help = true;
      } else if (arg.startsWith('--process=')) {
        process = arg.substring(10).toLowerCase();
      } else if (arg.startsWith('--limit=')) {
        limit = int.tryParse(arg.substring(8)) ?? 60;
      } else if (arg.startsWith('--interval=')) {
        final seconds = num.tryParse(arg.substring(11)) ?? 1;
        intervalMs = math.max(200, (seconds * 1000).round());
      } else if (arg == '--all' || arg == '--udp') {
        // Kept so older flags still run; everything is already the default.
      } else {
        stderr.writeln('Unknown option: $arg');
        help = true;
      }
    }

    return _Options(
      established: established,
      listen: listen,
      tcpOnly: tcpOnly,
      process: process,
      limit: limit,
      intervalMs: intervalMs,
      color: color,
      help: help,
    );
  }
}

void _render(
  Snapshot current,
  Snapshot? previous,
  _Options options, {
  required bool clear,
}) {
  bool visible(NetEndpoint socket) {
    if (options.tcpOnly && socket.protocol != 'TCP') {
      return false;
    }
    if (options.established && !socket.isEstablished) {
      return false;
    }
    if (options.listen && !socket.isListen) {
      return false;
    }
    if (options.process != null &&
        !socket.processName.toLowerCase().contains(options.process!)) {
      return false;
    }
    return true;
  }

  final sockets = current.endpoints.where(visible).toList();

  final previousKeys = <String>{
    if (previous != null)
      for (final socket in previous.endpoints) socket.key,
  };
  final currentKeys = <String>{
    for (final socket in current.endpoints) socket.key,
  };
  final opened = [
    for (final socket in current.endpoints)
      if (previous != null &&
          !previousKeys.contains(socket.key) &&
          visible(socket))
        socket,
  ];
  final closed = [
    if (previous != null)
      for (final socket in previous.endpoints)
        if (!currentKeys.contains(socket.key) && visible(socket)) socket,
  ];

  final elapsed = previous == null
      ? 1.0
      : current.capturedAt.difference(previous.capturedAt).inMilliseconds /
          1000.0;
  final seconds = elapsed <= 0 ? 1.0 : elapsed;
  final stackDelta = previous == null
      ? null
      : _StackDelta.from(current.stack, previous.stack, seconds);

  final buffer = StringBuffer();
  if (clear) {
    buffer.write('\x1b[H\x1b[J');
  }

  buffer.writeln(_style(options, '1', 'WINDOWS SOCKET MONITOR'));
  buffer.writeln(
    'Updated ${current.capturedAt.toLocal()}   '
    'refresh ${options.intervalMs} ms   '
    '${sockets.length} sockets visible   '
    '+${opened.length} / -${closed.length} this tick',
  );
  buffer.writeln();

  _writeStack(buffer, current.stack, stackDelta, options);
  buffer.writeln();
  _writeAdapters(buffer, current, previous, seconds, options);
  buffer.writeln();
  _writeProcesses(buffer, sockets, options);
  buffer.writeln();
  _writeEvents(buffer, opened, closed, options);
  buffer.writeln();
  _writeSockets(buffer, sockets, opened, options);

  stdout.write(buffer);
}

void _writeStack(
  StringBuffer buffer,
  StackStats stack,
  _StackDelta? delta,
  _Options options,
) {
  buffer.writeln(_style(options, '1', 'STACK COUNTERS'));
  buffer.writeln(
    'IP    recv ${_count(stack.ipInReceives)}  '
    'deliver ${_count(stack.ipInDelivers)}  '
    'out ${_count(stack.ipOutRequests)}'
    '${delta == null ? '' : '   Δ ${_perSec(delta.ipIn)}/s in  ${_perSec(delta.ipOut)}/s out'}',
  );
  buffer.writeln(
    'TCP   estab ${stack.tcpEstablished}  '
    'conns ${_count(stack.tcpConnections)}  '
    'segs in ${_count(stack.tcpInSegs)}  '
    'out ${_count(stack.tcpOutSegs)}  '
    'retrans ${_count(stack.tcpRetransSegs)}'
    '${delta == null ? '' : '   Δ ${_perSec(delta.tcpIn)}/s in  ${_perSec(delta.tcpOut)}/s out'}',
  );
  buffer.writeln(
    'UDP   in ${_count(stack.udpInDatagrams)}  '
    'out ${_count(stack.udpOutDatagrams)}  '
    'no-port ${_count(stack.udpNoPorts)}  '
    'err ${_count(stack.udpInErrors)}'
    '${delta == null ? '' : '   Δ ${_perSec(delta.udpIn)}/s in  ${_perSec(delta.udpOut)}/s out'}',
  );
  buffer.writeln(
    'ICMP  in ${_count(stack.icmpInMsgs)}  '
    'out ${_count(stack.icmpOutMsgs)}'
    '${delta == null ? '' : '   Δ ${_perSec(delta.icmpIn)}/s in  ${_perSec(delta.icmpOut)}/s out'}',
  );
}

void _writeAdapters(
  StringBuffer buffer,
  Snapshot current,
  Snapshot? previous,
  double seconds,
  _Options options,
) {
  buffer.writeln(_style(options, '1', 'ADAPTERS'));
  buffer.writeln(
    '${_pad('Name', 28)}'
    '${_pad('Down', 12)}'
    '${_pad('Up', 12)}'
    '${_pad('In total', 14)}'
    '${_pad('Out total', 14)}'
    'Status',
  );

  var totalInRate = 0;
  var totalOutRate = 0;
  for (final adapter in current.adapters) {
    if (adapter.isLoopback || !adapter.isUp) {
      continue;
    }
    AdapterCounters? before;
    if (previous != null) {
      for (final adapterBefore in previous.adapters) {
        if (adapterBefore.index == adapter.index) {
          before = adapterBefore;
          break;
        }
      }
    }
    final inRate = before == null
        ? 0
        : _rate(adapter.inOctets, before.inOctets, seconds);
    final outRate = before == null
        ? 0
        : _rate(adapter.outOctets, before.outOctets, seconds);
    totalInRate += inRate;
    totalOutRate += outRate;
    buffer.writeln(
      '${_pad(_clip(adapter.name, 26), 28)}'
      '${_pad('${_bytes(inRate)}/s', 12)}'
      '${_pad('${_bytes(outRate)}/s', 12)}'
      '${_pad(_bytes(adapter.inOctets), 14)}'
      '${_pad(_bytes(adapter.outOctets), 14)}'
      'up',
    );
  }
  buffer.writeln(
    '${_pad('TOTAL', 28)}'
    '${_pad('${_bytes(totalInRate)}/s', 12)}'
    '${_pad('${_bytes(totalOutRate)}/s', 12)}',
  );
}

void _writeProcesses(
  StringBuffer buffer,
  List<NetEndpoint> sockets,
  _Options options,
) {
  final grouped = <String, _ProcessSockets>{};
  for (final socket in sockets) {
    final key = '${socket.pid}|${socket.processName}';
    final row = grouped.putIfAbsent(
      key,
      () => _ProcessSockets(socket.processName, socket.pid),
    );
    row.total++;
    if (socket.protocol == 'TCP') {
      row.tcp++;
    } else {
      row.udp++;
    }
    if (socket.isEstablished) {
      row.established++;
    }
    if (socket.isListen) {
      row.listen++;
    }
  }

  final rows = grouped.values.toList()
    ..sort((a, b) => b.total.compareTo(a.total));

  buffer.writeln(
    _style(options, '1', 'PROCESSES  (${rows.length} with sockets)'),
  );
  buffer.writeln(
    '${_pad('Process', 22)}'
    '${_pad('PID', 8)}'
    '${_pad('Total', 8)}'
    '${_pad('TCP', 7)}'
    '${_pad('UDP', 7)}'
    '${_pad('Estab', 8)}'
    'Listen',
  );
  for (final row in rows.take(15)) {
    buffer.writeln(
      '${_pad(_clip(row.name, 20), 22)}'
      '${_pad('${row.pid}', 8)}'
      '${_pad('${row.total}', 8)}'
      '${_pad('${row.tcp}', 7)}'
      '${_pad('${row.udp}', 7)}'
      '${_pad('${row.established}', 8)}'
      '${row.listen}',
    );
  }
  if (rows.length > 15) {
    buffer.writeln('... ${rows.length - 15} more processes');
  }
}

void _writeEvents(
  StringBuffer buffer,
  List<NetEndpoint> opened,
  List<NetEndpoint> closed,
  _Options options,
) {
  buffer.writeln(_style(options, '1', 'SOCKET EVENTS'));
  if (opened.isEmpty && closed.isEmpty) {
    buffer.writeln('  (no open/close since last refresh)');
    return;
  }
  for (final socket in opened.take(8)) {
    buffer.writeln(
      _style(
        options,
        '32',
        '  + ${_clip(socket.processName, 18)}  '
        '${socket.protoLabel} ${socket.state}  '
        '${socket.local} -> ${socket.remote}',
      ),
    );
  }
  for (final socket in closed.take(8)) {
    buffer.writeln(
      _style(
        options,
        '31',
        '  - ${_clip(socket.processName, 18)}  '
        '${socket.protoLabel} ${socket.state}  '
        '${socket.local} -> ${socket.remote}',
      ),
    );
  }
  final extra = (opened.length - 8).clamp(0, opened.length) +
      (closed.length - 8).clamp(0, closed.length);
  if (extra > 0) {
    buffer.writeln('  ... $extra more events');
  }
}

void _writeSockets(
  StringBuffer buffer,
  List<NetEndpoint> sockets,
  List<NetEndpoint> opened,
  _Options options,
) {
  final openedKeys = {for (final socket in opened) socket.key};
  final limit = options.limit <= 0 ? sockets.length : options.limit;

  buffer.writeln(_style(options, '1', 'SOCKETS  (${sockets.length})'));
  buffer.writeln(
    '${_pad('', 3)}'
    '${_pad('Process', 20)}'
    '${_pad('PID', 8)}'
    '${_pad('Proto', 7)}'
    '${_pad('State', 13)}'
    '${_pad('Local', 30)}'
    'Remote',
  );

  for (final socket in sockets.take(limit)) {
    final mark = openedKeys.contains(socket.key) ? '+' : ' ';
    final line =
        '${_pad(mark, 3)}'
        '${_pad(_clip(socket.processName, 18), 20)}'
        '${_pad('${socket.pid}', 8)}'
        '${_pad(socket.protoLabel, 7)}'
        '${_pad(socket.state, 13)}'
        '${_pad(_clip(socket.local, 28), 30)}'
        '${socket.remote}';
    buffer.writeln(
      mark == '+' ? _style(options, '32', line) : line,
    );
  }
  if (sockets.length > limit) {
    buffer.writeln('... ${sockets.length - limit} more  (use --limit=0 for all)');
  }
}

class _ProcessSockets {
  _ProcessSockets(this.name, this.pid);

  final String name;
  final int pid;
  int total = 0;
  int tcp = 0;
  int udp = 0;
  int established = 0;
  int listen = 0;
}

class _StackDelta {
  const _StackDelta({
    required this.ipIn,
    required this.ipOut,
    required this.tcpIn,
    required this.tcpOut,
    required this.udpIn,
    required this.udpOut,
    required this.icmpIn,
    required this.icmpOut,
  });

  final int ipIn;
  final int ipOut;
  final int tcpIn;
  final int tcpOut;
  final int udpIn;
  final int udpOut;
  final int icmpIn;
  final int icmpOut;

  factory _StackDelta.from(StackStats now, StackStats before, double seconds) {
    int perSec(int current, int previous) {
      var delta = current - previous;
      if (delta < 0) {
        delta += 0x100000000;
      }
      return (delta / seconds).round();
    }

    return _StackDelta(
      ipIn: perSec(now.ipInReceives, before.ipInReceives),
      ipOut: perSec(now.ipOutRequests, before.ipOutRequests),
      tcpIn: perSec(now.tcpInSegs, before.tcpInSegs),
      tcpOut: perSec(now.tcpOutSegs, before.tcpOutSegs),
      udpIn: perSec(now.udpInDatagrams, before.udpInDatagrams),
      udpOut: perSec(now.udpOutDatagrams, before.udpOutDatagrams),
      icmpIn: perSec(now.icmpInMsgs, before.icmpInMsgs),
      icmpOut: perSec(now.icmpOutMsgs, before.icmpOutMsgs),
    );
  }
}

int _rate(int now, int before, double seconds) {
  var delta = now - before;
  if (delta < 0) {
    delta += 0x100000000;
  }
  return (delta / seconds).round();
}

String _bytes(int value) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var size = value.toDouble();
  var unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  final digits = unit == 0 || size >= 10 ? 0 : 1;
  return '${size.toStringAsFixed(digits)} ${units[unit]}';
}

String _count(int value) {
  if (value >= 1000000) {
    return '${(value / 1000000).toStringAsFixed(1)}M';
  }
  if (value >= 10000) {
    return '${(value / 1000).toStringAsFixed(1)}K';
  }
  return '$value';
}

String _perSec(int value) => _count(value);

String _pad(String value, int width) {
  if (value.length >= width) {
    return value.substring(0, width);
  }
  return value.padRight(width);
}

String _clip(String value, int width) {
  if (value.length <= width) {
    return value;
  }
  return '${value.substring(0, width - 1)}…';
}

String _style(_Options options, String code, String text) {
  if (!options.color) {
    return text;
  }
  return '\x1b[${code}m$text\x1b[0m';
}
