import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:windows_traffic_monitor/windows_traffic_monitor.dart';

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

  if (options.listProcesses) {
    _printProcesses();
    return;
  }

  await _run(options);
}

Future<void> _run(_Options options) async {
  final table = ProcessTable();
  final resolver = TargetResolver(table);

  ProxyTarget target;
  if (options.launch != null ||
      options.pid != null ||
      options.process != null) {
    target = resolver.resolve(
      name: options.process,
      pid: options.pid,
      launchPath: options.launch,
      launchArgs: options.launchArgs,
    );
    if (options.launch == null && target.processes.isEmpty) {
      stderr.writeln(
        'No running process matched '
        '${options.pid != null ? 'pid ${options.pid}' : options.process}.',
      );
      exitCode = 1;
      return;
    }
  } else {
    final picked = await resolver.pickInteractive();
    if (picked == null) {
      exitCode = 1;
      return;
    }
    target = picked;
  }

  final monitor = WindowsNetMonitor();
  late final AppProxyServer proxy;
  proxy = AppProxyServer(
    host: options.listenAddress,
    port: options.port,
    resolveOwner: (clientPort) {
      final endpoint = monitor.findLocalTcp(
        clientPort,
        remotePort: proxy.boundPort,
      );
      if (endpoint == null) {
        return null;
      }
      return (pid: endpoint.pid, name: endpoint.processName);
    },
    includeFlow: (pid, name) => target.matches(name, pid),
  );
  Process? child;

  final session = ProxySession(target: target, proxy: proxy);
  try {
    await session.start();
  } catch (error) {
    stderr.writeln('Failed to start proxy: $error');
    await session.stop();
    exitCode = 1;
    return;
  }

  if (options.launch != null) {
    try {
      child = await const ProxyLauncher().start(
        executable: options.launch!,
        args: options.launchArgs,
        proxyUrl: 'http://${proxy.listenLabel}',
        freshProfile: options.freshProfile,
      );
      target = ProxyTarget(
        processes: [
          ProcessInfo(
            pid: child.pid,
            name: target.filter ?? options.launch!,
            path: options.launch!,
          ),
        ],
        launchPath: options.launch,
        launchArgs: options.launchArgs,
        filter: target.filter,
      );
    } catch (error) {
      stderr.writeln('Failed to launch ${options.launch}: $error');
      await session.stop();
      exitCode = 1;
      return;
    }
  }

  PayloadTap? tap;
  try {
    tap = await PayloadTap.start();
  } catch (error) {
    stderr.writeln('Payload tap failed: $error');
  }

  stdout.writeln(
    'Logging only ${target.label}.  '
    'DATA needs Administrator.  HTTPS payload is encrypted.  Ctrl+C to exit.',
  );

  var shuttingDown = false;
  Future<void> shutdown() async {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    tap?.stop();
    child?.kill();
    await session.stop();
  }

  ProcessSignal.sigint.watch().listen((_) async {
    await shutdown();
    exit(0);
  });

  Snapshot? previous;
  var first = true;

  void tick() {
    try {
      final snap = monitor.capture(
        only: (name, pid) => target.matches(name, pid),
      );
      tap?.setConnections(snap.endpoints);
      _render(
        snap,
        previous,
        options,
        proxy,
        target,
        tap: tap,
        clear: !first,
      );
      previous = snap;
      first = false;
    } on WindowsNetException catch (error) {
      stderr.writeln(error);
    }
  }

  tick();
  Timer.periodic(Duration(milliseconds: options.intervalMs), (_) {
    if (!shuttingDown) {
      tick();
    }
  });
}

void _printProcesses() {
  final rows = ProcessTable().list();
  stdout.writeln('${_pad('PID', 10)}${_pad('Process', 28)}Path');
  for (final process in rows) {
    stdout.writeln(
      '${_pad('${process.pid}', 10)}'
      '${_pad(_clip(process.name, 26), 28)}'
      '${process.path}',
    );
  }
}

const _usage = '''
Usage: traffic_monitor.exe
       traffic_monitor.exe --pid=1234
       traffic_monitor.exe --launch=APP.exe [-- args]

No flags: lists live PIDs and waits for you to pick one.

Logs only that process: its sockets and the HTTP/CONNECT flows it
sends through the local proxy. Nothing else on the machine is logged.

  --process=NAME      Target process name (substring)
  --pid=N             Target process id
  --launch=PATH       Start the app pointed at this proxy
  -- args             Extra arguments after -- go to the launched app
  --port=N            Proxy listen port (default 8888)
  --listen=ADDR       Bind address (default 127.0.0.1)
  --fresh-profile     Chromium: temp --user-data-dir so flags apply
  --no-fresh-profile  Chromium: reuse the existing profile
  --list              Print processes and exit
  --established       Only ESTABLISHED TCP
  --listen-sockets    Only listening TCP sockets
  --tcp               Hide UDP
  --limit=N           Max socket rows (default 60, 0 = all)
  --interval=N        Refresh interval in seconds (default 1)
  --no-color          Disable ANSI colors
  --help              Show this help

Requires Windows. Run as Administrator to see DATA payloads.
HTTPS/TLS content stays encrypted. Plain HTTP/text is shown.
''';

class _Options {
  const _Options({
    required this.established,
    required this.listen,
    required this.tcpOnly,
    required this.process,
    required this.pid,
    required this.limit,
    required this.intervalMs,
    required this.color,
    required this.help,
    required this.launch,
    required this.launchArgs,
    required this.port,
    required this.listenAddress,
    required this.freshProfile,
    required this.listProcesses,
  });

  final bool established;
  final bool listen;
  final bool tcpOnly;
  final String? process;
  final int? pid;
  final int limit;
  final int intervalMs;
  final bool color;
  final bool help;
  final String? launch;
  final List<String> launchArgs;
  final int port;
  final String listenAddress;
  final bool freshProfile;
  final bool listProcesses;

  factory _Options.parse(List<String> args) {
    var established = false;
    var listen = false;
    var tcpOnly = false;
    String? process;
    int? pid;
    var limit = 60;
    var intervalMs = 1000;
    var color = true;
    var help = false;
    String? launch;
    var launchArgs = <String>[];
    var port = 8888;
    var listenAddress = '127.0.0.1';
    var freshProfile = true;
    var listProcesses = false;

    final split = args.indexOf('--');
    final ours = split == -1 ? args : args.sublist(0, split);
    if (split != -1) {
      launchArgs = args.sublist(split + 1);
    }

    for (final arg in ours) {
      if (arg == '--established') {
        established = true;
      } else if (arg == '--listen' || arg == '--listen-sockets') {
        listen = true;
      } else if (arg == '--tcp') {
        tcpOnly = true;
      } else if (arg == '--no-color') {
        color = false;
      } else if (arg == '--help' || arg == '-h') {
        help = true;
      } else if (arg == '--proxy' ||
          arg == '--system' ||
          arg == '--no-system') {
        // Removed: this tool only logs one app, never the system proxy.
      } else if (arg == '--fresh-profile') {
        freshProfile = true;
      } else if (arg == '--no-fresh-profile') {
        freshProfile = false;
      } else if (arg == '--list') {
        listProcesses = true;
      } else if (arg.startsWith('--process=')) {
        process = arg.substring(10).toLowerCase();
      } else if (arg.startsWith('--pid=')) {
        pid = int.tryParse(arg.substring(6));
      } else if (arg.startsWith('--launch=')) {
        launch = arg.substring(9);
      } else if (arg.startsWith('--port=')) {
        port = int.tryParse(arg.substring(7)) ?? 8888;
      } else if (arg.startsWith('--listen=')) {
        listenAddress = arg.substring(9);
        if (listenAddress.isEmpty) {
          listenAddress = '127.0.0.1';
        }
      } else if (arg.startsWith('--limit=')) {
        limit = int.tryParse(arg.substring(8)) ?? 60;
      } else if (arg.startsWith('--interval=')) {
        final seconds = num.tryParse(arg.substring(11)) ?? 1;
        intervalMs = math.max(200, (seconds * 1000).round());
      } else if (arg == '--all' || arg == '--udp') {
        // Kept so older flags still run.
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
      pid: pid,
      limit: limit,
      intervalMs: intervalMs,
      color: color,
      help: help,
      launch: launch,
      launchArgs: launchArgs,
      port: port,
      listenAddress: listenAddress,
      freshProfile: freshProfile,
      listProcesses: listProcesses,
    );
  }
}

void _render(
  Snapshot current,
  Snapshot? previous,
  _Options options,
  AppProxyServer proxy,
  ProxyTarget target, {
  PayloadTap? tap,
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
    return target.matches(socket.processName, socket.pid);
  }

  final sockets = current.endpoints.where(visible).toList();

  final previousKeys = <String>{
    if (previous != null)
      for (final socket in previous.endpoints) socket.key,
  };
  final opened = [
    for (final socket in current.endpoints)
      if (previous != null &&
          !previousKeys.contains(socket.key) &&
          visible(socket))
        socket,
  ];

  final buffer = StringBuffer();
  if (clear) {
    buffer.write('\x1b[H\x1b[J');
  }

  buffer.writeln(_style(options, '1', 'APP LOG'));
  buffer.writeln(
    'Target ${target.label}   '
    'proxy ${proxy.listenLabel}   '
    'flows ${proxy.totalFlows}   '
    'tunnels ${proxy.openTunnels}   '
    '↑ ${_bytes(proxy.bytesUp)}  ↓ ${_bytes(proxy.bytesDown)}   '
    '${current.capturedAt.toLocal()}',
  );
  buffer.writeln();
  _writeData(buffer, tap, proxy, options);
  buffer.writeln();
  _writeFlows(buffer, proxy, options);
  buffer.writeln();
  _writeSockets(buffer, sockets, opened, options);
  stdout.write(buffer);
}

void _writeData(
  StringBuffer buffer,
  PayloadTap? tap,
  AppProxyServer proxy,
  _Options options,
) {
  final tapStatus = tap?.error ?? tap?.status ?? 'off';
  buffer.writeln(_style(options, '1', 'DATA  tap=$tapStatus'));

  final rows = <_DataRow>[
    for (final chunk in tap?.chunks ?? const <PayloadChunk>[])
      _DataRow(
        direction: chunk.direction,
        kind: chunk.kind,
        title: '${chunk.local} -> ${chunk.remote}',
        bytes: chunk.bytes,
        text: chunk.text,
      ),
    for (final flow in proxy.flows)
      if (flow.requestLog.isNotEmpty || flow.responseLog.isNotEmpty)
        _DataRow(
          direction: 'http',
          kind: flow.method,
          title: '${flow.authority} ${flow.method == 'CONNECT' ? '' : flow.path}',
          bytes: flow.bytesUp + flow.bytesDown,
          text: [
            if (flow.requestLog.isNotEmpty) '>> ${flow.requestLog}',
            if (flow.responseLog.isNotEmpty) '<< ${flow.responseLog}',
          ].join('\n'),
        ),
  ];

  if (rows.isEmpty) {
    buffer.writeln(
      tap?.error != null
          ? '  ${tap!.error}'
          : '  (henuz payload yok — admin gerekir, HTTPS sifreli kalir)',
    );
    return;
  }

  for (final row in rows.reversed.take(8)) {
    final arrow = switch (row.direction) {
      'up' => '↑',
      'down' => '↓',
      _ => '*',
    };
    buffer.writeln(
      '  $arrow ${_pad(row.kind, 5)} ${_bytes(row.bytes).padRight(8)} '
      '${_clip(row.title.trim(), 70)}',
    );
    for (final line in row.text.split('\n').take(6)) {
      if (line.trim().isEmpty) {
        continue;
      }
      buffer.writeln('      ${_clip(line, 110)}');
    }
  }
}

class _DataRow {
  const _DataRow({
    required this.direction,
    required this.kind,
    required this.title,
    required this.bytes,
    required this.text,
  });

  final String direction;
  final String kind;
  final String title;
  final int bytes;
  final String text;
}

void _writeFlows(StringBuffer buffer, AppProxyServer proxy, _Options options) {
  final rows = proxy.flows.reversed.take(18).toList();
  buffer.writeln(_style(options, '1', 'FLOWS  (${proxy.totalFlows})'));
  buffer.writeln(
    '${_pad('', 3)}'
    '${_pad('Meth', 8)}'
    '${_pad('Code', 6)}'
    '${_pad('Host', 32)}'
    '${_pad('Path', 28)}'
    '${_pad('Up', 10)}'
    '${_pad('Down', 10)}'
    'Age',
  );
  if (rows.isEmpty) {
    buffer.writeln(
      '  (no HTTP yet — use --launch so this app is sent through the proxy)',
    );
    return;
  }
  for (final flow in rows) {
    final mark = flow.open ? '*' : ' ';
    final code = flow.error != null
        ? 'ERR'
        : (flow.status == 0 ? '-' : '${flow.status}');
    final line =
        '${_pad(mark, 3)}'
        '${_pad(flow.method, 8)}'
        '${_pad(code, 6)}'
        '${_pad(_clip(flow.authority, 30), 32)}'
        '${_pad(_clip(flow.method == 'CONNECT' ? '-' : flow.path, 26), 28)}'
        '${_pad(_bytes(flow.bytesUp), 10)}'
        '${_pad(_bytes(flow.bytesDown), 10)}'
        '${flow.duration.inMilliseconds}ms';
    buffer.writeln(
      flow.error != null
          ? _style(options, '31', line)
          : flow.open
          ? _style(options, '33', line)
          : line,
    );
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
    buffer.writeln(mark == '+' ? _style(options, '32', line) : line);
  }
  if (sockets.length > limit) {
    buffer.writeln(
      '... ${sockets.length - limit} more  (use --limit=0 for all)',
    );
  }
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
