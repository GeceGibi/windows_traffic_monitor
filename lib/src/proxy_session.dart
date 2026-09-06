import 'dart:io';

import 'app_proxy.dart';
import 'win32_process.dart';

class ProxyTarget {
  const ProxyTarget({
    required this.processes,
    this.launchPath,
    this.launchArgs = const [],
    this.filter,
  });

  final List<ProcessInfo> processes;
  final String? launchPath;
  final List<String> launchArgs;
  final String? filter;

  String get label {
    if (launchPath != null) {
      return _base(launchPath!);
    }
    if (filter != null && processes.isEmpty) {
      return filter!;
    }
    if (processes.isEmpty) {
      return '(none)';
    }
    final names = {for (final process in processes) process.name};
    if (names.length == 1) {
      final pids = processes.map((p) => p.pid).join(', ');
      return '${names.first} [$pids]';
    }
    return '${processes.length} processes';
  }

  Set<int> get pids => {for (final process in processes) process.pid};

  bool matches(String processName, int pid) {
    if (pids.contains(pid)) {
      return true;
    }
    final needle = (filter ?? (launchPath == null ? null : _base(launchPath!)))
        ?.toLowerCase();
    if (needle == null || needle.isEmpty) {
      return pids.isEmpty;
    }
    return processName.toLowerCase().contains(needle);
  }
}

class ProxySession {
  ProxySession({required this.target, required this.proxy, this.child});

  final ProxyTarget target;
  final AppProxyServer proxy;
  final Process? child;

  Future<void> start() => proxy.start();

  Future<void> stop() async {
    await proxy.stop();
    child?.kill();
  }
}

class ProxyLauncher {
  const ProxyLauncher();

  Future<Process> start({
    required String executable,
    required List<String> args,
    required String proxyUrl,
    required bool freshProfile,
  }) async {
    final environment = <String, String>{
      ...Platform.environment,
      'HTTP_PROXY': proxyUrl,
      'HTTPS_PROXY': proxyUrl,
      'http_proxy': proxyUrl,
      'https_proxy': proxyUrl,
      'ALL_PROXY': proxyUrl,
      'NO_PROXY': 'localhost,127.0.0.1',
      'no_proxy': 'localhost,127.0.0.1',
    };

    final launchArgs = <String>[];
    if (isChromiumExecutable(executable)) {
      launchArgs
        ..add('--proxy-server=$proxyUrl')
        ..add('--proxy-bypass-list=<-loopback>');
      if (freshProfile) {
        final dir = await Directory.systemTemp.createTemp('wtm-profile-');
        launchArgs.add('--user-data-dir=${dir.path}');
      }
    }
    launchArgs.addAll(args);

    return Process.start(
      executable,
      launchArgs,
      environment: environment,
      mode: ProcessStartMode.detached,
    );
  }
}

class TargetResolver {
  TargetResolver(this.table);

  final ProcessTable table;

  ProxyTarget resolve({
    String? name,
    int? pid,
    String? launchPath,
    List<String> launchArgs = const [],
  }) {
    if (launchPath != null) {
      return ProxyTarget(
        processes: const [],
        launchPath: launchPath,
        launchArgs: launchArgs,
        filter: _base(launchPath),
      );
    }
    final matches = table.find(name: name, pid: pid);
    return ProxyTarget(processes: matches, filter: name);
  }

  Future<ProxyTarget?> pickInteractive({
    List<String> preferNames = const [],
  }) async {
    while (true) {
      final running = table.list();
      if (running.isEmpty) {
        stdout.writeln('Gorunen process yok.');
        return null;
      }

      final preferred = {for (final name in preferNames) name.toLowerCase()};
      running.sort((a, b) {
        final aHot = preferred.contains(a.name.toLowerCase()) ? 0 : 1;
        final bHot = preferred.contains(b.name.toLowerCase()) ? 0 : 1;
        if (aHot != bHot) {
          return aHot.compareTo(bHot);
        }
        final byName = a.name.toLowerCase().compareTo(b.name.toLowerCase());
        return byName != 0 ? byName : a.pid.compareTo(b.pid);
      });

      stdout.writeln();
      stdout.writeln('  ${'#'.padLeft(4)}  ${'PID'.padRight(8)}  Process');
      stdout.writeln('  ----  --------  --------');
      for (var i = 0; i < running.length; i++) {
        final process = running[i];
        stdout.writeln(
          '  ${'${i + 1}'.padLeft(4)}  '
          '${process.pid.toString().padRight(8)}  '
          '${process.name}',
        );
      }
      stdout.writeln();
      stdout.write('PID veya # sec (r=yenile, Enter=cikis): ');
      final line = stdin.readLineSync()?.trim();
      if (line == null || line.isEmpty) {
        return null;
      }
      if (line == 'r' || line == 'R') {
        continue;
      }

      final asInt = int.tryParse(line);
      if (asInt != null) {
        for (final process in running) {
          if (process.pid == asInt) {
            return ProxyTarget(processes: [process]);
          }
        }
        if (asInt >= 1 && asInt <= running.length) {
          return ProxyTarget(processes: [running[asInt - 1]]);
        }
        stdout.writeln('PID veya # yok: $asInt');
        continue;
      }

      final byName = [
        for (final process in running)
          if (process.name.toLowerCase().contains(line.toLowerCase())) process,
      ];
      if (byName.length == 1) {
        return ProxyTarget(processes: [byName.first]);
      }
      if (byName.isEmpty) {
        stdout.writeln('Eslesen process yok: $line');
        continue;
      }
      stdout.writeln('Birden fazla eslesme var, listedeki PID veya # yaz.');
    }
  }
}

String _base(String path) {
  final slash = path.replaceAll('/', '\\').lastIndexOf('\\');
  return slash == -1 ? path : path.substring(slash + 1);
}
