import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const int _processQueryLimitedInformation = 0x1000;

final DynamicLibrary _kernel32 = DynamicLibrary.open('kernel32.dll');

final int Function(Pointer<Uint32> ids, int bytes, Pointer<Uint32> needed)
_enumProcesses = _kernel32
    .lookupFunction<
      Int32 Function(Pointer<Uint32>, Uint32, Pointer<Uint32>),
      int Function(Pointer<Uint32>, int, Pointer<Uint32>)
    >('K32EnumProcesses');

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

class ProcessInfo {
  const ProcessInfo({
    required this.pid,
    required this.name,
    required this.path,
  });

  final int pid;
  final String name;
  final String path;

  @override
  String toString() => '$name ($pid)';
}

class ProcessTable {
  ProcessTable() {
    if (!Platform.isWindows) {
      throw UnsupportedError('Process listing only runs on Windows.');
    }
  }

  List<ProcessInfo> list() {
    return using((arena) {
      var capacity = 1024;
      while (true) {
        final ids = arena<Uint32>(capacity);
        final needed = arena<Uint32>();
        if (_enumProcesses(ids, capacity * 4, needed) == 0) {
          throw ProcessTableException('K32EnumProcesses failed.');
        }
        final count = needed.value ~/ 4;
        if (count >= capacity) {
          capacity *= 2;
          continue;
        }

        final result = <ProcessInfo>[];
        for (var i = 0; i < count; i++) {
          final pid = ids[i];
          if (pid == 0) {
            continue;
          }
          final path = _imagePath(pid);
          if (path == null) {
            continue;
          }
          result.add(ProcessInfo(pid: pid, name: _baseName(path), path: path));
        }
        result.sort((a, b) {
          final byName = a.name.toLowerCase().compareTo(b.name.toLowerCase());
          return byName != 0 ? byName : a.pid.compareTo(b.pid);
        });
        return result;
      }
    });
  }

  List<ProcessInfo> find({String? name, int? pid}) {
    final all = list();
    if (pid != null) {
      return [
        for (final process in all)
          if (process.pid == pid) process,
      ];
    }
    if (name == null || name.isEmpty) {
      return all;
    }
    final needle = name.toLowerCase();
    return [
      for (final process in all)
        if (process.name.toLowerCase().contains(needle) ||
            process.path.toLowerCase().contains(needle))
          process,
    ];
  }

  String? _imagePath(int pid) {
    final handle = _openProcess(_processQueryLimitedInformation, 0, pid);
    if (handle == 0) {
      return null;
    }
    return using((arena) {
      final size = arena<Uint32>();
      size.value = 32768;
      final name = arena<Uint16>(size.value).cast<Utf16>();
      final ok = _queryFullProcessImageName(handle, 0, name, size);
      _closeHandle(handle);
      if (ok == 0) {
        return null;
      }
      return name.toDartString();
    });
  }
}

class ProcessTableException implements Exception {
  ProcessTableException(this.message);

  final String message;

  @override
  String toString() => message;
}

String _baseName(String path) {
  final slash = path.replaceAll('/', '\\').lastIndexOf('\\');
  return slash == -1 ? path : path.substring(slash + 1);
}

const chromiumExecutables = {
  'chrome.exe',
  'msedge.exe',
  'brave.exe',
  'chromium.exe',
  'opera.exe',
  'vivaldi.exe',
  'arc.exe',
};

bool isChromiumExecutable(String pathOrName) {
  return chromiumExecutables.contains(_baseName(pathOrName).toLowerCase());
}
