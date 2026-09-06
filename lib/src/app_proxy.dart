import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'payload_tap.dart';

class ProxyFlow {
  ProxyFlow({
    required this.id,
    required this.startedAt,
    required this.method,
    required this.host,
    required this.port,
    required this.path,
    this.pid = 0,
    this.processName = '',
  });

  final int id;
  final DateTime startedAt;
  DateTime? endedAt;
  final String method;
  final String host;
  final int port;
  final String path;
  final int pid;
  final String processName;
  int status = 0;
  int bytesUp = 0;
  int bytesDown = 0;
  String? error;
  final StringBuffer requestLog = StringBuffer();
  final StringBuffer responseLog = StringBuffer();

  void appendPreview(StringBuffer into, List<int> data) {
    if (into.length >= 8192) {
      return;
    }
    final preview = previewPayload(data);
    if (into.isNotEmpty) {
      into.write('\n');
    }
    into.write(preview.text);
    if (into.length > 8192) {
      final keep = into.toString().substring(0, 8192);
      into
        ..clear()
        ..write(keep)
        ..write('\n…');
    }
  }

  bool get open => endedAt == null;

  String get authority => '$host:$port';

  String get target => method == 'CONNECT' ? authority : path;

  Duration get duration => (endedAt ?? DateTime.now()).difference(startedAt);
}

typedef ProxyFlowListener = void Function();
typedef ProxyOwnerLookup = ({int pid, String name})? Function(int clientPort);
typedef ProxyFlowFilter = bool Function(int pid, String name);

/// Local HTTP and CONNECT proxy. Binds to loopback only.
class AppProxyServer {
  AppProxyServer({
    this.host = '127.0.0.1',
    this.port = 8888,
    this.maxFlows = 300,
    this.onChange,
    this.resolveOwner,
    this.includeFlow,
  });

  final String host;
  final int port;
  final int maxFlows;
  final ProxyFlowListener? onChange;
  final ProxyOwnerLookup? resolveOwner;
  final ProxyFlowFilter? includeFlow;

  ServerSocket? _server;
  var _nextId = 1;
  final List<ProxyFlow> flows = <ProxyFlow>[];
  var bytesUp = 0;
  var bytesDown = 0;
  var totalFlows = 0;
  var openTunnels = 0;

  InternetAddress get address =>
      _server?.address ?? InternetAddress.loopbackIPv4;

  int get boundPort => _server?.port ?? port;

  String get listenLabel => '${address.address}:$boundPort';

  Future<void> start() async {
    _server = await ServerSocket.bind(InternetAddress(host), port);
    _server!.listen(
      _accept,
      onError: (Object error) {
        stderr.writeln('Proxy accept error: $error');
      },
    );
  }

  Future<void> stop() async {
    await _server?.close();
    _server = null;
  }

  void _accept(Socket client) {
    unawaited(_handleClient(client));
  }

  Future<void> _handleClient(Socket client) async {
    final incoming = _SocketReader(client);
    Socket? remote;
    ProxyFlow? flow;
    try {
      client.setOption(SocketOption.tcpNoDelay, true);
      final headerBytes = await incoming.readHeaders();
      if (headerBytes == null) {
        return;
      }

      final request = _HttpRequest.parse(headerBytes);
      if (request == null) {
        incoming.send(
          ascii.encode('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'),
        );
        return;
      }

      var owner = resolveOwner?.call(client.remotePort);
      if (owner == null && resolveOwner != null) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
        owner = resolveOwner!.call(client.remotePort);
      }
      final pid = owner?.pid ?? 0;
      final processName = owner?.name ?? '';
      if (includeFlow != null &&
          owner != null &&
          !includeFlow!(pid, processName)) {
        return;
      }

      flow = ProxyFlow(
        id: _nextId++,
        startedAt: DateTime.now(),
        method: request.method,
        host: request.host,
        port: request.port,
        path: request.path,
        pid: pid,
        processName: processName,
      );
      _addFlow(flow);
      flow.appendPreview(flow.requestLog, headerBytes);

      remote = await Socket.connect(
        request.host,
        request.port,
        timeout: const Duration(seconds: 15),
      );
      remote.setOption(SocketOption.tcpNoDelay, true);

      if (request.method == 'CONNECT') {
        flow.status = 200;
        openTunnels++;
        _notify();
        incoming.send(
          ascii.encode('HTTP/1.1 200 Connection Established\r\n\r\n'),
        );
        await incoming.pipeTo(
          remote,
          onUp: (n) => _countUp(flow!, n),
          onDown: (n) => _countDown(flow!, n),
          onUpBytes: (data) => flow!.appendPreview(flow.requestLog, data),
          onDownBytes: (data) => flow!.appendPreview(flow.responseLog, data),
        );
        return;
      }

      final forwarded = request.originFormBytes();
      remote.add(forwarded);
      _countUp(flow, forwarded.length);
      await incoming.pipeTo(
        remote,
        onUp: (n) => _countUp(flow!, n),
        onDown: (n) => _countDown(flow!, n),
        onUpBytes: (data) => flow!.appendPreview(flow.requestLog, data),
        onDownBytes: (data) => flow!.appendPreview(flow.responseLog, data),
        onStatus: (status) {
          flow!.status = status;
          _notify();
        },
      );
    } catch (error) {
      if (flow != null) {
        flow.error = '$error';
        if (flow.status == 0) {
          flow.status = 502;
        }
      }
      try {
        incoming.send(
          ascii.encode('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'),
        );
      } catch (_) {}
    } finally {
      if (flow != null && flow.open) {
        flow.endedAt = DateTime.now();
        if (flow.method == 'CONNECT' && flow.status == 200) {
          openTunnels = (openTunnels - 1).clamp(0, 1 << 30);
        }
        _notify();
      }
      incoming.close();
      try {
        await remote?.close();
      } catch (_) {
        remote?.destroy();
      }
    }
  }

  void _addFlow(ProxyFlow flow) {
    totalFlows++;
    flows.add(flow);
    if (flows.length > maxFlows) {
      flows.removeRange(0, flows.length - maxFlows);
    }
    _notify();
  }

  void _countUp(ProxyFlow flow, int n) {
    flow.bytesUp += n;
    bytesUp += n;
  }

  void _countDown(ProxyFlow flow, int n) {
    flow.bytesDown += n;
    bytesDown += n;
  }

  void _notify() {
    onChange?.call();
  }
}

/// Single-subscription socket reader that keeps leftover bytes after headers.
class _SocketReader {
  _SocketReader(this._client) {
    _sub = _client.listen(
      (data) {
        if (_sink != null) {
          _sink!.add(data);
          _onUp?.call(data.length);
          _onUpBytes?.call(data);
          return;
        }
        _buffer.add(data);
        _wait?.complete();
        _wait = null;
      },
      onError: (Object error) {
        _error = error;
        _wait?.complete();
        _wait = null;
        _sink?.addError(error);
      },
      onDone: () {
        _done = true;
        _wait?.complete();
        _wait = null;
        _sink?.close();
      },
      cancelOnError: false,
    );
  }

  final Socket _client;
  late final StreamSubscription<Uint8List> _sub;
  final BytesBuilder _buffer = BytesBuilder(copy: false);
  Completer<void>? _wait;
  Object? _error;
  var _done = false;
  Socket? _sink;
  void Function(int)? _onUp;
  void Function(List<int> data)? _onUpBytes;
  final BytesBuilder _responseHead = BytesBuilder(copy: false);

  void send(List<int> bytes) {
    _client.add(bytes);
  }

  Future<Uint8List?> readHeaders() async {
    while (true) {
      if (_error != null) {
        throw _error!;
      }
      final data = _buffer.toBytes();
      final end = _findHeaderEnd(data);
      if (end != -1) {
        final headers = Uint8List.fromList(data.sublist(0, end));
        final leftover = data.sublist(end + 4);
        _buffer.clear();
        if (leftover.isNotEmpty) {
          _buffer.add(leftover);
        }
        return headers;
      }
      if (_done) {
        return null;
      }
      if (data.length > 262144) {
        return null;
      }
      _wait = Completer<void>();
      await _wait!.future;
    }
  }

  Future<void> pipeTo(
    Socket remote, {
    required void Function(int) onUp,
    required void Function(int) onDown,
    void Function(List<int> data)? onUpBytes,
    void Function(List<int> data)? onDownBytes,
    void Function(int status)? onStatus,
  }) async {
    _onUp = (n) => onUp(n);
    _onUpBytes = onUpBytes;
    _sink = remote;
    final leftover = _buffer.takeBytes();
    if (leftover.isNotEmpty) {
      remote.add(leftover);
      onUp(leftover.length);
      onUpBytes?.call(leftover);
    }

    var statusRead = false;
    final down = remote.listen(
      (data) {
        _client.add(data);
        onDown(data.length);
        onDownBytes?.call(data);
        if (statusRead) {
          return;
        }
        _responseHead.add(data);
        final bytes = _responseHead.toBytes();
        final end = _findHeaderEnd(bytes);
        if (end != -1) {
          statusRead = true;
          final status = _parseStatus(bytes.sublist(0, end));
          if (status != 0) {
            onStatus?.call(status);
          }
        } else if (bytes.length > 8192) {
          statusRead = true;
        }
      },
      onError: (_) {},
      cancelOnError: true,
    );

    await Future.any([_sub.asFuture<void>(), down.asFuture<void>()]);
    await down.cancel();
  }

  void close() {
    unawaited(_sub.cancel());
    try {
      _client.destroy();
    } catch (_) {}
  }
}

int _findHeaderEnd(List<int> data) {
  for (var i = 0; i < data.length - 3; i++) {
    if (data[i] == 13 &&
        data[i + 1] == 10 &&
        data[i + 2] == 13 &&
        data[i + 3] == 10) {
      return i;
    }
  }
  return -1;
}

int _parseStatus(List<int> header) {
  final first = ascii.decode(header, allowInvalid: true).split('\r\n').first;
  final parts = first.split(' ');
  if (parts.length < 2) {
    return 0;
  }
  return int.tryParse(parts[1]) ?? 0;
}

class _HttpRequest {
  const _HttpRequest({
    required this.method,
    required this.host,
    required this.port,
    required this.path,
    required this.version,
    required this.headers,
  });

  final String method;
  final String host;
  final int port;
  final String path;
  final String version;
  final List<String> headers;

  static _HttpRequest? parse(Uint8List raw) {
    final text = ascii.decode(raw, allowInvalid: true);
    final lines = text.split('\r\n');
    if (lines.isEmpty) {
      return null;
    }
    final requestLine = lines.first.split(' ');
    if (requestLine.length < 3) {
      return null;
    }
    final method = requestLine[0].toUpperCase();
    final target = requestLine[1];
    final version = requestLine[2];
    final headerLines = [
      for (var i = 1; i < lines.length; i++)
        if (lines[i].isNotEmpty) lines[i],
    ];

    if (method == 'CONNECT') {
      final parsed = _splitHostPort(target, 443);
      if (parsed == null) {
        return null;
      }
      return _HttpRequest(
        method: method,
        host: parsed.$1,
        port: parsed.$2,
        path: target,
        version: version,
        headers: headerLines,
      );
    }

    String host;
    var port = 80;
    var path = target;
    final uri = Uri.tryParse(target);
    if (uri != null && uri.hasScheme && uri.host.isNotEmpty) {
      host = uri.host;
      port = uri.hasPort ? uri.port : (uri.scheme == 'https' ? 443 : 80);
      path = uri.hasQuery ? '${uri.path}?${uri.query}' : uri.path;
      if (path.isEmpty) {
        path = '/';
      }
    } else {
      final hostHeader = _headerValue(headerLines, 'host');
      if (hostHeader == null) {
        return null;
      }
      final parsed = _splitHostPort(hostHeader, 80);
      if (parsed == null) {
        return null;
      }
      host = parsed.$1;
      port = parsed.$2;
    }

    return _HttpRequest(
      method: method,
      host: host,
      port: port,
      path: path,
      version: version,
      headers: headerLines,
    );
  }

  Uint8List originFormBytes() {
    final out = StringBuffer()
      ..write(method)
      ..write(' ')
      ..write(path.isEmpty ? '/' : path)
      ..write(' ')
      ..write(version)
      ..write('\r\n');
    var sawHost = false;
    for (final line in headers) {
      final name = line.split(':').first.toLowerCase();
      if (name == 'proxy-connection' ||
          name == 'proxy-authorization' ||
          name == 'connection') {
        continue;
      }
      if (name == 'host') {
        sawHost = true;
      }
      out
        ..write(line)
        ..write('\r\n');
    }
    if (!sawHost) {
      out.write('Host: $host${port == 80 ? '' : ':$port'}\r\n');
    }
    out.write('Connection: close\r\n\r\n');
    return ascii.encode(out.toString());
  }
}

(String, int)? _splitHostPort(String value, int fallbackPort) {
  var host = value.trim();
  var port = fallbackPort;
  if (host.startsWith('[')) {
    final close = host.indexOf(']');
    if (close == -1) {
      return null;
    }
    final name = host.substring(1, close);
    if (close + 1 < host.length && host[close + 1] == ':') {
      port = int.tryParse(host.substring(close + 2)) ?? fallbackPort;
    }
    return (name, port);
  }
  final colon = host.lastIndexOf(':');
  if (colon > 0 && !host.substring(0, colon).contains(':')) {
    port = int.tryParse(host.substring(colon + 1)) ?? fallbackPort;
    host = host.substring(0, colon);
  }
  if (host.isEmpty) {
    return null;
  }
  return (host, port);
}

String? _headerValue(List<String> headers, String name) {
  for (final line in headers) {
    final split = line.indexOf(':');
    if (split <= 0) {
      continue;
    }
    if (line.substring(0, split).toLowerCase() == name) {
      return line.substring(split + 1).trim();
    }
  }
  return null;
}
