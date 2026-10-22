"""Loopback-only local UI for Logchecker. No third-party Python dependencies."""
import csv
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from traffic import Analyzer, command, decode

ROOT = Path(__file__).resolve().parent
MAX_UPLOAD = 64 * 1024 * 1024


def interfaces():
    executable = shutil.which('tshark')
    if not executable:
        raise ValueError('TShark не найден. Установите tshark.')
    result = subprocess.run([executable, '-D'], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('Нет доступа к интерфейсам. Проверьте права dumpcap и группу wireshark.\n' + result.stderr[-1500:])
    return [dict(id=m[1], label=m[2]) for line in result.stdout.splitlines()
            if (m := re.match(r'^(\d+)\. (.+)$', line))]


class Session:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = deque(maxlen=300)
        self.analyzer = Analyzer()
        self.stats = self.analyzer.summary()
        self.state = 'idle'
        self.error = ''
        self.stop_event = threading.Event()
        self.proc = None
        self.worker = None
        self.total_events = 0
        self.malformed = 0

    def start(self, interface=None, pcap=None, duration=60):
        executable = shutil.which('tshark')
        if not executable:
            raise ValueError('TShark не найден.')
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError('Сначала остановите текущую сессию.')
            self.events.clear()
            self.analyzer = Analyzer()
            self.stats = self.analyzer.summary()
            self.error = ''
            self.total_events = self.malformed = 0
            self.state = 'running'
            self.stop_event.clear()
            self.worker = threading.Thread(target=self.run, args=(executable, interface, pcap, duration), daemon=True)
            self.worker.start()

    def run(self, executable, interface, pcap, duration):
        analyzer = self.analyzer
        errors = deque(maxlen=20)
        proc = None
        reader = None
        try:
            proc = subprocess.Popen(command(executable, interface, pcap, duration), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
            with self.lock:
                self.proc = proc
            def stderr_reader():
                for line in proc.stderr:
                    errors.append(line[:1000])
            reader = threading.Thread(target=stderr_reader, daemon=True)
            reader.start()
            if self.stop_event.is_set():
                proc.terminate()
            for row in csv.reader(proc.stdout, delimiter='\t'):
                try:
                    with self.lock:
                        event = analyzer.feed(decode(row))
                except (ValueError, KeyError):
                    with self.lock:
                        self.malformed += 1
                    continue
                with self.lock:
                    self.stats = analyzer.summary()
                    if event:
                        self.total_events += 1
                        self.events.append(event)
            code = proc.wait()
            reader.join(timeout=2)
            with self.lock:
                if code and not self.stop_event.is_set():
                    self.state = 'error'
                    self.error = ''.join(errors)[-3000:] or f'TShark завершился с кодом {code}'
                else:
                    self.state = 'stopped' if self.stop_event.is_set() else 'done'
        except Exception as exc:
            with self.lock:
                self.state = 'error'
                self.error = str(exc)
        finally:
            if proc:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                if reader:
                    reader.join(timeout=2)
                proc.stdout.close()
                proc.stderr.close()
            if pcap:
                Path(pcap).unlink(missing_ok=True)
            with self.lock:
                self.proc = None

    def stop(self):
        with self.lock:
            self.stop_event.set()
            proc = self.proc
        if proc and proc.poll() is None:
            proc.terminate()
            def ensure_exit():
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            threading.Thread(target=ensure_exit, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return dict(state=self.state, error=self.error, stats=self.stats.copy(),
                        **self.analyzer.insights.snapshot(), events=list(self.events), total_events=self.total_events, malformed=self.malformed,
                        busy=bool(self.worker and self.worker.is_alive()))


def make_server(port=0):
    session = Session()
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, data, code=200, content_type='application/json; charset=utf-8'):
            raw = json.dumps(data, ensure_ascii=False).encode() if isinstance(data, (dict, list)) else data
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def allowed(self):
            host = f'127.0.0.1:{self.server.server_port}'
            if self.headers.get('Host') != host:
                self.respond(dict(error='Недопустимый Host'), 403)
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            path = urlsplit(self.path).path
            if path == '/api/state':
                self.respond(session.snapshot())
            elif path == '/api/config':
                try:
                    self.respond(dict(token=token, interfaces=interfaces(), error=''))
                except (ValueError, subprocess.TimeoutExpired) as exc:
                    self.respond(dict(token=token, interfaces=[], error=str(exc)))
            elif path in ('/', '/app.js', '/style.css'):
                name = {'/':'index.html', '/app.js':'app.js', '/style.css':'style.css'}[path]
                mime = {'/':'text/html', '/app.js':'text/javascript', '/style.css':'text/css'}[path]
                self.respond((ROOT / 'web' / name).read_bytes(), content_type=mime+'; charset=utf-8')
            else:
                self.respond(dict(error='Не найдено'), 404)

        def do_POST(self):
            if not self.allowed():
                return
            origin = self.headers.get('Origin')
            if (self.headers.get('X-Logchecker-Token') != token or
                origin not in (None, f'http://127.0.0.1:{self.server.server_port}')):
                self.respond(dict(error='Недопустимый запрос'), 403)
                return
            temp = None
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= MAX_UPLOAD:
                    raise ValueError('Максимальный размер PCAP — 64 МиБ.')
                self.connection.settimeout(15)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('Файл загружен не полностью.')
                if self.path == '/api/stop':
                    session.stop()
                elif self.path == '/api/live':
                    data = json.loads(body)
                    duration = int(data.get('duration', 60))
                    if not 1 <= duration <= 3600:
                        raise ValueError('Длительность: от 1 до 3600 секунд.')
                    interface = str(data.get('interface', ''))
                    if interface not in {i['id'] for i in interfaces()}:
                        raise ValueError('Выберите доступный интерфейс.')
                    session.start(interface=interface, duration=duration)
                elif self.path == '/api/pcap':
                    if body[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
                        raise ValueError('Нужен файл PCAP или PCAPNG.')
                    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
                        temp = f.name
                        f.write(body)
                    session.start(pcap=temp)
                    temp = None
                else:
                    self.respond(dict(error='Не найдено'), 404)
                    return
                self.respond(dict(ok=True))
            except (ValueError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
                self.respond(dict(error=str(exc)), 400)
            finally:
                if temp:
                    Path(temp).unlink(missing_ok=True)

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.session = session
    server.token = token
    return server


if __name__ == '__main__':
    server = make_server()
    url = f'http://127.0.0.1:{server.server_port}'
    print(f'Logchecker: {url}', flush=True)
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.session.stop()
        if server.session.worker:
            server.session.worker.join(timeout=5)
        server.server_close()
