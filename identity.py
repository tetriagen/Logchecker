"""Passive hostname evidence and best-effort Linux socket ownership."""
import ipaddress
import re
import shutil
import subprocess
import threading
import time
from collections import OrderedDict


def hostname(value, http=False):
    """Accept a hostname, not a URL, terminal control sequence or arbitrary header."""
    value = value.strip().lower()
    if http and value.count(':') == 1:
        host, port = value.rsplit(':', 1)
        if port.isdigit() and 0 < int(port) <= 65535:
            value = host
    value = value.rstrip('.')
    if not value or len(value) > 253:
        return ''
    try:
        ipaddress.ip_address(value.strip('[]'))
        return ''
    except ValueError:
        pass
    labels = value.split('.')
    return value if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in labels) else ''


class DNSHints:
    """Only simple one-answer A/AAAA replies; never infer a site from a query."""
    def __init__(self, capacity=4096):
        self.entries = OrderedDict()
        self.capacity = capacity
        self.last_time = None

    def observe(self, p):
        if self.last_time is not None and p['time'] < self.last_time:
            self.entries.clear()
        self.last_time = p['time']
        name = hostname(p.get('dns', ''))
        if not (p.get('response') and p.get('dns_rcode') == '0' and
                p.get('dns_answers') == '1' and p.get('dns_type') in ('1', '28') and
                hostname(p.get('dns_owner', '')) == name and name):
            return
        address = p.get('dns_a' if p['dns_type'] == '1' else 'dns_aaaa', '')
        try:
            address = str(ipaddress.ip_address(address))
            ttl = min(int(p.get('dns_ttl', '0')), 60)
        except ValueError:
            return
        if ttl <= 0:
            return
        key = (p['dst'], address, name)
        self.entries[key] = dict(name=name, source='DNS', confidence='candidate',
                                 frame=p['frame'], observed=p['time'], expires=p['time'] + ttl)
        self.entries.move_to_end(key)
        if len(self.entries) > self.capacity:
            self.entries.popitem(last=False)

    def lookup(self, p):
        pairs = {(p['src'], p['dst']), (p['dst'], p['src'])}
        return [dict(v) for (client, address, _), v in reversed(self.entries.items())
                if (client, address) in pairs and v['observed'] <= p['time'] < v['expires']][:8]


def endpoint(value):
    host, port = value.rsplit(':', 1)
    if not port.isdigit() or not 0 < int(port) <= 65535 or '%' in host:
        raise ValueError('Not an exact endpoint')
    address = ipaddress.ip_address(host.strip('[]'))
    if address.is_unspecified:
        raise ValueError('Wildcard endpoint')
    return str(getattr(address, 'ipv4_mapped', None) or address), port


def parse_sockets(text):
    result = {}
    for line in text.splitlines():
        parts = line.split(None, 6)
        if len(parts) != 7 or parts[0] not in ('tcp', 'udp'):
            continue
        try:
            local, remote = endpoint(parts[4]), endpoint(parts[5])
        except ValueError:
            continue
        owners = [dict(name=name, pid=int(pid), local_ip=local[0], local_port=local[1],
                       source='ss: точный сокет', confidence='socket_match')
                  for name, pid in re.findall(r'\("([^"\n]{1,128})",pid=(\d+),', parts[6])][:8]
        if owners:
            result[(parts[0].upper(), local, remote)] = owners
        if len(result) >= 8192:
            break
    return result


class SocketOwners:
    """Poll only while capturing live. No sudo and no PCAP/process correlation."""
    def __init__(self):
        self.lock = threading.Lock()
        self.table = {}
        self.sampled = 0
        self.status = 'Определение процессов: ожидание таблицы сокетов.'
        self.stop_event = threading.Event()
        self.thread = None

    def refresh(self):
        executable = shutil.which('ss')
        try:
            if not executable:
                raise OSError('ss не найден')
            result = subprocess.run([executable, '-H', '-n', '-t', '-u', '-a', '-p'],
                                    capture_output=True, text=True, timeout=1)
            if result.returncode or 'Operation not permitted' in result.stderr:
                raise OSError('нет доступа к таблице сокетов')
            table = parse_sockets(result.stdout)
            status = 'Процессы: локальные TCP/UDP-сокеты, обновление раз в 0,5 с. Короткие и недоступные сокеты могут остаться неизвестными.'
        except (OSError, subprocess.TimeoutExpired):
            table = {}
            status = 'Процессы недоступны: нужен Linux с ss и доступ к сокетам пользователя. Захват продолжает работать.'
        with self.lock:
            self.table, self.sampled, self.status = table, time.time(), status

    def start(self):
        self.refresh()
        def poll():
            while not self.stop_event.wait(.5):
                self.refresh()
        self.thread = threading.Thread(target=poll, daemon=True)
        self.thread.start()

    def lookup(self, p):
        try:
            src = endpoint(f"[{p['src']}]:{p['sport']}")
            dst = endpoint(f"[{p['dst']}]:{p['dport']}")
        except ValueError:
            return []
        with self.lock:
            if abs(p['time'] - self.sampled) > 2:
                return []
            return [dict(owner, sampled=self.sampled, frame=p['frame'])
                    for local, remote in ((src, dst), (dst, src))
                    for owner in self.table.get((p['transport'], local, remote), [])][:8]

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
