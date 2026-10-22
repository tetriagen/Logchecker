"""Streaming traffic explanations powered by TShark."""
import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import OrderedDict
from insights import Insights

FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'ip.src', 'ipv6.src',
          'ip.dst', 'ipv6.dst', 'tcp.srcport', 'udp.srcport', 'tcp.dstport',
          'udp.dstport', 'dns.qry.name', 'dns.flags.response', 'tcp.flags.syn',
          'tcp.flags.ack', 'tcp.flags.reset', 'tls.record.content_type']


def decode(row):
    if len(row) != len(FIELDS):
        raise ValueError('Unexpected field count')
    p = dict(zip(FIELDS, row))
    return dict(frame=int(p['frame.number']), time=float(p['frame.time_epoch']),
                size=int(p['frame.len']), src=p['ip.src'] or p['ipv6.src'],
                dst=p['ip.dst'] or p['ipv6.dst'], sport=p['tcp.srcport'] or p['udp.srcport'],
                dport=p['tcp.dstport'] or p['udp.dstport'],
                transport='TCP' if p['tcp.srcport'] else 'UDP' if p['udp.srcport'] else 'OTHER',
                dns=p['dns.qry.name'], response=p['dns.flags.response'].lower() in ('1', 'true'),
                syn=p['tcp.flags.syn'].lower() in ('1', 'true'), ack=p['tcp.flags.ack'].lower() in ('1', 'true'),
                reset=p['tcp.flags.reset'].lower() in ('1', 'true'), tls=bool(p['tls.record.content_type']))


class Analyzer:
    def __init__(self, capacity=4096):
        self.flows = OrderedDict()
        self.insights = Insights(capacity)
        self.capacity = capacity
        self.packets = self.bytes = self.skipped = self.evicted = 0

    def feed(self, p):
        self.insights.feed(p)
        self.packets += 1
        self.bytes += p['size']
        if not p['src'] or not p['dst']:
            self.skipped += 1
            return None
        key = (p['transport'], tuple(sorted(((p['src'], p['sport']), (p['dst'], p['dport'])))))
        new = key not in self.flows
        flow = self.flows.setdefault(key, dict(packets=0, bytes=0, tls_seen=False))
        flow['packets'] += 1
        flow['bytes'] += p['size']
        self.flows.move_to_end(key)
        if len(self.flows) > self.capacity:
            self.flows.popitem(last=False)
            self.evicted += 1
        if p['dns']:
            explanation = ('DNS-ответ для ' if p['response'] else 'Запрос адреса домена ') + p['dns']
            note = 'Сам по себе DNS-запрос не указывает на угрозу.'
        elif p['reset']:
            explanation = 'TCP-соединение отклонено или сброшено.'
            note = 'Возможны закрытый порт, приложение или сетевой фильтр; это не доказательство атаки.'
        elif p['syn'] and not p['ack']:
            explanation = 'Попытка открыть TCP-соединение.'
            note = 'Этот пакет ещё не подтверждает успешное подключение.'
        elif p['tls'] and not flow['tls_seen']:
            flow['tls_seen'] = True
            explanation = 'Обнаружен пакет TLS.'
            note = 'Содержимое приложения может быть зашифровано; URL и текст запросов здесь не определяются.'
        elif new:
            explanation = 'Обнаружен обмен данными по ' + p['transport'] + '.'
            note = 'Приложение и безопасность соединения по одному номеру порта не определяются.'
        else:
            return None
        return dict(frame=p['frame'], time=p['time'], src=p['src'], dst=p['dst'],
                    sport=p['sport'], dport=p['dport'], protocol=p['transport'],
                    explanation=explanation, note=note)

    def summary(self):
        return dict(packets=self.packets, bytes=self.bytes, non_ip=self.skipped,
                    tracked_flows=len(self.flows), evicted_flows=self.evicted)


def command(executable, interface=None, pcap=None, duration=60, capture_filter=None):
    args = [executable, '-n', '-l']
    if pcap:
        args += ['-r', pcap]
    else:
        args += ['-p', '-i', interface, '-a', f'duration:{duration}']
        if capture_filter:
            args += ['-f', capture_filter]
    args += ['-T', 'fields', '-E', 'quote=d', '-E', 'occurrence=f']
    for field in FIELDS:
        args += ['-e', field]
    return args


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError('Нужно положительное число')
    return value


def main():
    parser = argparse.ArgumentParser(description='Понятный анализ сетевого трафика')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--interfaces', action='store_true')
    source.add_argument('--live', metavar='INTERFACE')
    source.add_argument('--pcap', metavar='FILE')
    parser.add_argument('--duration', type=positive, default=60)
    parser.add_argument('--filter', help='Фильтр захвата BPF, только для live')
    parser.add_argument('--json', action='store_true', help='События JSON Lines')
    args = parser.parse_args()
    if args.filter and not args.live:
        parser.error('--filter применяется только к --live')
    executable = shutil.which('tshark')
    if not executable:
        parser.exit(2, 'TShark не установлен. Установите tshark из пакетов вашей ОС.\n')
    if args.interfaces:
        return subprocess.call([executable, '-D'])
    analyzer = Analyzer()
    proc = subprocess.Popen(command(executable, args.live, args.pcap, args.duration, args.filter),
                            stdout=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    malformed = 0
    interrupted = False
    try:
        for row in csv.reader(proc.stdout, delimiter='\t'):
            try:
                event = analyzer.feed(decode(row))
            except (ValueError, KeyError):
                malformed += 1
                continue
            if event:
                if args.json:
                    print(json.dumps(dict(type='event', **event), ensure_ascii=True), flush=True)
                else:
                    # Escape untrusted packet strings before writing to a terminal.
                    route = f"{event['src']}:{event['sport']} → {event['dst']}:{event['dport']}"
                    message = f"Пакет #{event['frame']} | {route} | {event['explanation']} {event['note']}"
                    print(''.join(c if c.isprintable() else repr(c)[1:-1] for c in message), flush=True)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
        proc.stdout.close()
    print(json.dumps(dict(type='summary', **analyzer.summary(), malformed=malformed,
                          interrupted=interrupted, capture_exit_code=code), ensure_ascii=False))
    if code and not interrupted:
        print('Захват завершился с ошибкой: проверьте сообщение TShark выше, интерфейс и права dumpcap.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
