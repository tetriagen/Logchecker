"""Bounded, evidence-based summaries; no reputation or application guessing."""
from collections import OrderedDict, deque
from identity import DNSHints, hostname


class Insights:
    def __init__(self, capacity=4096):
        self.capacity = capacity
        self.flows = OrderedDict()
        self.attempts = deque(maxlen=4096)
        self.alerts = deque(maxlen=100)
        self.last_time = None
        self.sequence = 0
        self.dns_hints = DNSHints(capacity)

    def feed(self, p):
        if not p['src'] or not p['dst']:
            return
        self.dns_hints.observe(p)
        key = (p['transport'], tuple(sorted(((p['src'], p['sport']), (p['dst'], p['dport'])))))
        if key not in self.flows:
            self.sequence += 1
            self.flows[key] = dict(id=self.sequence, src=p['src'], dst=p['dst'], sport=p['sport'],
                dport=p['dport'], protocol=p['transport'], packets=0, bytes=0, sent=0, received=0,
                first=p['time'], last=p['time'], first_frame=p['frame'], last_frame=p['frame'],
                tls=False, dns=[], resets=0, syn=False, reply=False, evidence={},
                sites=[], dns_candidates=[], applications=[])
        f = self.flows[key]
        for field, source in (('sni', 'TLS SNI'), ('http_host', 'HTTP Host')):
            name = hostname(p.get(field, ''), http=field == 'http_host')
            if name and len(f['sites']) < 8 and not any(s['name'] == name and s['source'] == source for s in f['sites']):
                f['sites'].append(dict(name=name, source=source, confidence='observed', frame=p['frame']))
        # Hints are valid at the time of the last packet in this group, not forever.
        f['dns_candidates'] = self.dns_hints.lookup(p) if not f['sites'] else []
        for owner in p.get('applications', []):
            if len(f['applications']) < 8 and not any((a['pid'], a['local_ip'], a['local_port']) ==
                    (owner['pid'], owner['local_ip'], owner['local_port']) for a in f['applications']):
                f['applications'].append(dict(owner))
        forward = (p['src'], p['sport']) == (f['src'], f['sport'])
        f['packets'] += 1
        f['bytes'] += p['size']
        f['sent' if forward else 'received'] += p['size']
        f['first'] = min(f['first'], p['time'])
        f['last'] = max(f['last'], p['time'])
        f['last_frame'] = p['frame']
        f['reply'] |= not forward
        for condition, name in ((p['tls'], 'tls'), (p['reset'], 'reset'),
                                (p['syn'] and not p['ack'], 'syn'), (bool(p['dns']), 'dns')):
            if condition:
                f['evidence'].setdefault(name, p['frame'])
        f['tls'] |= p['tls']
        f['syn'] |= p['syn'] and not p['ack']
        f['resets'] += int(p['reset'])
        if p['dns'] and p['dns'] not in f['dns'] and len(f['dns']) < 8:
            f['dns'].append(p['dns'])
        self.flows.move_to_end(key)
        if len(self.flows) > self.capacity:
            self.flows.popitem(last=False)
        # Capture timestamps, not wall time: identical behaviour for PCAP and live.
        if self.last_time is not None and p['time'] < self.last_time:
            self.attempts.clear()
        self.last_time = p['time']
        while self.attempts and p['time'] - self.attempts[0]['time'] > 10:
            self.attempts.popleft()
        if p['transport'] == 'TCP' and p['syn'] and not p['ack']:
            self.attempts.append({k:p[k] for k in ('time','src','dst','dport','frame')})
            matches = [a for a in self.attempts if (a['src'], a['dst']) == (p['src'], p['dst'])]
            ports = {a['dport'] for a in matches}
            recent = any(a['src']==p['src'] and a['dst']==p['dst'] and 0 <= p['time']-a['time'] <= 10 for a in self.alerts)
            if len(ports) >= 20 and not recent:
                self.alerts.append(dict(src=p['src'], dst=p['dst'], time=p['time'],
                    title=f"Обращения к {len(ports)} разным TCP-портам за 10 секунд",
                    explanation='Возможное сканирование портов. Так же могут работать инвентаризация и разрешённые проверки.',
                    action='Проверьте, принадлежит ли адрес источника вашему сканеру и ожидались ли эти подключения.',
                    ports=sorted(ports), frames=[a['frame'] for a in matches][:40]))

    def snapshot(self):
        result = []
        for f in reversed(self.flows.values()):
            item = {**f, 'dns':list(f['dns']), 'evidence':dict(f['evidence']),
                    'sites':[dict(s) for s in f['sites']], 'dns_candidates':[dict(s) for s in f['dns_candidates']],
                    'applications':[dict(a) for a in f['applications']]}
            if f['dns']:
                item['explanation'] = 'Обмен DNS: поиск адресов доменов ' + ', '.join(f['dns'])
            elif f['tls']:
                item['explanation'] = 'Обмен с использованием TLS. Содержимое приложения может быть зашифровано.'
            elif f['syn'] and not f['reply']:
                item['explanation'] = 'Попытки установить TCP-соединение; обратный трафик пока не наблюдался.'
            elif f['reply']:
                item['explanation'] = 'Виден обмен в обе стороны. Это не подтверждает успешную работу приложения.'
            else:
                item['explanation'] = 'Виден трафик в одну сторону; начало или ответы могли не попасть в запись.'
            item['attention'] = bool(f['resets'])
            item['note'] = (f"Наблюдалось сбросов TCP: {f['resets']}. Возможны закрытый порт, приложение или фильтр; это не доказательство атаки."
                            if f['resets'] else 'По этим признакам нельзя определить, безопасно ли соединение.')
            item['identity_note'] = ('SNI/Host — наблюдаемое имя, не подтверждение владельца сайта. DNS — только возможная связь. '
                'Процесс сопоставлен с локальным сокетом около времени пакета; это не имя вкладки браузера. Направление — по первому пакету.')
            result.append(item)
            if len(result) >= 100:
                break
        return dict(conversations=result, alerts=list(self.alerts),
                    coverage='Последние 100 из максимум 4096 групп по адресам и портам. Повторные сессии с теми же адресами и портами объединяются. Проверка сканирования: 20 TCP-портов одного адреса за 10 секунд; окно ограничено 4096 попытками. Отсутствие срабатываний не означает безопасность.')
