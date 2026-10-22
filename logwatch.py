"""Local, evidence-based SSH and nginx log analysis. Python 3.10+."""
import argparse
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote, urlsplit

SSH = re.compile(r'(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from (\S+)')
WEB = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (\S+) [^"]+" (\d{3}) ')
STAMP = re.compile(r'^(\w{3}\s+\d+ \d\d:\d\d:\d\d)')


def analyze(lines, year, threshold=5, window=300):
    events, findings = [], []
    skipped = 0
    for number, raw in enumerate(lines, 1):
        raw = raw.rstrip('\n')
        ssh, web = SSH.search(raw), WEB.search(raw)
        try:
            if ssh:
                stamp = STAMP.match(raw)
                when = (datetime.strptime(f'{year} {stamp[1]}', '%Y %b %d %H:%M:%S')
                        if stamp else datetime.fromisoformat(raw.split()[0].replace('Z', '+00:00')))
                kind = 'ssh_failure' if ssh[1] == 'Failed password' else 'ssh_success'
                ip, detail = ssh[3], ssh[2]
            elif web:
                when = datetime.strptime(web[2], '%d/%b/%Y:%H:%M:%S %z')
                ip, detail = web[1], web[4]
                path = unquote(urlsplit(detail).path).lower()
                kind = 'web_probe' if any(p in path for p in ('/.env', '/.git', '/wp-admin', '/wp-login', '/phpmyadmin', '../')) else 'web_request'
            else:
                skipped += 1
                continue
            ipaddress.ip_address(ip)
            events.append(dict(time=when.isoformat(), seconds=when.timestamp(), kind=kind,
                               ip=ip, detail=detail, line=number, raw=raw))
        except (ValueError, IndexError):
            skipped += 1
    events.sort(key=lambda e: e['seconds'])
    history = defaultdict(list)
    alerts = {}
    for event in events:
        ip, kind, now = event['ip'], event['kind'], event['seconds']
        for category in ('ssh_failure', 'web_probe', 'web_request'):
            history[ip, category] = [e for e in history[ip, category] if now - e['seconds'] <= window]
        if kind == 'ssh_success':
            previous = history[ip, 'ssh_failure']
            if len(previous) >= threshold:
                findings.append(dict(rule='success_after_failures', severity='high', ip=ip,
                                     explanation='Successful SSH login after repeated failures from the same IP; investigate, not proof of compromise.',
                                     evidence=[e['line'] for e in previous] + [event['line']]))
            history[ip, 'ssh_failure'] = []
            continue
        categories = [kind]
        if kind == 'web_probe':
            categories.append('web_request')
        for category in categories:
            bucket = history[ip, category]
            bucket.append(event)
            limit = threshold * 20 if category == 'web_request' else threshold
            if len(bucket) < limit:
                continue
            key = (ip, category)
            if key not in alerts or now - alerts[key][0] > window:
                finding = dict(rule={'ssh_failure': 'ssh_brute_force', 'web_probe': 'suspicious_paths', 'web_request': 'request_burst'}[category],
                               severity='medium', ip=ip, explanation=f'At least {limit} matching events within {window} seconds.',
                               evidence=[e['line'] for e in bucket])
                findings.append(finding)
                alerts[key] = (now, finding)
    return dict(parsed=len(events), skipped=skipped, findings=findings,
                timeline=[{k: v for k, v in e.items() if k != 'seconds'} for e in events])


def positive(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--year', type=int, default=datetime.now().year, help='Year for syslog timestamps without a year')
    parser.add_argument('--threshold', type=positive, default=5)
    parser.add_argument('--window', type=positive, default=300, help='Window in seconds')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    with open(args.file, encoding='utf-8', errors='replace') as source:
        report = analyze(source, args.year, args.threshold, args.window)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Parsed: {report['parsed']}; skipped: {report['skipped']}; findings: {len(report['findings'])}")
        by_line = {e['line']: e for e in report['timeline']}
        for finding in report['findings']:
            print(f"\n[{finding['severity']}] {finding['rule']} — {finding['ip']}")
            print(finding['explanation'])
            for line in finding['evidence']:
                print(f"  {line}: {by_line[line]['raw']}")


if __name__ == '__main__':
    main()
