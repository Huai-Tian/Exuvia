#!/usr/bin/env python3
"""fart_sweep.py — device-side sweep runner (SKILL §7 device-coverage arm).

  fart_sweep.py <package> --plan fart_plan.json [-o sweep_report.json]
                [--spawn] [--plan-path /data/local/tmp/fart_plan.json]

Pipeline position:

  covdebt.py (repaired.dex -> coverage_debt.json)
    -> fart_plan.py (debt -> fart_plan.json)
    -> fart_sweep.py (this file: pushes the plan, attaches Frida, runs
       fart_sweep.js, collects sweep_report.json)
    -> re-dump with your existing dump arm
    -> repair_all.py --dump <new dumps> ...   # walls shrink measurably

Needs: adb reachable device, frida-server running on it, and the Python
`frida` package on this host. The app must already be installed (sweep the
REPAIRED build — its classes match the debt list one to one).

This tool is exercised on-device by the maintainer; CI coverage is the
offline half (covdebt/fart_plan anchors in selftest.py).
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
JS = os.path.join(HERE, 'fart_sweep.js')
REMOTE_PLAN = '/data/local/tmp/fart_plan.json'


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('package', help='package of the REPAIRED app on device')
    ap.add_argument('--plan', required=True, help='fart_plan.json from fart_plan.py')
    ap.add_argument('--plan-path', default=REMOTE_PLAN,
                    help='on-device plan path (default %(default)s)')
    ap.add_argument('--spawn', action='store_true',
                    help='spawn the app instead of attaching to a running one')
    ap.add_argument('--timeout', type=int, default=1800,
                    help='max sweep seconds (default %(default)s)')
    ap.add_argument('-o', '--out', default='sweep_report.json')
    args = ap.parse_args()

    r = sh(['adb', 'push', args.plan, args.plan_path])
    if r.returncode != 0:
        sys.exit('[fart_sweep] adb push failed: %s' % r.stderr.strip())

    try:
        import frida
    except ImportError:
        sys.exit('[fart_sweep] python package `frida` not installed '
                 '(pip install frida); plan already pushed to %s' % args.plan_path)

    device = frida.get_usb_device(timeout=30)
    session = None
    pid = None
    if args.spawn:
        pid = device.spawn([args.package])
        session = device.attach(pid)
    else:
        session = device.attach(args.package)

    report = {'tool': 'fart_sweep', 'package': args.package,
              'plan': args.plan, 'spawn': args.spawn,
              'started': time.strftime('%Y-%m-%d %H:%M:%S'),
              'progress': [], 'result': None}
    done = []

    def on_message(msg, data):
        p = msg.get('payload')
        if msg.get('type') == 'send' and isinstance(p, dict):
            if p.get('complete'):
                report['result'] = p
                done.append(True)
            elif p.get('progress'):
                report['progress'].append(p)
                print('[fart_sweep] %d/%d ok=%d fail=%d skip=%d'
                      % (p['ok'] + p['fail'], p['total'], p['ok'],
                         p['fail'], p['skipped']))
        elif msg.get('type') == 'error':
            report.setdefault('script_errors', []).append(msg)

    script = session.create_script(open(JS).read())
    script.on('message', on_message)
    script.load()
    if args.spawn:
        device.resume(pid)

    t0 = time.time()
    while not done and time.time() - t0 < args.timeout:
        time.sleep(0.5)
    if not done:
        report['result'] = {'complete': False, 'reason': 'timeout'}
    try:
        session.detach()
    except Exception:
        pass

    with open(args.out, 'w') as f:
        json.dump(report, f, indent=1)
    res = report['result']
    print('[fart_sweep] done: ok=%s fail=%s skip=%s -> %s'
          % (res.get('ok'), res.get('fail'), res.get('skipped'), args.out))
    print('[fart_sweep] next: re-dump the app now (your dump arm), then '
          'repair_all.py --dump <new dumps> — the wall count should drop.')


if __name__ == '__main__':
    main()
