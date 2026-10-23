#!/usr/bin/env python3
"""fart_plan.py — coverage debt -> invocation plan (SKILL §7 device-coverage
arm). Consumes covdebt.py's debt JSON and emits a FART-style active-
invocation plan for the device sweep:

  fart_plan.py coverage_debt.json [--components components.txt] -o fart_plan.json

Per entry it decides the cheapest action that makes the method START
executing (materialization precedes execution, so dummy args + swallowed
exceptions are enough — the call need never succeed):

  static method      -> invoke via reflection with a null receiver
  instance method    -> invoke on a receiver synthesized by
                        Unsafe.allocateInstance (no ctor side effects, no
                        no-arg ctor required; abstract classes are skipped
                        honestly — only a subclass instance could run them)
  <init>             -> construct through that very constructor with dummy
                        args (there is no other way to run a ctor)
  <clinit>           -> Class.forName(name, true, loader) — class init
                        itself runs the static initializer

--components is a text file (one class per line, dotted or descriptor) of
manifest-declared components; those classes are sorted as the "component"
tier — callbacks live there and carry the highest repair value per sweep
second. Finding #13: covdebt's `hot` flag (wall named by an in-dex invoke
site = reachable = latent crash) outranks everything — those entries form
the "hot" tier, planned first. Zero-sample: no family-specific constants.
"""
import argparse
import json
import sys

_PRIM = {'Z': 'boolean', 'B': 'byte', 'C': 'char', 'S': 'short',
         'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double', 'V': 'void'}


def _dotted(desc):
    """'Lcom/a/B;' / '[I' / 'I' -> 'com.a.B' / '[I' / 'int' (plan form)."""
    if desc in _PRIM:
        return _PRIM[desc]
    if desc.startswith('L'):
        return desc[1:-1].replace('/', '.')
    return desc  # arrays keep descriptor form; the executor forName()s them


def _dummy(ptype):
    """Dummy-argument recipe for one parameter type. The device executor
    boxes numbers for reflection (method.invoke wants boxed primitives)."""
    if ptype == 'boolean':
        return {'kind': 'prim', 'box': 'java.lang.Boolean', 'value': False}
    if ptype in ('byte', 'short', 'char', 'int'):
        box = {'byte': 'java.lang.Byte', 'short': 'java.lang.Short',
               'char': 'java.lang.Character', 'int': 'java.lang.Integer'}[ptype]
        return {'kind': 'prim', 'box': box, 'value': 0}
    if ptype == 'long':
        return {'kind': 'prim', 'box': 'java.lang.Long', 'value': 0}
    if ptype == 'float':
        return {'kind': 'prim', 'box': 'java.lang.Float', 'value': 0.0}
    if ptype == 'double':
        return {'kind': 'prim', 'box': 'java.lang.Double', 'value': 0.0}
    return {'kind': 'ref', 'value': None}


def plan_entry(e, tier):
    if e['clinit']:
        return {'class': _dotted(e['class']), 'name': '<clinit>',
                'proto': e['proto'], 'action': 'init_class', 'tier': tier}
    params = [_dotted(p) for p in e['params']]
    if e['constructor']:
        return {'class': _dotted(e['class']), 'name': '<init>',
                'proto': e['proto'], 'action': 'construct',
                'params': params,
                'args': [_dummy(p) for p in params], 'tier': tier}
    if e['abstract']:
        return None  # abstract methods carry no body — cannot be debt
    if e['class_abstract'] and not e['static']:
        return {'class': _dotted(e['class']), 'name': e['name'],
                'proto': e['proto'], 'action': 'skip',
                'reason': 'abstract class: only a subclass instance can run it',
                'tier': tier}
    return {'class': _dotted(e['class']), 'name': e['name'],
            'proto': e['proto'], 'action': 'invoke',
            'receiver': 'static' if e['static'] else 'alloc',
            'params': params,
            'args': [_dummy(p) for p in params], 'tier': tier}


def make_plan(debt_json, components=(), limit=0):
    comps = set()
    for c in components:
        c = c.strip()
        if c:
            comps.add(c)
            if c.startswith('L'):
                comps.add(c[1:-1].replace('/', '.'))
            else:
                comps.add('L' + c.replace('.', '/') + ';')
    plan, skips = [], 0
    for e in debt_json['debt']:
        # finding #13: a wall invoked by in-dex real code is a latent crash
        # (the countdown-end AIOOBE class of bug) — sweep it first.
        tier = ('hot' if e.get('hot')
                else 'component' if e['class'] in comps else 'rest')
        pe = plan_entry(e, tier)
        if pe is None:
            continue
        if pe['action'] == 'skip':
            skips += 1
        plan.append(pe)
    rank = {'hot': 0, 'component': 1, 'rest': 2}
    plan.sort(key=lambda p: (rank[p['tier']], p['action'] != 'invoke',
                             p['class'], p['name']))
    if limit:
        plan = plan[:limit]
    by_action = {}
    by_tier = {}
    for p in plan:
        by_action[p['action']] = by_action.get(p['action'], 0) + 1
        by_tier[p['tier']] = by_tier.get(p['tier'], 0) + 1
    return {'tool': 'fart_plan', 'source': debt_json.get('dex'),
            'summary': {'entries': len(plan), 'skipped_abstract': skips,
                        'hot': by_tier.get('hot', 0),
                        'by_tier': by_tier, 'by_action': by_action},
            'plan': plan}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('debt', help='coverage_debt.json from covdebt.py')
    ap.add_argument('--components', default=None,
                    help='text file: one manifest component class per line')
    ap.add_argument('--limit', type=int, default=0,
                    help='keep only the first N entries (smoke sweeps)')
    ap.add_argument('-o', '--out', default=None)
    args = ap.parse_args()
    debt = json.load(open(args.debt))
    comps = open(args.components).readlines() if args.components else []
    out = make_plan(debt, comps, args.limit)
    path = args.out or args.debt.replace('.json', '') + '.plan.json'
    with open(path, 'w') as f:
        json.dump(out, f, indent=1)
    s = out['summary']
    print('[fart_plan] %d entries (hot=%d, %s), %d abstract-class skips -> %s'
          % (s['entries'], s['hot'],
             ', '.join('%s=%d' % kv for kv in sorted(s['by_action'].items())),
             s['skipped_abstract'], path))


if __name__ == '__main__':
    main()
