/*
 * fart_sweep.js — thin Frida executor for Exuvia's coverage sweep
 * (SKILL §7 device-coverage arm). Reads a fart_plan.json plan and runs every
 * entry through java.lang.reflect with dummy args, swallowing ALL exceptions.
 *
 * Core insight (family-3 lazy re-materialization): a method's body is
 * restored by the packer BEFORE its first instruction executes. So the call
 * need only START — it never has to succeed. An NPE inside the target is a
 * success for us: it proves real code ran.
 *
 * Usage (via fart_sweep.py, or manually):
 *   adb push fart_plan.json /data/local/tmp/fart_plan.json
 *   frida -U -n <pkg> -l fart_sweep.js
 * Progress and the final report travel over send(); the Python runner
 * collects them into sweep_report.json.
 */

var PLAN_PATH = '/data/local/tmp/fart_plan.json';

Java.perform(function () {
  var FileReader = Java.use('java.io.FileReader');
  var BufferedReader = Java.use('java.io.BufferedReader');
  var StringBuffer = Java.use('java.lang.StringBuffer');
  var JClass = Java.use('java.lang.Class');
  var Thread = Java.use('java.lang.Thread');
  // The application classloader (java.lang.Object's own loader is the
  // bootstrap, which cannot see app classes — never use that one).
  var appCl = Thread.currentThread().getContextClassLoader();

  function readPlan(path) {
    var br = BufferedReader.$new(FileReader.$new(path));
    var sb = StringBuffer.$new();
    var line;
    while ((line = br.readLine()) !== null) sb.append(line);
    br.close();
    return JSON.parse(sb.toString());
  }

  var planJson = readPlan(PLAN_PATH);
  var plan = planJson.plan;
  var ok = 0, fail = 0, skipped = 0;
  var errors = [];
  var unsafe = null;
  try {
    var Unsafe = Java.use('sun.misc.Unsafe');
    var f = Unsafe.class.getDeclaredField('theUnsafe');
    f.setAccessible(true);
    unsafe = f.get(null);
  } catch (e) {
    errors.push('no Unsafe: ' + e);
  }

  function classFor(name) {
    // load but DO NOT initialize (init happens only on explicit demand)
    return JClass.forName(name, false, appCl);
  }

  function paramClass(p) {
    switch (p) {
      case 'boolean': return Java.use('java.lang.Boolean').TYPE;
      case 'byte':    return Java.use('java.lang.Byte').TYPE;
      case 'char':    return Java.use('java.lang.Character').TYPE;
      case 'short':   return Java.use('java.lang.Short').TYPE;
      case 'int':     return Java.use('java.lang.Integer').TYPE;
      case 'long':    return Java.use('java.lang.Long').TYPE;
      case 'float':   return Java.use('java.lang.Float').TYPE;
      case 'double':  return Java.use('java.lang.Double').TYPE;
      default:        return classFor(p);
    }
  }

  function boxArgs(args) {
    var out = [];
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (a.kind === 'ref') { out.push(null); continue; }
      var Box = Java.use(a.box);
      if (a.box === 'java.lang.Character') out.push(Box.valueOf(String.fromCharCode(0)));
      else out.push(Box.valueOf(a.value));
    }
    return out;
  }

  function report(force) {
    if (force || ((ok + fail) % 200 === 0))
      send({ progress: true, ok: ok, fail: fail, skipped: skipped, total: plan.length });
  }

  for (var i = 0; i < plan.length; i++) {
    var e = plan[i];
    try {
      if (e.action === 'skip') { skipped++; continue; }
      var cls = classFor(e.class);
      if (e.action === 'init_class') {
        JClass.forName(e.class, true, appCl);
        ok++; report(false); continue;
      }
      var ptypes = [];
      for (var j = 0; j < e.params.length; j++) ptypes.push(paramClass(e.params[j]));
      if (e.action === 'construct') {
        var ctor = cls.getDeclaredConstructor(ptypes);
        ctor.setAccessible(true);
        try { ctor.newInstance(boxArgs(e.args)); } catch (ce) { /* started = success */ }
        ok++; report(false); continue;
      }
      // action === 'invoke'
      var m = cls.getDeclaredMethod(e.name, ptypes);
      m.setAccessible(true);
      var recv = null;
      if (e.receiver === 'alloc') {
        if (unsafe === null) { skipped++; continue; }
        recv = unsafe.allocateInstance(cls);
      }
      try { m.invoke(recv, boxArgs(e.args)); } catch (ie) { /* started = success */ }
      ok++; report(false);
    } catch (err) {
      fail++;
      if (errors.length < 50) errors.push(e.class + '.' + e.name + e.proto + ': ' + err);
    }
  }
  send({ complete: true, ok: ok, fail: fail, skipped: skipped,
         total: plan.length, errors: errors });
});
