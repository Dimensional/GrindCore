"""Struct layouts as GrindCore.build compiles them, for one RID.

For each struct in the spec (gcnative/_spec.py): its size, alignment, and every field's offset and width, measured
with the RID's own compiler and flags, from the compile commands GrindCore.build's CMake harness writes to
<tree>/artifacts/obj/native/<rid>/compile_commands.json. The suite's layout check (test_abi) compares ctypes with
these, so the bindings are checked against the real build on every RID instead of being inferred from Windows.

How: each C unit that #includes a spec struct's defining header gets a probe: the unit's own preprocessor lines (its
#include/#define/#if... in order, so the probe sees what the unit sees), then a table of sizeof/offsetof values. The
probe is compiled with the unit's command, to an object only. Nothing is linked or run, so cross-compiled RIDs
(osx-x64 on Apple Silicon, win-arm64 on x64) need no machine of that kind. The table is a byte array that starts
with a marker and holds each value as 4 explicit little-endian bytes, so it reads the same out of ELF, Mach-O and
COFF objects. Every unit that sees a struct must agree on its layout, and a struct no unit sees is an error. A unit
whose preprocessor lines don't compile on their own is passed over, and so is a struct a unit doesn't see (its
header under an #if); both are listed with the compiler's message.

Run it where the RID was built, with the tree at the path it was built at (the commands hold absolute paths), e.g.
in the RID's build image (tools/native-build/hosts/layout-probe.sh does that for every RID):
  python3 probe_layouts.py --cc-json <tree>/artifacts/obj/native/<rid>/compile_commands.json --rid <rid> [--out F]
On Windows it sets up MSVC from the command's own cl.exe: that Visual Studio, toolset version and host/target pair.
Writes layouts/<rid>.json next to this script by default; gen_bindings.py merges those into _spec.LAYOUTS.
Python 3.6+, stdlib only.
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gcnative import _spec  # noqa: E402

MARK = b"GCLAYOUTPROBE1"
END = b"END!"
CONTROL = 0xFFFF  # a record with known values (sizeof(char[7]), alignment 1, no fields): the table reads back right
# the unit's preprocessor lines that make its context. Other #pragma lines are dropped (some, like `#pragma unroll`,
# are only valid inside a function), except pack, which changes layouts.
DIRECTIVE = re.compile(r"^\s*#\s*(include|include_next|import|define|undef|if|ifdef|ifndef|elif|else|endif)\b"
                       r"|^\s*#\s*pragma\s+pack\b")
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')


def die(msg):
    sys.exit("probe_layouts: " + msg)


def prologue(path):
    """The unit's preprocessor lines, in order, with line continuations kept."""
    out, cont = [], False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f.read().splitlines():
            if cont or DIRECTIVE.match(line):
                out.append(line)
                cont = line.rstrip().endswith("\\")
    return out


def is_msvc(compiler):
    return os.path.basename(compiler.strip('"')).lower() in ("cl", "cl.exe")


def tokens(entry):
    """The command's words; MSVC's keep their quotes (they're passed back through cmd.exe as one string)."""
    if "arguments" in entry:
        return list(entry["arguments"])
    cmd = entry["command"]
    first = cmd[1:cmd.index('"', 1)] if cmd.startswith('"') else cmd.split()[0]
    return shlex.split(cmd, posix=not is_msvc(first))


def include_dirs(toks, directory, msvc):
    flags = ("/I", "-I", "/external:I", "-external:I") if msvc else ("-I", "-isystem", "-iquote", "-idirafter")
    dirs, i = [], 1
    while i < len(toks):
        a = toks[i].strip('"')
        for flag in flags:
            if a == flag and i + 1 < len(toks):
                dirs.append(toks[i + 1].strip('"'))
                i += 1
                break
            if a.startswith(flag) and len(a) > len(flag) and not (msvc and flag == "/I" and a[2:3] == ":"):
                dirs.append(a[len(flag):])
                break
        i += 1
    return [os.path.normpath(os.path.join(directory, d)) for d in dirs]


def resolve(name, quoted, here, dirs):
    for d in ([here] if quoted else []) + dirs:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return os.path.normcase(os.path.realpath(p)).replace("\\", "/")
    return None


def included(path, dirs, memo):
    """Every file `path` includes, directly or not, that resolves in the unit's include path. #if isn't evaluated, so
    this can name more than the unit sees; the compiler sorts that out (a struct it doesn't see is an error there)."""
    out, todo = set(), [path]
    while todo:
        p = todo.pop()
        if p not in memo:
            memo[p] = set()
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = INCLUDE.match(line)
                    q = m and resolve(m.group(2), m.group(1) == '"', os.path.dirname(p), dirs)
                    if q:
                        memo[p].add(q)
        for q in memo[p] - out:
            out.add(q)
            todo.append(q)
    return out


def probe_command(toks, entry, probe, obj, unit_dir, msvc):
    """The unit's own command with its source swapped for the probe, compiling to `obj` with warnings off. Dropped:
    the output and dependency-file options, link-time code generation (/GL, -flto: the object would hold IR, not the
    table), debug-info output (/Zi /Fd /FS, which would write a .pdb), and warnings turned into errors."""
    src = os.path.normcase(os.path.normpath(os.path.join(entry["directory"], entry["file"])))
    out, it = [toks[0]], iter(toks[1:])
    for a in it:
        bare = a.strip('"')
        if os.path.normcase(os.path.normpath(os.path.join(entry["directory"], bare))) == src:
            continue
        if msvc:
            la = bare.lower()
            if la in ("/c", "-c", "/fs", "-fs", "/gl", "-gl", "/zi", "-zi", "/z7", "-z7", "/wx", "-wx") \
                    or re.match(r"^[/-](fo|fd|we\d|w[1-4]\d|w[0-4]$|showincludes)", la) \
                    or (re.match(r"^[/-]fp", la) and not la.startswith(("/fp:", "-fp:"))):
                continue
        else:
            if a in ("-o", "-MF", "-MT", "-MQ", "--serialize-diagnostics"):
                next(it, None)
                continue
            if a in ("-c", "-MD", "-MMD", "-MP", "-M", "-MM") or a.startswith(("-flto", "-Werror")):
                continue
        out.append(a)
    if msvc:
        return " ".join([out[0], '/I"%s"' % unit_dir] + out[1:] + ["/w", "/c", '"%s"' % probe, '/Fo"%s"' % obj])
    return [out[0], "-iquote", unit_dir] + out[1:] + ["-w", "-c", probe, "-o", obj]


def msvc_env(compiler):
    """vcvarsall for the Visual Studio, toolset version and host/target pair of `compiler` (a cl.exe path)."""
    cl = compiler.strip('"')
    m = re.match(r"^(.*)\\VC\\Tools\\MSVC\\(\d+\.\d+)\.\d+\\bin\\Host(\w+)\\(\w+)\\cl\.exe$", cl, re.I)
    if not m:
        die("can't tell the Visual Studio and toolset from %s" % cl)
    vs, ver, host, tgt = m.groups()
    vcarch = host.lower() if host.lower() == tgt.lower() else "%s_%s" % (host.lower(), tgt.lower())
    bat = os.path.join(vs, "VC", "Auxiliary", "Build", "vcvarsall.bat")
    r = subprocess.run('cmd /d /s /c "call "%s" %s -vcvars_ver=%s >nul && set"' % (bat, vcarch, ver),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    env = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line and not line.startswith("="))
    if r.returncode or "INCLUDE" not in env:
        die("vcvarsall %s -vcvars_ver=%s failed:\n%s" % (vcarch, ver, r.stdout[-2000:]))
    return env, "vcvarsall %s -vcvars_ver=%s" % (vcarch, ver)


def compiler_version(toks, msvc, env):
    if msvc:
        r = subprocess.run(toks[0], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                           env=env)
    else:
        r = subprocess.run([toks[0], "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    return (r.stdout.strip().splitlines() or ["?"])[0]


def c_exprs(name):
    """(size, alignment, [(offset, width) per field]) as C expressions for spec struct `name`."""
    spelled, fields = _spec.C_NAMES[name], [f for f, _, _ in _spec.STRUCTS[name][1]]
    if isinstance(spelled, list):  # an anonymous member's type: measured through its parent
        parent, member = spelled
        base = "offsetof(%s, %s)" % (parent, member)
        return ("sizeof(((%s *)0)->%s)" % (parent, member), None,
                [("offsetof(%s, %s.%s) - %s" % (parent, member, f, base), "sizeof(((%s *)0)->%s.%s)" % (parent, member, f))
                 for f in fields])
    return ("sizeof(%s)" % spelled, spelled,
            [("offsetof(%s, %s)" % (spelled, f), "sizeof(((%s *)0)->%s)" % (spelled, f)) for f in fields])


def write_probe(path, unit, names, index):
    """The probe source, and line number -> spec struct for the lines that belong to one struct."""
    lines = ["/* GENERATED by probe_layouts.py for %s: its preprocessor lines, then the layout table. */" % unit]
    lines += prologue(unit)
    lines += ["", "#include <stddef.h>",
              "#define GC_B(v) (unsigned char)((v) & 255u), (unsigned char)(((v) >> 8) & 255u), "
              "(unsigned char)(((v) >> 16) & 255u), (unsigned char)(((v) >> 24) & 255u)",
              "struct gc_al_control { char c; char t[7]; };"]
    owner, rows = {}, []
    for name in names:
        size, aligned, fields = c_exprs(name)
        i = index[name]
        if aligned:
            lines.append("struct gc_al_%d { char c; %s t; };" % (i, aligned))
            owner[len(lines)] = name
        vals = [str(i), size, "offsetof(struct gc_al_%d, t)" % i if aligned else "0", str(len(fields))]
        vals += [e for pair in fields for e in pair]
        rows.append((name, "  " + ", ".join("GC_B(%s)" % v for v in vals) + ","))
    lines += ["const unsigned char gc_layout_probe[] = {",
              "  " + ", ".join("'%s'" % chr(c) for c in MARK) + ",",
              "  GC_B(%d), GC_B(sizeof(char[7])), GC_B(offsetof(struct gc_al_control, t)), GC_B(0)," % CONTROL]
    for name, row in rows:
        lines.append(row)
        owner[len(lines)] = name
    lines += ["  " + ", ".join("'%s'" % chr(c) for c in END), "};", ""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    return owner


def read_table(obj, names, index):
    with open(obj, "rb") as f:
        data = f.read()
    pos = data.find(MARK)
    if pos < 0 or data.find(MARK, pos + 1) >= 0:
        die("%s: the layout table occurs %s times" % (obj, data.count(MARK)))
    p = pos + len(MARK)

    def u32():
        nonlocal p
        v = int.from_bytes(data[p:p + 4], "little")
        p += 4
        return v
    if (u32(), u32(), u32(), u32()) != (CONTROL, 7, 1, 0):
        die("%s: the control record reads back wrong; the table can't be trusted" % obj)
    out = {}
    for name in names:
        i, size, align, n = u32(), u32(), u32(), u32()
        if i != index[name] or n != len(_spec.STRUCTS[name][1]):
            die("%s: table out of step at %s" % (obj, name))
        out[name] = (size, align, [[u32(), u32()] for _ in range(n)])
    if data[p:p + 4] != END:
        die("%s: no end marker after the table" % obj)
    return out


def write_doc(path, doc):
    """The results as JSON with one line per struct, so a layouts/ file reads (and diffs) struct by struct."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("{\n")
        for k in sorted(k for k in doc if k != "structs"):
            f.write(" %s: %s,\n" % (json.dumps(k), json.dumps(doc[k], sort_keys=True)))
        f.write(' "structs": {\n')
        names = sorted(doc["structs"])
        for i, n in enumerate(names):
            f.write("  %s: %s%s\n" % (json.dumps(n), json.dumps(doc["structs"][n], sort_keys=True),
                                      "," if i < len(names) - 1 else ""))
        f.write(" }\n}\n")


def rel(path):
    """A tree's path from its src/native/ (GrindCore's files) or artifacts/ (the build's) on."""
    p = path.replace("\\", "/")
    if "/src/native/" in p:
        return p.split("/src/native/", 1)[1]
    return "artifacts/" + p.split("/artifacts/", 1)[1] if "/artifacts/" in p else os.path.basename(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cc-json", required=True, help="the RID's compile_commands.json")
    ap.add_argument("--rid", required=True)
    ap.add_argument("--out", help="default: layouts/<rid>.json next to this script")
    ap.add_argument("--work", help="keep the probes here (default: a temporary folder)")
    a = ap.parse_args()
    with open(a.cc_json, encoding="utf-8") as f:
        db = [e for e in json.load(f) if e["file"].endswith(".c")]
    if not db:
        die("no C units in " + a.cc_json)
    toks0 = tokens(db[0])
    msvc = is_msvc(toks0[0])
    env, setup = msvc_env(toks0[0]) if msvc else (None, "")
    compiler = compiler_version(toks0, msvc, env)
    print("%s: %d C units; %s%s" % (a.rid, len(db), compiler, (" (" + setup + ")") if setup else ""), flush=True)

    names = sorted(_spec.STRUCTS)
    index = {n: i for i, n in enumerate(names)}
    by_header = {}
    for n in names:
        by_header.setdefault(_spec.STRUCTS[n][2].split("GrindCore/", 1)[1], []).append(n)

    # which units include which spec headers, directly or through other headers. A header the code map recorded but
    # no unit includes any more (the build moved to another copy, e.g. blake3.h to official BLAKE3's) is matched by
    # its file name, and listed as such.
    units, memos = [], {}
    for e in db:
        unit = os.path.normpath(os.path.join(e["directory"], e["file"]))
        toks = tokens(e)
        dirs = include_dirs(toks, e["directory"], msvc)
        files = included(os.path.normcase(os.path.realpath(unit)).replace("\\", "/"), dirs, memos.setdefault(tuple(dirs), {}))
        units.append((e, unit, toks, files))
    fold = (lambda s: s.lower()) if os.name == "nt" else (lambda s: s)
    matched, by_name = {}, {}
    for h in by_header:
        exact = lambda p, h=h: p.endswith("/" + fold(h))
        if not any(exact(p) for _, _, _, files in units for p in files):
            by_name[h] = sorted({rel(p) for _, _, _, files in units for p in files
                                 if p.rsplit("/", 1)[-1] == fold(h.rsplit("/", 1)[-1])})
            exact = lambda p, h=h: p.rsplit("/", 1)[-1] == fold(h.rsplit("/", 1)[-1])
        matched[h] = exact
    for h, found in sorted(by_name.items()):
        print("%s is included nowhere; by its name: %s" % (h, ", ".join(found) or "nothing"))
    plan = []
    for e, unit, toks, files in units:
        seen = [s for h, structs in by_header.items() if any(matched[h](p) for p in files) for s in structs]
        if seen:
            plan.append((e, unit, toks, sorted(seen, key=index.get)))
    print("%d units include a spec struct's header" % len(plan), flush=True)

    tmp = None if a.work else tempfile.TemporaryDirectory(prefix="gc-layouts-")
    work = os.path.abspath(a.work or tmp.name)
    os.makedirs(work, exist_ok=True)
    results, passed_over, unseen = {}, {}, {}
    for k, (e, unit, toks, live) in enumerate(plan):
        probe, obj = os.path.join(work, "probe_%d.c" % k), os.path.join(work, "probe_%d.%s" % (k, "obj" if msvc else "o"))
        base = os.path.basename(probe)
        err = re.compile(r"%s(?::(\d+):\d+:|\((\d+)\)\s*:)\s*(?:fatal )?error\b(.*)" % re.escape(base))
        while live:
            owner = write_probe(probe, unit, live, index)
            if os.path.exists(obj):
                os.remove(obj)
            cmd = probe_command(toks, e, probe, obj, os.path.dirname(unit), msvc)
            r = subprocess.run(cmd, cwd=e["directory"], shell=msvc, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, errors="replace")
            if r.returncode == 0 and os.path.exists(obj):
                break
            errs = [(int(m.group(1) or m.group(2)), m.group(3).strip()) for m in map(err.search, r.stdout.splitlines()) if m]
            mine = [(ln, msg) for ln, msg in errs if ln in owner]
            if not mine:  # the unit's own lines don't compile on their own
                first = next((l for l in r.stdout.splitlines() if "error" in l), r.stdout.strip()[-300:])
                passed_over[rel(unit)] = first.strip()[:300]
                live = []
                break
            ln, msg = mine[0]  # one struct at a time, so one error's knock-on effects drop nothing else
            unseen.setdefault(owner[ln], {})[rel(unit)] = msg[:200]
            live = [n for n in live if n != owner[ln]]
        if not live:
            continue
        for name, value in read_table(obj, live, index).items():
            results.setdefault(name, []).append((rel(unit), value))
        print("  %-60s %d structs" % (rel(unit), len(live)), flush=True)
    if tmp:
        tmp.cleanup()

    problems, structs = [], {}
    for name in names:
        got = results.get(name)
        if not got:
            problems.append("%s: no unit sees it (%s)" % (name, unseen.get(name, "no unit includes %s" % _spec.STRUCTS[name][2])))
            continue
        values = {json.dumps(v) for _, v in got}
        if len(values) > 1:
            problems.append("%s: units disagree: %s" % (name, "; ".join("%s %s" % (u, v) for u, v in got)))
            continue
        size, align, fields = got[0][1]
        structs[name] = {"size": size, "align": align, "fields": fields, "units": sorted(u for u, _ in got)}
    for u, why in sorted(passed_over.items()):
        print("passed over %s: %s" % (u, why))
    if problems:
        die("\n  ".join(["%d problem(s):" % len(problems)] + problems))
    out = a.out or os.path.join(HERE, "layouts", a.rid + ".json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    doc = {"rid": a.rid, "target": a.rid.replace("-legacy", ""), "compiler": compiler, "setup": setup,
           "compile_commands": rel(a.cc_json), "units_probed": len(plan) - len(passed_over),
           "units_passed_over": passed_over, "not_seen_by": unseen, "headers_matched_by_name": by_name,
           "structs": structs}
    write_doc(out, doc)
    print("%s: %d structs from %d units -> %s" % (a.rid, len(structs), len(plan) - len(passed_over), out))


if __name__ == "__main__":
    main()
