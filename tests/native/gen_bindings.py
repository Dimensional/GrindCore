"""Generate gcnative/_spec.py (plain data, committed) from the code map (codemap.db, built by the audit workspace's
tools/codemap).

For every entry of entrypoints.c: return and parameter types as portable type codes. For every struct a caller may
have to allocate or fill (reachable from an export's pointer parameters, defined in a header): its fields, plus the
clang layout for win-x64 and win-x86 so the runtime can self-check ctypes' layout on those targets.

Type codes: void i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 size ssize ptr cstr, or "struct:<name>" / "union:<name>".
size = anything whose width differs between the win-x64 and win-x86 maps (size_t); ptr = any pointer, array or
function pointer. Unknown types stop the generator rather than guessing.

Run after the code map is rebuilt:  python gen_bindings.py [--db codemap.db]
(the default is the workspace's tools/codemap/out/codemap.db, with GrindCore checked out as its submodule)
"""
import argparse, re, sqlite3, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB = HERE.parents[2] / "tools" / "codemap" / "out" / "codemap.db"
OUT = HERE / "gcnative" / "_spec.py"

INTS = {
    "char": "i8", "signed char": "i8", "unsigned char": "u8", "_Bool": "u8", "bool": "u8",
    "short": "i16", "unsigned short": "u16", "int": "i32", "unsigned int": "u32",
    "long long": "i64", "unsigned long long": "u64", "float": "f32", "double": "f64", "void": "void",
}
# spelled return types (func.ret_type has no canonical form); typedefs resolved by hand, checked against both maps
RET_TYPEDEFS = {
    "int32_t": "i32", "uint32_t": "u32", "int64_t": "i64", "uint64_t": "u64", "uint8_t": "u8", "size_t": "size",
    "BoolInt": "i32", "Byte": "u8", "UInt32": "u32", "UInt64": "u64", "SRes": "i32",
    "CLzmaEncHandle": "ptr", "CLzma2EncHandle": "ptr", "BrotliDecoderResult": "i32",
}


# Anonymous unions/structs: the code map records only their parent's field (type "union (unnamed at ...)"), not their
# members. Members written out here from the headers; the layout self-check verifies them against clang's sizes and
# offsets, and any other anonymous record stops the generator.
ANONYMOUS = {
    ("sha3_context_", "u"): ("union", [("s", "u64", [25]), ("sb", "u8", [200])]),            # hashes/sha3.h:31
    ("CBlake2sp", "u"): ("union", [("_pad_align_ptr", "ptr", [8]), ("_pad_align_32bit", "u32", [16])]),  # 7z-deps/Blake2.h:54
}


def die(msg):
    sys.exit("gen_bindings: " + msg)


def main():
    ap = argparse.ArgumentParser(description="Generate gcnative/_spec.py from the code map.")
    ap.add_argument("--db", type=Path, default=DB, help="the code map (default: %(default)s)")
    path = ap.parse_args().db
    if not path.is_file():
        die("no code map at %s (build it with the workspace's tools/codemap, or pass --db)" % path)
    db = sqlite3.connect(str(path))
    cfg = dict(db.execute("select name, id from config"))
    c64, c32 = cfg["native:win-x64"], cfg["native:win-x86"]

    # Which symbols exist where. entrypoints.c decides the exports on Linux/macOS (everything else is localized);
    # Windows additionally exports every __declspec(dllexport) definition. GrindCore.net's P/Invokes are what the
    # managed side expects. The union is tested; each name is tagged with its sources.
    entry = {r[0] for r in db.execute("select name from entrypoint where config_id = ?", (c64,))}
    dllexport = {r[0] for r in db.execute("select name from func where config_id = ? and is_export = 1 and is_definition = 1", (c64,))}
    defined = {r[0] for r in db.execute("select name from func where config_id = ? and is_definition = 1", (c64,))}
    pinvoked = set()
    for cname, cid in cfg.items():
        if cname.startswith("cs:"):
            pinvoked |= {r[0] for r in db.execute("select distinct p.entry_point from pinvoke p join func f on f.id = p.func_id "
                                                  "where f.config_id = ?", (cid,))}
    pinvoked &= {n for n in pinvoked if re.match(r"(SZ|DN8|DN9|FL2|z7)_", n)}  # GrindCore's own library, not libc etc.

    def signatures(cid):
        out = {}
        for name in sorted(entry | dllexport):
            row = db.execute("select ret_type, id from func where config_id = ? and name = ? and is_definition = 1 "
                             "order by is_export desc limit 1", (cid, name)).fetchone()
            if not row:
                continue
            params = db.execute("select name, type, canonical, size, pointee_canonical from param where func_id = ? order by idx",
                                (row[1],)).fetchall()
            out[name] = (row[0], params)
        return out

    s64, s32 = signatures(c64), signatures(c32)
    if set(s64) != set(s32):
        die("win-x64 and win-x86 export sets differ: %s" % sorted(set(s64) ^ set(s32)))
    symbols = {}
    for n in sorted(entry | dllexport | pinvoked):
        symbols[n] = [tag for tag, s in (("entrypoints", entry), ("dllexport", dllexport), ("pinvoke", pinvoked)) if n in s]
        if n not in defined:
            symbols[n].append("undefined")

    records = {}  # name -> (kind, key) for header-defined records in the x64 map

    def record_by_name(name):
        name = re.sub(r"^(const )?(struct |union |enum )?", "", name).strip()
        if name in records:
            return records[name]
        row = db.execute("select r.key, r.layout, f.path from record r join file f on f.id = r.file_id where r.config_id = ? "
                         "and r.name = ? and f.path like '%.h' order by length(r.key) limit 1", (c64, name)).fetchone()
        records[name] = row
        return row

    def scalar(canon, size64, size32, where):
        c = canon.replace("const ", "").replace("volatile ", "").strip()
        if "*" in c or "(" in c or "[" in c:
            return "ptr"
        # records before the width rule: an embedded struct holding a pointer also differs between x64 and x86
        if c.startswith("enum ") or db.execute("select 1 from record where config_id = ? and name = ? and layout = 'ENUM_DECL'",
                                              (c64, c)).fetchone():
            return "i32"
        if c not in INTS:
            rec = record_by_name(c)
            if rec:
                return ("union:" if rec[1] == "UNION_DECL" else "struct:") + re.sub(r"^(struct |union )", "", c)
            if c.startswith("struct ") and (size64, size32) == (8, 4):
                # 7-Zip declares its interface structs (ISeqInStream_, ICompressProgress_, ...) through a macro the
                # code map doesn't record; each is a single function pointer, i.e. pointer-sized on every target
                return "ptr"
        if size64 is not None and size32 is not None and size64 != size32:
            return "size"
        if c in INTS:
            return INTS[c]
        if size64 in (1, 2, 4, 8):  # typedef'd enum names etc.; the width is known from the map
            return {1: "u8", 2: "u16", 4: "i32", 8: "i64"}[size64]
        die("unknown type %r at %s" % (canon, where))

    exports, wanted = {}, set()
    for name in sorted(s64):
        ret64, p64 = s64[name]
        ret32, p32 = s32[name]
        r = RET_TYPEDEFS.get(ret64.strip())
        if r is None:
            r = "ptr" if "*" in ret64 else INTS.get(ret64.replace("const ", "").strip())
            if r is None:
                die("unknown return type %r of %s" % (ret64, name))
            if ret64.replace(" ", "") in ("constchar*", "char*"):
                r = "cstr"
        args = []
        for (pn, t, canon, size, pointee), (_, _, _, size32, _) in zip(p64, p32):
            args.append(scalar(canon, size, size32, "%s(%s)" % (name, pn)))
            if pointee:
                base = re.sub(r"^(const )?(struct |union )?", "", pointee).replace("*", "").strip()
                if record_by_name(base):
                    wanted.add(base)
        exports[name] = (r, args)

    # structs: everything reachable from the exports' pointee types through fields, header-defined only
    structs, layouts, todo = {}, {}, sorted(wanted)
    while todo:
        name = todo.pop()
        if name in structs:
            continue
        key, layout, path = record_by_name(name)
        fields = []
        rows = db.execute("select name, type, canonical, offset_bits, size from field where config_id = ? and record_key = ? order by idx",
                          (c64, key)).fetchall()
        for fname, ftype, canon, off, size in rows:
            if "(unnamed" in canon or "(anonymous" in canon:
                if (name, fname) not in ANONYMOUS:
                    die("%s.%s is an anonymous record; add its members to ANONYMOUS" % (name, fname))
                sub = "%s__%s" % (name, fname)
                kind, members = ANONYMOUS[(name, fname)]
                structs[sub] = (kind, members, path)
                fields.append((fname, "%s:%s" % (kind, sub), []))
                continue
            m = re.match(r"^(.*?)((?:\[\d+\])+)$", canon.replace("const ", "").strip())
            base, dims = (m.group(1).strip(), [int(d) for d in re.findall(r"\[(\d+)\]", m.group(2))]) if m else (canon, [])
            size32 = db.execute("select size from field where config_id = ? and record_key = ? and name = ?", (c32, key, fname)).fetchone()
            code = scalar(base, size // max(1, _prod(dims)), (size32[0] // max(1, _prod(dims))) if size32 else None,
                          "%s.%s" % (name, fname))
            if code.startswith(("struct:", "union:")) and code.split(":", 1)[1] not in structs:
                todo.append(code.split(":", 1)[1])
            fields.append((fname, code, dims))
        # bit-fields can't be expressed this way: fields must not overlap
        offs = [r[3] for r in rows]
        if len(set(offs)) != len(offs) and layout != "UNION_DECL" or any(o % 8 for o in offs):
            die("%s has bit-fields; add support before using it" % name)
        structs[name] = ("union" if layout == "UNION_DECL" else "struct", fields, path)
        for tag, cid in (("win-x64", c64), ("win-x86", c32)):
            k = db.execute("select key from record where config_id = ? and name = ? order by length(key) limit 1", (cid, name)).fetchone()
            if k:
                size, align = db.execute("select size, align from record where config_id = ? and key = ?", (cid, k[0])).fetchone()
                offsets = [o // 8 for (o,) in db.execute("select offset_bits from field where config_id = ? and record_key = ? order by idx", (cid, k[0]))]
                layouts.setdefault(name, {})[tag] = (size, align, offsets)

    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        f.write('"""GENERATED by tests/native/gen_bindings.py from the code map. Do not edit."""\n\n')
        f.write("# name -> (return type, [parameter types])\nEXPORTS = {\n")
        for name in sorted(exports):
            f.write("    %r: %r,\n" % (name, exports[name]))
        f.write("}\n\n# name -> (kind, [(field, type, [array dims])], defining header)\nSTRUCTS = {\n")
        for name in sorted(structs):
            f.write("    %r: %r,\n" % (name, structs[name]))
        f.write("}\n\n# clang layouts from the code map: name -> {target: (size, alignment, [field offsets])}. An alignment above\n"
                "# what malloc/ctypes guarantee (e.g. CBlake2sp's MY_ALIGN(64)) must be honoured by the caller: Library.alloc().\n"
                "LAYOUTS = {\n")
        for name in sorted(layouts):
            f.write("    %r: %r,\n" % (name, layouts[name]))
        f.write("}\n\n# every symbol that is listed anywhere -> where: entrypoints (exported everywhere), dllexport (also exported\n"
                "# on Windows), pinvoke (GrindCore.net calls it), undefined (no definition in the library at all)\nSYMBOLS = {\n")
        for name in sorted(symbols):
            f.write("    %r: %r,\n" % (name, symbols[name]))
        f.write("}\n")
    gaps = {n: t for n, t in symbols.items() if "entrypoints" not in t}
    print("wrote %s: %d exports, %d structs, %d symbols (%d not in entrypoints.c)" % (OUT, len(exports), len(structs), len(symbols), len(gaps)))


def _prod(dims):
    p = 1
    for d in dims:
        p *= d
    return p


if __name__ == "__main__":
    main()
