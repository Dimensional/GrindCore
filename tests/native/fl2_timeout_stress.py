"""Fast-LZMA2's timeouts under load (audit/other-codecs.md 4.4.1 finding 9): decode a multi-reset frame with a
4-thread DStream and encode with a CStream, both with a 1 ms timeout, ITER times each, and count wrong results. Run
several copies at once for load; a library with FL2POOL_waitAll's timed wait fixed must never print WRONG (official
1.0.1 does, in about 10-20% of runs on a loaded x86/x64 machine). Not part of the test suite. Stdlib only.

  python3 fl2_timeout_stress.py ITER LIB        (NT=<tests/native> if run from elsewhere)"""
import ctypes, hashlib, os, sys
sys.path.insert(0, os.environ.get("NT") or os.path.dirname(os.path.abspath(__file__)))
import gcnative
from gctest import fl2_util as F, sample

z = F.Api(gcnative.load(sys.argv[2]), "x")
c = z.call
L = z.L
data = sample.mixed(24 << 20, seed=5)
cs = z.cstream(4); cs.set(F.LEVEL, 3); cs.set(F.RESET_INTERVAL, 1); cs.init(0); frame = cs.compress(data, 1 << 20); cs.close()
small = data[:3 << 20]
s = z.cstream(1, 0); s.init(6); want_c = s.compress(small, len(small)); s.close()
ib, ob = L.struct.FL2_inBuffer(), L.struct.FL2_outBuffer()


def decode_with_timeout():
    d = z.dstream(4)
    c("FL2_setDStreamTimeout", d.s, 1)
    src = F._In(frame); ib.src, ib.size, ib.pos = src.addr, src.n, 0
    obuf, got, done = ctypes.create_string_buffer(1 << 20), bytearray(), False
    while not done:
        ob.dst, ob.size, ob.pos = ctypes.addressof(obuf), len(obuf), 0
        r = c("FL2_decompressStream", d.s, ctypes.addressof(ob), ctypes.addressof(ib))
        if F.error_of(r) == F.TIMED_OUT:
            while True:
                w = c("FL2_waitDStream", d.s)
                if F.error_of(w) != F.TIMED_OUT:
                    break
            if F.is_error(w):
                return "error %d" % F.error_of(w)
            done = w == 0
        elif F.is_error(r):
            return "error %d" % F.error_of(r)
        else:
            done = r == 0
        got += obuf.raw[:ob.pos]
    c("FL2_setDStreamTimeout", d.s, 0); d.close()
    if bytes(got) == data:
        return "ok"
    first = next(i for i in range(min(len(got), len(data))) if got[i] != data[i]) if len(got) == len(data) else -1
    return "WRONG len %d first diff %d" % (len(got), first)


def encode_with_timeout():
    s = z.cstream(1, 0); s.init(6); c("FL2_setCStreamTimeout", s.s, 1)
    src = F._In(small); ib.src, ib.size, ib.pos = src.addr, src.n, 0
    got = bytearray()
    for name, args in (("FL2_compressStream", (ctypes.addressof(ib),)), ("FL2_endStream", ())):
        while True:
            s._out()
            r = c(name, s.s, ctypes.addressof(s.ob), *args)
            got += s.out.raw[:s.ob.pos]
            if F.error_of(r) == F.TIMED_OUT:
                continue
            if F.is_error(r):
                return "error %d" % F.error_of(r)
            if r == 0 and (name == "FL2_endStream" or ib.pos == ib.size):
                break
    c("FL2_setCStreamTimeout", s.s, 0); s.close()
    return "ok" if bytes(got) == want_c else ("WRONG (decodes: %s)" % (z.decompress(bytes(got), len(small)) == small if True else ""))


res = {}
for i in range(int(sys.argv[1])):
    for name, fn in (("decode", decode_with_timeout), ("encode", encode_with_timeout)):
        try:
            r = fn()
        except Exception as e:
            r = "EXC %s" % e
        key = (name, r if not r.startswith("WRONG len") else "WRONG")
        res[key] = res.get(key, 0) + 1
        if r.startswith("WRONG"):
            print(name, r, flush=True)
print(os.path.basename(sys.argv[2]), res, flush=True)
