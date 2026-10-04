"""Build official 7-Zip's LZMA/LZMA2 code, from an exact upstream tag (default 25.01, the version GrindCore vendors),
as a small shared library: the reference for gctest/test_lzma_reference.py and gctest/test_lzma_dec.py.

The files come from github.com/ip7z/7zip (Igor Pavlov's official repository) and are compiled unmodified. For 25.01
every file is checked against a pinned SHA-256 (PINNED, taken from the tag on 2026-10-02; the C files are the ones
GrindCore vendors, all identical apart from the hook's LzmaEnc.c and Lzma2Enc.c). Stdlib only, Python 3.6+.

Variants:
  default   the C decoder: what GrindCore builds on every RID except win-x64.
  --asm     7-Zip's assembler decoder (LzmaDec_DecodeReal_3, -DZ7_LZMA_DEC_OPT), as upstream builds it:
              win-x64: Asm/x86/LzmaDecOpt.asm with MSVC's ml64, the decoder GrindCore's win-x64 build uses;
              arm64 (Linux, macOS): Asm/arm64/LzmaDecOpt.S, which GrindCore vendors but doesn't build;
              win-arm64: the same .S, assembled by clang (Visual Studio's C++ Clang tools) for
                aarch64-pc-windows-msvc and linked by MSVC, or --asm-obj with an object assembled elsewhere.
            Upstream's x86-64 .asm is MASM syntax; on Linux/macOS it needs asmc or uasm, which aren't used here.

  python3 build_7zip_ref.py [--tag 25.01] [--out DIR] [--cc cc] [--asm] [--src DIR] [--fetch-only DIR]
  -> DIR/lib7zref[-asm].so (.dylib on macOS, .dll on Windows). Point GC_REF_7ZIP at it.

Windows: needs Visual Studio with the C++ tools; vcvarsall is found with vswhere, for the bitness of this Python
(--arch to override). Off Windows: --cc as for the other references (the compiler doesn't change LZMA's output).
--src takes a folder holding C/ and Asm/ as fetched before (hosts without network); --fetch-only DIR fills one."""
import argparse
import hashlib
import os
import platform
import struct
import subprocess
import sys
import urllib.request

C_FILES = ["7zStream.c", "Alloc.c", "CpuArch.c", "LzFind.c", "LzFindMt.c", "LzFindOpt.c", "Lzma2Dec.c", "Lzma2DecMt.c",
           "Lzma2Enc.c", "LzmaDec.c", "LzmaEnc.c", "MtCoder.c", "MtDec.c", "Threads.c"]
H_FILES = ["7zTypes.h", "7zWindows.h", "Alloc.h", "Compiler.h", "CpuArch.h", "LzFind.h", "LzFindMt.h", "LzHash.h",
           "Lzma2Dec.h", "Lzma2DecMt.h", "Lzma2Enc.h", "LzmaDec.h", "LzmaEnc.h", "MtCoder.h", "MtDec.h", "Precomp.h",
           "RotateDefs.h", "Threads.h"]
ASM_FILES = ["x86/LzmaDecOpt.asm", "x86/7zAsm.asm", "arm64/LzmaDecOpt.S", "arm64/7zAsm.S"]

PINNED = {"25.01": {
    "C/7zStream.c": "835941df3324d828770bc09749a976bad8449e3733896d51bf102557c9ac0acb",
    "C/7zTypes.h": "5de943c886d5d7bbcf16203e9b292a9e7be327b43fe3dfd9f4ad07d6d0870ef6",
    "C/7zWindows.h": "8e7d4ed4f6599ca599514d5c1710668a61865f0c11c44b47994aede33f4cac16",
    "C/Alloc.c": "c6fd2197a63b3e7b0629d2da54c3bd99cf37b036cee9307171cb8724db472eb1",
    "C/Alloc.h": "ba50561a4697f305b797f526d0e473645639fa3ad3fd3fcda5e037740cd8be76",
    "C/Compiler.h": "e4b14a798e6c01bc885966249afa6b5061a5dd10c723ce86b254e89ae650de7f",
    "C/CpuArch.c": "9f215eaf12eaafdb6e83755bb3ac82fe3629905fcd9d257880a89ef2edd67755",
    "C/CpuArch.h": "0af64ee3470cd06772ea4836f08f0eb1cb39b7d4d38ce13d2224a6578fd8c7d9",
    "C/LzFind.c": "f73da68845094a85b006a0d2da80b3ecdec92a1ca0f85df637e565c642e8d5ba",
    "C/LzFind.h": "42732b38df9bb18f82866d7deaa8663f6c6f9cb10e2a2cdfa9e6f420c2e2f239",
    "C/LzFindMt.c": "6b04cd48e97c14a26f01865adde16440160f367e72a7b1ffda8ca084472ae223",
    "C/LzFindMt.h": "1851370be11bd1b998974a094f1997a34da91ad6474641c27bbd83a9a38fb4a8",
    "C/LzFindOpt.c": "c8ac04141e38d825e74984e924842e76fc903d74472dd8354470f23ecbfd853a",
    "C/LzHash.h": "42d146d2130dfe49d0b21d15cc6f0fe9d79ac0ebb629985fe3aedde7b2bee80e",
    "C/Lzma2Dec.c": "3d691d30e4a1f4b661d56fc483db702167ff6a91781d143a017c793c1860476f",
    "C/Lzma2Dec.h": "a4b97083c3817d3e1e3049f8b1abc0b4ca3e91192606497c02bb5351b57422c7",
    "C/Lzma2DecMt.c": "9be6852324b9fb6d9f365590a273c9dbeb33f084ed01e2382981033a531f0f5e",
    "C/Lzma2DecMt.h": "b7d3f0d6370cfed2d91380dcb45d535e16191c65a7e63932d6c878113cf99261",
    "C/Lzma2Enc.c": "aa8ce1b218c0aad21884c3a436defbbc2d9b60bcd753d6fa7cfb196f19d4ccd5",
    "C/Lzma2Enc.h": "d0fc59677e8e2b51e7182916a65a09bdd1625b29a9621c0042ae8fc64cf1e919",
    "C/LzmaDec.c": "b9ca2b8707400347c75d6fef288d1354a3b4cf93e8da42f26207b8bd4c4d5e59",
    "C/LzmaDec.h": "3aaf07b4ae4173a2d103179455dc7089b5ddbc7fc3db3c0e40964a7499c69266",
    "C/LzmaEnc.c": "51433dc03a3d3a574d30621cb584069d6915e99b100ee67f2d11549e4011b49f",
    "C/LzmaEnc.h": "c5e78398309363dd181840b7ba0bcb856f66619f755d5e2f5e04f7437186ba5f",
    "C/MtCoder.c": "bbb952acf0bb36ff2c7d5a79204696a3a7d8ac53ba3588d093541a5e016798d0",
    "C/MtCoder.h": "e14b8bccded0f359f89be0ed48bdc3fcdd58f2cfe39eba3adf6bccf4dd65405d",
    "C/MtDec.c": "75d2c2979311baf18453c322337213c88a26fe256e8ae445710aceb3fd289edd",
    "C/MtDec.h": "c5eb7b409ef86b15f03b8c7c1d58668e89d864f0e19baa2a3fe9fd41819b1df0",
    "C/Precomp.h": "fea249c753dfbbdd69d9397e91497205452b784279f70cad4658dc567cd2f85f",
    "C/RotateDefs.h": "9bc3ff572bec5611c5c2508b7d0c18706a1dc4c908ea3bd432237c33056e1f28",
    "C/Threads.c": "7a55fd15f700f9737be4042a2231350cd29ceed0c284599ebd0e40f25ddf2435",
    "C/Threads.h": "166b4d1ae24f650513e0cc8421af1656ad36aafc9e9a6c9984ec36d33e787b4f",
    "Asm/arm64/7zAsm.S": "4ac9f07dcba411a08e1f3e5f9e3610410beec0624fbbb91eab65ad8b4abd43a7",
    "Asm/arm64/LzmaDecOpt.S": "25ee0f34dd5f304ebfce3bb1b016fdee60c876a42e6a90981aa228d59c317552",
    "Asm/x86/7zAsm.asm": "8a06bb3e5d26ed5b0a311141203469c31ca1119326d6bb12fcc6dc495b94e184",
    "Asm/x86/LzmaDecOpt.asm": "bddfb31a59c49c8f25f75d19e7330437d2ca3ba81d9655fa427d7585521a3859",
}}

# What the tests call by name. Off Windows every global symbol is exported; MSVC needs a .def.
EXPORTS = ["LzmaProps_Decode", "LzmaDec_Init", "LzmaDec_AllocateProbs", "LzmaDec_FreeProbs", "LzmaDec_Allocate",
           "LzmaDec_Free", "LzmaDec_DecodeToDic", "LzmaDec_DecodeToBuf", "LzmaDecode",
           "Lzma2Dec_AllocateProbs", "Lzma2Dec_Allocate", "Lzma2Dec_Init", "Lzma2Dec_DecodeToDic",
           "Lzma2Dec_DecodeToBuf", "Lzma2Dec_Parse", "Lzma2Decode",
           "Lzma2DecMtProps_Init", "Lzma2DecMt_Create", "Lzma2DecMt_Destroy", "Lzma2DecMt_Decode",
           "LzmaEncProps_Init", "LzmaEncode", "LzmaEnc_Create", "LzmaEnc_Destroy", "LzmaEnc_SetProps",
           "LzmaEnc_SetDataSize", "LzmaEnc_WriteProperties", "LzmaEnc_MemEncode",
           "Lzma2EncProps_Init", "Lzma2EncProps_Normalize", "Lzma2Enc_Create", "Lzma2Enc_Destroy", "Lzma2Enc_SetProps",
           "Lzma2Enc_WriteProperties", "Lzma2Enc_Encode2"]
EXPORT_DATA = ["g_Alloc", "g_BigAlloc", "g_AlignedAlloc"]


def fetch(tag, src):
    pins = PINNED.get(tag)
    if pins is None:
        print("warning: tag %s has no pinned hashes; the files are not checked" % tag)
    for rel in ["C/" + n for n in C_FILES + H_FILES] + ["Asm/" + n for n in ASM_FILES]:
        path = os.path.join(src, *rel.split("/"))
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            url = "https://raw.githubusercontent.com/ip7z/7zip/%s/%s" % (tag, rel)
            with urllib.request.urlopen(url, timeout=60) as r:
                body = r.read()
            with open(path, "wb") as f:
                f.write(body)
        if pins is not None:
            with open(path, "rb") as f:
                got = hashlib.sha256(f.read()).hexdigest()
            if got != pins[rel]:
                sys.exit("%s: SHA-256 %s, expected %s (not official 7-Zip %s)" % (path, got, pins[rel], tag))


def arch_name(a):
    if a.arch:
        return a.arch
    m = platform.machine().lower()
    if m in ("arm64", "aarch64"):
        return "arm64"
    if struct.calcsize("P") == 4:
        return "x86"
    return "x64"


def build_unix(a, src, lib):
    cdir = os.path.join(src, "C")
    cmd = a.cc.split() + ["-O2", "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", lib,
                          "-I", cdir] + [os.path.join(cdir, c) for c in C_FILES]
    if a.asm:
        if arch_name(a) != "arm64":
            sys.exit("--asm off Windows is the arm64 decoder only (upstream's x86-64 LzmaDecOpt.asm is MASM syntax)")
        cmd += ["-DZ7_LZMA_DEC_OPT", "-I", os.path.join(src, "Asm", "arm64"),
                os.path.join(src, "Asm", "arm64", "LzmaDecOpt.S")]
    if sys.platform != "darwin":
        cmd += ["-lpthread", "-Wl,-z,defs"]
    print(" ".join(cmd))
    subprocess.check_call(cmd)


def find_clang(vswhere):
    """Visual Studio's own clang (the "C++ Clang tools" component), else one on PATH, else None."""
    out = subprocess.run([vswhere, "-latest", "-products", "*", "-find", r"VC\Tools\Llvm\**\bin\clang.exe"],
                         stdout=subprocess.PIPE, universal_newlines=True).stdout.splitlines()
    # Visual Studio ships clang per host CPU (Llvm\x64\bin, Llvm\ARM64\bin); either targets every architecture
    hostdir = "\\arm64\\" if platform.machine().lower() in ("arm64", "aarch64") else "\\x64\\"
    out = [p for p in out if hostdir in p.lower()] or out
    if out:
        return out[0]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.exists(os.path.join(d, "clang.exe")):
            return os.path.join(d, "clang.exe")
    return None


def build_windows(a, src, lib):
    arch = arch_name(a)
    if a.asm and arch == "x86":
        sys.exit("--asm on Windows: x64 (LzmaDecOpt.asm with ml64) or arm64 (LzmaDecOpt.S with clang)")
    vswhere = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                           "Microsoft Visual Studio", "Installer", "vswhere.exe")
    component = "Microsoft.VisualStudio.Component.VC.Tools." + ("ARM64" if arch == "arm64" else "x86.x64")
    vs = subprocess.check_output([vswhere, "-latest", "-products", "*", "-requires", component, "-property",
                                  "installationPath"], universal_newlines=True).strip().splitlines()
    if not vs:
        sys.exit("no Visual Studio with %s (vswhere found none)" % component)
    vcvars = os.path.join(vs[0], "VC", "Auxiliary", "Build", "vcvarsall.bat")
    work = lib + ".work"
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(work, "ref.def"), "w") as f:
        f.write("EXPORTS\n" + "".join("  %s\n" % n for n in EXPORTS) + "".join("  %s DATA\n" % n for n in EXPORT_DATA))
    cdir = os.path.join(src, "C")
    cl = 'cl /nologo /c /O2 /Oi /Gy /MT /DNDEBUG /W3 /I"%s"%s %s' % (
        cdir, " /DZ7_LZMA_DEC_OPT" if a.asm else "", " ".join('"%s"' % os.path.join(cdir, c) for c in C_FILES))
    steps = [cl]
    objs = ["%s.obj" % os.path.splitext(c)[0] for c in C_FILES]
    if a.asm and arch == "x64":
        adir = os.path.join(src, "Asm", "x86")
        steps.append('ml64 /nologo /c /I"%s" /Fo LzmaDecOpt.obj "%s"' % (adir, os.path.join(adir, "LzmaDecOpt.asm")))
        objs.append("LzmaDecOpt.obj")
    elif a.asm:
        # arm64: upstream's GNU-syntax LzmaDecOpt.S, which MSVC's armasm64 can't read. LLVM's assembler builds it
        # unmodified for aarch64-pc-windows-msvc (it uses no x18, which Windows reserves for the TEB), and MSVC links
        # the COFF object. Like the x64 .asm, it has no unwind data. --asm-obj takes one assembled elsewhere.
        if a.asm_obj:
            obj = os.path.abspath(a.asm_obj)
        else:
            clang = find_clang(vswhere)
            if not clang:
                sys.exit("--asm on win-arm64 needs clang (Visual Studio's C++ Clang tools) or --asm-obj")
            adir = os.path.join(src, "Asm", "arm64")
            obj = os.path.join(work, "LzmaDecOpt.obj")
            subprocess.check_call([clang, "--target=aarch64-pc-windows-msvc", "-c", "-I", adir, "-o", obj,
                                   os.path.join(adir, "LzmaDecOpt.S")])
        objs.append('"%s"' % obj)
    steps.append('link /nologo /DLL /DEF:ref.def /OUT:"%s" %s' % (lib, " ".join(objs)))
    host = platform.machine().lower()
    vcarch = "x64_arm64" if arch == "arm64" and host in ("amd64", "x86_64") else arch   # cross-compiling, as CI does
    line = 'call "%s" %s >nul && %s' % (vcvars, vcarch, " && ".join(steps))
    print(line)
    # one string with /s: a list would be re-quoted with \" escapes, which cmd.exe doesn't understand
    r = subprocess.call('cmd /d /s /c "%s"' % line, cwd=work)
    if r:
        sys.exit("build failed (%d)" % r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="25.01")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--asm", action="store_true")
    ap.add_argument("--asm-obj", help="win-arm64 --asm: a LzmaDecOpt.obj assembled elsewhere (clang "
                    "--target=aarch64-pc-windows-msvc), for hosts without clang")
    ap.add_argument("--arch", choices=("x64", "x86", "arm64"))
    ap.add_argument("--src", help="a folder with C/ and Asm/ from an earlier fetch (checked against the pins)")
    ap.add_argument("--fetch-only", metavar="DIR", help="fetch and check the files into DIR, and build nothing")
    a = ap.parse_args()
    if a.fetch_only:
        fetch(a.tag, a.fetch_only)
        print(a.fetch_only)
        return
    src = os.path.abspath(a.src or os.path.join(a.out, "7zip-" + a.tag))   # MSVC runs in a work folder
    fetch(a.tag, src)
    ext = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
    lib = os.path.abspath(os.path.join(a.out, "lib7zref" + ("-asm" if a.asm else "") + ext))
    os.makedirs(a.out, exist_ok=True)
    (build_windows if os.name == "nt" else build_unix)(a, src, lib)
    print(lib)


if __name__ == "__main__":
    main()
