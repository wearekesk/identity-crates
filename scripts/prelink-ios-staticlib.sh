#!/usr/bin/env bash
# Pre-link a Rust iOS static library so it can share an app with other Rust
# static libraries.
#
# A Rust staticlib carries its own copy of the Rust runtime (std, alloc,
# compiler_builtins). Those symbols are private-extern, which hides them from
# other images but not from other objects in the same link, so two Rust
# staticlibs loaded with -all_load collide on hundreds of duplicate symbols.
# `ld -r` folds the archive into one object and, without -keep_private_externs,
# makes every private-extern symbol local; the exports list keeps the FFI
# entry points global.
#
# _rust_eh_personality is kept as a weak private extern instead. Compact unwind
# can encode only three personality routines per image, and an app usually
# spends two on C++ and Objective-C, so a second local copy fails the link with
# "Too many personality routines". Weak, every Rust library in the image shares
# one; private, it is not exported from the image, so dyld never coalesces it
# with another framework's.
#
#   prelink-ios-staticlib.sh prelink   <in.a> <out.a> <target> <exports.txt>
#   prelink-ios-staticlib.sh check     <lib.a> <target> <exports.txt>
#   prelink-ios-staticlib.sh self-test <raw.a> <target> <exports.txt>
#
# <target> is a Rust target triple: aarch64-apple-ios, aarch64-apple-ios-sim
# or x86_64-apple-ios. <exports.txt> lists the FFI functions, one Mach-O
# symbol name per line (leading underscore, e.g. _my_ffi_fn). Inputs must be
# thin (one arch): run this before lipo. MIN_IOS overrides the deployment
# target (13.0, or 14.0 for arm64 simulators, which is Rust's floor there).
#
# check: the archive's defined globals are exactly the exports plus a weak
# private _rust_eh_personality, and it links with -all_load, together with C++
# and Objective-C code that use exceptions, beside a second Rust staticlib:
# once raw, and once pre-linked the same way.
# self-test: that link must FAIL for the raw archive (duplicate symbols) and
# for a pre-link that leaves the personality local (too many personalities);
# otherwise the check has stopped detecting either problem.
set -euo pipefail

PERSONALITY=_rust_eh_personality

die() { echo "prelink-ios-staticlib: $*" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

target_info() { # <target> -> sets ARCH SDK PLATFORM MIN CLANG_TARGET
  case "$1" in
    aarch64-apple-ios)     ARCH=arm64;  SDK=iphoneos;        PLATFORM=ios;           MIN=13.0 ;;
    aarch64-apple-ios-sim) ARCH=arm64;  SDK=iphonesimulator; PLATFORM=ios-simulator; MIN=14.0 ;;
    x86_64-apple-ios)      ARCH=x86_64; SDK=iphonesimulator; PLATFORM=ios-simulator; MIN=13.0 ;;
    *) die "unsupported target: $1" ;;
  esac
  MIN=${MIN_IOS:-$MIN}
  CLANG_TARGET="$ARCH-apple-ios$MIN${PLATFORM#ios}"
}

thin_or_die() { # <lib.a> <arch>
  local archs
  archs="$(lipo -archs "$1")" || die "lipo cannot read $1"
  [[ "$archs" == "$2" ]] || die "$1 has architectures '$archs'; expected a thin $2 archive"
}

read_exports() { # <exports.txt> -> sorted unique names on stdout
  grep -v '^[[:space:]]*$' "$1" | sort -u || die "exports list $1 has no names"
}

weaken() { # <object.o> <symbol>: make one defined global a weak private extern
  python3 -I - "$1" "$2" <<'PY'
import struct, sys
path, name = sys.argv[1], sys.argv[2].encode()
data = bytearray(open(path, "rb").read())
magic, _, _, filetype, ncmds = struct.unpack_from("<IiiII", data, 0)
if magic != 0xFEEDFACF or filetype != 1:  # MH_MAGIC_64, MH_OBJECT
    sys.exit(f"{path}: not a 64-bit Mach-O object file")
off, hits = 32, 0
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", data, off + 8)
        for i in range(nsyms):
            e = symoff + 16 * i
            strx, ntype, _, desc = struct.unpack_from("<IBBH", data, e)
            end = data.index(0, stroff + strx)
            if ntype & 0xE0 or bytes(data[stroff + strx:end]) != name:  # skip N_STAB entries
                continue
            if ntype & 0x0E != 0x0E or not ntype & 0x01 or ntype & 0x10:  # N_SECT, N_EXT, not N_PEXT
                sys.exit(f"{path}: {name.decode()} is not a defined global (n_type {ntype:#x})")
            struct.pack_into("<B", data, e + 4, ntype | 0x10)  # N_PEXT
            struct.pack_into("<H", data, e + 6, desc | 0x0080)  # N_WEAK_DEF
            hits += 1
    off += size
if hits != 1:
    sys.exit(f"{path}: expected one defined {name.decode()}, found {hits}")
open(path, "wb").write(data)
PY
}

prelink_into() { # <in.a> <out.a> <exports.txt> <personality: weak|local>; target_info already set
  local in=$1 out=$2 exports=$3 personality=$4 dir
  dir="$(mktemp -d "$WORK/prelink.XXXX")"
  read_exports "$exports" > "$dir/exports.txt"
  if [[ "$personality" == weak ]]; then echo "$PERSONALITY" >> "$dir/exports.txt"; fi
  # -all_load: ld -r pulls an archive member only to resolve an undefined
  # symbol, and with no other input nothing is undefined.
  xcrun ld -r -arch "$ARCH" -platform_version "$PLATFORM" "$MIN" "$(xcrun -sdk "$SDK" --show-sdk-version)" \
    -all_load -exported_symbols_list "$dir/exports.txt" "$in" -o "$dir/prelinked.o"
  if [[ "$personality" == weak ]]; then weaken "$dir/prelinked.o" "$PERSONALITY"; fi
  mkdir -p "$(dirname "$out")"
  rm -f "$out"
  xcrun libtool -static -o "$out" "$dir/prelinked.o"
}

prelink() { # <in.a> <out.a> <target> <exports.txt>
  target_info "$3"
  thin_or_die "$1" "$ARCH"
  [[ -s "$4" ]] || die "exports list $4 is empty"
  prelink_into "$1" "$2" "$4" weak
}

other_lib() { # <target> <raw|weak> -> sets OTHER_LIB to a second Rust staticlib; target_info already set
  local dir="$WORK/other-$1"
  if [[ ! -f "$dir/raw.a" ]]; then
    mkdir -p "$dir"
    echo '#[no_mangle] pub extern "C" fn other_ffi() {}' | rustc --edition 2021 --crate-type staticlib \
      --crate-name other --target "$1" -C opt-level=2 -o "$dir/raw.a" -
    echo _other_ffi > "$dir/exports.txt"
    prelink_into "$dir/raw.a" "$dir/weak.a" "$dir/exports.txt" weak
  fi
  OTHER_LIB="$dir/$2.a"
}

collision_link() { # <lib.a> <target> <exports.txt> <raw|weak> <log>; target_info already set; returns the link status
  local lib=$1 exports=$3 log=$5 dir sym rc
  other_lib "$2" "$4"
  dir="$(mktemp -d "$WORK/link.XXXX")"
  sym="$(read_exports "$exports" | head -1)"
  sym="${sym#_}"
  # The two personalities an app's own code typically brings.
  printf 'extern void %s(void);\nint objc_try(void);\nint cxx_try(void);\nint main(void) { return (int)(long)&%s == 0 || !objc_try() || !cxx_try(); }\n' \
    "$sym" "$sym" > "$dir/main.c"
  printf '#import <Foundation/Foundation.h>\nint objc_try(void) { @try { @throw [NSException exceptionWithName:@"e" reason:nil userInfo:nil]; } @catch (NSException *e) { return 1; } return 0; }\n' > "$dir/objc.m"
  printf '#include <stdexcept>\nextern "C" int cxx_try(void) { try { throw std::runtime_error("e"); } catch (const std::exception &) { return 1; } return 0; }\n' > "$dir/cxx.cpp"
  set +e
  xcrun -sdk "$SDK" clang -target "$CLANG_TARGET" "$dir/main.c" "$dir/objc.m" "$dir/cxx.cpp" -Wl,-all_load \
    "$lib" "$OTHER_LIB" -framework Foundation -framework Security -lc++ -liconv \
    -o "$dir/a.out" > "$log" 2>&1
  rc=$?
  set -e
  return "$rc"
}

check() { # <lib.a> <target> <exports.txt>
  local lib=$1 t=$2 exports=$3 log="$WORK/check.log" other
  target_info "$t"
  thin_or_die "$lib" "$ARCH"
  if ! diff <({ read_exports "$exports"; echo "$PERSONALITY"; } | sort -u) \
            <(nm --no-llvm-bc -gUj "$lib" | grep -v -e '^$' -e ':$' | sort -u); then
    die "$lib: defined globals differ from $exports plus $PERSONALITY (< expected, > actual)"
  fi
  # grep -c, not -q: an early exit would SIGPIPE nm under pipefail.
  nm --no-llvm-bc -m "$lib" | grep -c "weak private external $PERSONALITY\$" > /dev/null \
    || die "$lib: $PERSONALITY is not a weak private extern"
  for other in raw weak; do
    if ! collision_link "$lib" "$t" "$exports" "$other" "$log"; then
      cat "$log" >&2
      die "$lib does not link beside a $other Rust staticlib ($t)"
    fi
  done
  echo "ok: $lib ($t) exports $(read_exports "$exports" | wc -l | tr -d ' ') functions and links beside raw and pre-linked Rust staticlibs"
}

self_test() { # <raw.a> <target> <exports.txt>
  local lib=$1 t=$2 exports=$3 log="$WORK/self-test.log" local_lib="$WORK/local/lib.a"
  target_info "$t"
  thin_or_die "$lib" "$ARCH"
  if collision_link "$lib" "$t" "$exports" raw "$log"; then
    die "self-test: the raw $lib linked, so the check would not catch duplicate symbols"
  fi
  grep -q 'duplicate symbol' "$log" || { cat "$log" >&2; die "self-test: the raw link failed, but not on duplicate symbols"; }
  prelink_into "$lib" "$local_lib" "$exports" local
  if collision_link "$local_lib" "$t" "$exports" raw "$log"; then
    die "self-test: a pre-link with a local $PERSONALITY linked, so the check would not catch the personality limit"
  fi
  if ! grep -qi 'too many personality routines' "$log" || grep -q 'duplicate symbol' "$log"; then
    cat "$log" >&2
    die "self-test: the local-personality pre-link failed, but not only on the personality limit"
  fi
  echo "ok: self-test, $lib ($t): the raw archive collides and a local-personality pre-link runs out of personalities"
}

cmd=${1:-}
shift || true
case "$cmd" in
  prelink)   [[ $# -eq 4 ]] || die "usage: prelink <in.a> <out.a> <target> <exports.txt>"; prelink "$@" ;;
  check)     [[ $# -eq 3 ]] || die "usage: check <lib.a> <target> <exports.txt>"; check "$@" ;;
  self-test) [[ $# -eq 3 ]] || die "usage: self-test <raw.a> <target> <exports.txt>"; self_test "$@" ;;
  *) die "usage: $0 prelink|check|self-test ..." ;;
esac
