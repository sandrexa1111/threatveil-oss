"""Build the verified SQLite amalgamation as a shared library; keep upstream provenance."""

import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

VERSION = "3.53.4"
ARCHIVE_SHA3 = "628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e"
SOURCE_SHA3 = "67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16"
# Docker ADD supplies this fixed build-only artifact; two publisher hashes are verified.
archive = Path("/tmp/sqlite-amalgamation.zip")  # noqa: S108
if hashlib.sha3_256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA3:
    raise RuntimeError("SQLite archive differs from the publisher's release checksum")
output = Path("/opt/threatveil-sqlite")
output.mkdir()
with zipfile.ZipFile(archive) as bundle:
    # Read exact entries into fixed filenames; never extract arbitrary archive paths.
    for filename in ("sqlite3.c", "sqlite3.h"):
        (output / filename).write_bytes(bundle.read(f"sqlite-amalgamation-3530400/{filename}"))
if hashlib.sha3_256((output / "sqlite3.c").read_bytes()).hexdigest() != SOURCE_SHA3:
    raise RuntimeError("SQLite C source differs from the publisher's release checksum")
subprocess.run([
    "/usr/bin/gcc", "-O2", "-fPIC", "-shared", "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=2", "-DSQLITE_THREADSAFE=1", "-DSQLITE_ENABLE_FTS5",
    "-DSQLITE_ENABLE_COLUMN_METADATA", "-DSQLITE_ENABLE_RTREE",
    "-Wl,-soname,libsqlite3.so.0", "-Wl,-z,relro,-z,now",
    "/opt/threatveil-sqlite/sqlite3.c", "-o", "/opt/threatveil-sqlite/libsqlite3.so.0",
    "-lpthread", "-ldl", "-lm",
], check=True)
library = ctypes.CDLL(str(output / "libsqlite3.so.0"))
library.sqlite3_libversion.restype = ctypes.c_char_p
if library.sqlite3_libversion().decode() != VERSION:
    raise RuntimeError("Built SQLite version differs from the reviewed source")
binary_hash = hashlib.sha256((output / "libsqlite3.so.0").read_bytes()).hexdigest()
component = {
    "type": "library", "name": "sqlite", "version": VERSION,
    "bom-ref": f"pkg:generic/sqlite@{VERSION}", "purl": f"pkg:generic/sqlite@{VERSION}",
    "cpe": f"cpe:2.3:a:sqlite:sqlite:{VERSION}:*:*:*:*:*:*:*",
    "hashes": [{"alg": "SHA-256", "content": binary_hash}],
    "externalReferences": [{"type": "distribution", "url": "https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip"}],
    "properties": [{"name": "threatveil:source-sha3-256", "value": SOURCE_SHA3},
                   {"name": "threatveil:archive-sha3-256", "value": ARCHIVE_SHA3}],
}
(output / "sqlite.cdx.json").write_text(json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "components": [component],
}, indent=2))
print(f"Verified SQLite {VERSION} shared library built with upstream source and binary provenance")
