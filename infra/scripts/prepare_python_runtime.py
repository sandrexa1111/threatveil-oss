"""Assemble official CPython runtime atop matching Debian distroless cc, with inventory.

Runs only in Docker's trusted build stage. Native libraries already in the pinned
distroless base are preserved; additional libraries retain their dpkg metadata.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

base = Path("/runtime-base")
output = Path("/runtime-rootfs")


def canonical(path):
    value = str(path)
    for prefix in ("/lib/", "/lib64/"):
        if value.startswith(prefix):
            return Path("/usr" + value)
    return Path(value)


def in_base(path):
    target = base / canonical(path).relative_to("/")
    for _ in range(12):
        if not target.is_symlink():
            return target.is_file()
        link = Path(os.readlink(target))
        target = base / link.relative_to("/") if link.is_absolute() else target.parent / link
        target = Path(os.path.normpath(target))
        if not target.is_relative_to(base):
            raise RuntimeError("Base symlink escaped its filesystem")
    raise RuntimeError("Base symlink loop")


def command(*arguments):
    # Absolute, fixed system tools inspect only files in reviewed image layers.
    # nosemgrep: local.semgrep-rules.python.lang.security.audit.dangerous-subprocess-use-audit
    return subprocess.run(arguments, check=True, text=True, capture_output=True).stdout  # noqa: S603


shutil.copytree("/usr/local", output / "usr/local", symlinks=True)
# The official slim image includes an unusable Tk extension without its GUI libraries.
# Hosted services have no Tk UI; remove that exact unsupported extension/package.
for extension in (output / "usr/local/lib/python3.13/lib-dynload").glob("_tkinter.*.so"):
    extension.unlink()
shutil.rmtree(output / "usr/local/lib/python3.13/tkinter", ignore_errors=True)
objects = [Path("/usr/local/bin/python3.13"), *[
    path for path in Path("/usr/local/lib/python3.13/lib-dynload").glob("*.so")
    if not path.name.startswith("_tkinter.")
]]
libraries = set()
for binary in objects:
    dependencies = command("/usr/bin/ldd", str(binary))
    if "not found" in dependencies:
        raise RuntimeError(f"Unresolved runtime dependency: {binary}")
    libraries.update(re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", dependencies, re.MULTILINE))

inventory = []
metadata = output / "var/lib/dpkg/status.d"
metadata.mkdir(parents=True, exist_ok=True)
for library in sorted(libraries):
    if Path(library).name == "libsqlite3.so.0":
        # The old Debian library is not delivered. Its upstream replacement has its own SBOM.
        patched = Path("/opt/threatveil-sqlite/libsqlite3.so.0")
        shutil.copy2(patched, output / "usr/local/lib/libsqlite3.so.0")
        continue
    if library.startswith("/usr/local/") or in_base(library):
        continue
    source = Path(library).resolve(strict=True)
    package = command("/usr/bin/dpkg-query", "--search", str(source)).split(": ", 1)[0]
    status = command("/usr/bin/dpkg-query", "--status", package)
    package_name = re.search(r"^Package: (.+)$", status, re.MULTILINE).group(1)
    if (base / "var/lib/dpkg/status.d" / package_name).exists():
        raise RuntimeError(f"Refusing a partial overwrite of a base-provided package: {package_name}")
    destination = output / canonical(source).relative_to("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    alias = output / canonical(library).relative_to("/")
    if alias != destination and not alias.exists():
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(os.path.relpath(destination, alias.parent))
    (metadata / package_name).write_text(status)
    inventory.append({"library": library, "source": str(source), "package": package_name})

manifest = output / "usr/local/share/threatveil/runtime-libraries.json"
manifest.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2("/opt/threatveil-sqlite/sqlite.cdx.json", manifest.parent / "sqlite.cdx.json")
manifest.write_text(json.dumps({"cpython": sys.version, "additional_libraries": inventory,
                               "excluded_stdlib_extension": "_tkinter (headless runtime)"}, indent=2))
print(f"Prepared CPython {sys.version.split()[0]} with {len(inventory)} additional inventoried libraries")
