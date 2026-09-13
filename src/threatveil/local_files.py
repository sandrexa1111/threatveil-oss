"""Descriptor-relative local files; untrusted namespace components never follow links."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path


def components(value):
    parts = Path(value).parts
    if not parts or any(part in ("", ".", "..", "/") for part in parts):
        raise ValueError("Invalid local namespace")
    return parts


@contextmanager
def directory_fd(root, parts=(), *, create=False):
    """The configured root is trusted; each child directory must be a real directory."""
    root = Path(root)
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            if components(part) != (part,):
                raise ValueError("Invalid local directory component")
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def read_file(descriptor, name, limit):
    if components(name) != (name,):
        raise ValueError("Invalid local file name")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Local file must be regular")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Local file exceeds its size limit")
    return value


def unlink_file(root, relative):
    parts = components(relative)
    try:
        with directory_fd(root, parts[:-1]) as descriptor:
            info = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Refusing nonregular local cleanup object")
            os.unlink(parts[-1], dir_fd=descriptor)
            os.fsync(descriptor)
            return True
    except FileNotFoundError:
        return False
