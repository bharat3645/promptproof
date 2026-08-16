"""Python bindings for promptproof, built on its C ABI (see ../../capi).

Zero third-party dependencies: this module uses only the stdlib ``ctypes``
and ``json`` to load ``libpromptproof_capi`` and call its two exported
functions (``promptproof_scan`` / ``promptproof_free_string``). It does not
reimplement any detection logic — every scan runs the real Rust engine.

Usage::

    import promptproof

    report = promptproof.scan("Ignore all previous instructions.")
    report["verdict"]   # "dangerous" | "suspicious" | "ok"
    report["score"]     # int
    report["findings"]  # list of dicts

The compiled library is not bundled with this module — build it first with
``cargo build --release`` from the ``capi/`` directory (or a source
distribution of it), then either set the ``PROMPTPROOF_CAPI_LIB``
environment variable to the built file's path, or leave it unset and this
module will look for ``capi/target/release/libpromptproof_capi.{so,dylib}``
relative to the repository root, then fall back to the platform's normal
shared-library search path (``ctypes.util.find_library``).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import sys

__all__ = ["scan", "PromptproofError", "PromptproofLibraryError"]
__version__ = "0.1.0"


class PromptproofError(Exception):
    """Base class for errors raised by this binding."""


class PromptproofLibraryError(PromptproofError):
    """Raised when the compiled promptproof-capi library cannot be loaded."""


def _candidate_lib_names():
    system = platform.system()
    if system == "Darwin":
        return ["libpromptproof_capi.dylib"]
    if system == "Windows":
        return ["promptproof_capi.dll"]
    return ["libpromptproof_capi.so"]


def _repo_relative_candidates():
    # bindings/python/promptproof/__init__.py -> capi/target/{release,debug}
    here = os.path.dirname(os.path.abspath(__file__))
    capi_dir = os.path.normpath(os.path.join(here, "..", "..", "..", "capi"))
    for profile in ("release", "debug"):
        for name in _candidate_lib_names():
            yield os.path.join(capi_dir, "target", profile, name)


def _find_library_path():
    env_path = os.environ.get("PROMPTPROOF_CAPI_LIB")
    if env_path:
        if not os.path.isfile(env_path):
            raise PromptproofLibraryError(
                f"PROMPTPROOF_CAPI_LIB is set to {env_path!r} but that file does not exist"
            )
        return env_path

    for candidate in _repo_relative_candidates():
        if os.path.isfile(candidate):
            return candidate

    found = ctypes.util.find_library("promptproof_capi")
    if found:
        return found

    raise PromptproofLibraryError(
        "could not locate libpromptproof_capi. Build it with "
        "`cargo build --release` from the capi/ directory, then either set "
        "the PROMPTPROOF_CAPI_LIB environment variable to the built "
        "library's path, or run from a checkout where capi/target/release "
        "sits alongside this bindings/python directory."
    )


def _load_library():
    path = _find_library_path()
    try:
        lib = ctypes.CDLL(path)
    except OSError as exc:  # pragma: no cover - platform/loader-dependent
        raise PromptproofLibraryError(f"failed to load {path!r}: {exc}") from exc

    lib.promptproof_scan.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.promptproof_scan.restype = ctypes.c_void_p
    lib.promptproof_free_string.argtypes = [ctypes.c_void_p]
    lib.promptproof_free_string.restype = None
    return lib


_lib = None


def _get_lib():
    global _lib
    if _lib is None:
        _lib = _load_library()
    return _lib


def scan(data):
    """Scan ``data`` (``str`` or ``bytes``) and return the parsed JSON report.

    Mirrors ``promptproof scan --json`` / the C ABI's ``promptproof_scan``:
    the returned ``dict`` has ``source``, ``verdict``, ``score``, ``stats``,
    and ``findings`` keys. A ``str`` is encoded as UTF-8 before crossing the
    FFI boundary; invalid UTF-8 bytes are lossily decoded on the Rust side,
    never a hard failure.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        payload = bytes(data)
    else:
        raise TypeError(f"scan() expects str or bytes, got {type(data).__name__}")

    lib = _get_lib()
    # ctypes' c_char_p accepts None for a NULL pointer when len is 0; for a
    # non-empty empty-bytes object it still passes a valid (non-null)
    # pointer, matching the C ABI's contract (NULL only allowed when len==0).
    buf = payload if payload else None
    ptr = lib.promptproof_scan(buf, ctypes.c_size_t(len(payload)))
    if not ptr:
        raise PromptproofError(
            "promptproof_scan returned NULL (unexpected: only occurs on a "
            "null input pointer with nonzero length, which this binding "
            "never passes)"
        )
    try:
        json_bytes = ctypes.cast(ptr, ctypes.c_char_p).value
        return json.loads(json_bytes.decode("utf-8"))
    finally:
        lib.promptproof_free_string(ptr)


if __name__ == "__main__":  # pragma: no cover
    text = sys.stdin.read()
    print(json.dumps(scan(text), indent=2))
