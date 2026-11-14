#!/usr/bin/env python3
"""Authoritative candidate-path observation for the config inventory.

Single standard-library filesystem boundary replacing the shell -e/-f
predicates for the Cargo config-candidate walk. Given one candidate path, it
prints exactly one status token on stdout and exits 0 when the observation
resolves:

- present     regular file reachable at the path (a digest is computed by
              the caller with the checked sha256 hasher)
- absent      no entry at the path (ENOENT) -- the only verified absence
- denied      EACCES/EPERM on traversal or target (unreachable ancestor or
              file); never reported as absent
- dangling    symlink whose target is absent; a failed/nonregular candidate,
              never reported as absent
- nonregular  entry exists but is not a regular file once symlinks resolve
- error       any other OSError (symlink loops, I/O faults, ...)

Symlink and parent-traversal distinctions are kept: lstat detects the entry
type; stat follows the link. Failures are never folded into absent.
"""
import errno
import os
import stat
import sys


def _fault_word(err):
    """A denied traversal or an unresolvable fault; neither is ever an absence."""
    if err.errno in (errno.EACCES, errno.EPERM):
        return "denied"
    return "error"


def _absent_word(err):
    """Only ENOENT at the path itself proves absence."""
    if err.errno == errno.ENOENT:
        return "absent"
    return _fault_word(err)


def _dangling_word(err):
    """ENOENT through a symlink is dangling, never absent."""
    if err.errno == errno.ENOENT:
        return "dangling"
    return _fault_word(err)


def _mode_word(mode):
    """A regular file once symlinks resolve; every other entry is nonregular."""
    if stat.S_ISREG(mode):
        return "present"
    return "nonregular"


def observe(path):
    # lstat names the entry type, stat follows the link; each failure path owns
    # its own word and the caller only ever sees one.
    try:
        lst = os.lstat(path)
    except OSError as err:
        return _absent_word(err)
    if not stat.S_ISLNK(lst.st_mode):
        return _mode_word(lst.st_mode)
    try:
        st = os.stat(path)
    except OSError as err:
        return _dangling_word(err)
    return _mode_word(st.st_mode)


def main():
    if len(sys.argv) != 2:
        print("usage: cargo_config_probe.py <candidate-path>", file=sys.stderr)
        return 2
    print(observe(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
