#!/usr/bin/env python3
"""Reject private hostnames in source and decoded PEM blocks; print paths only."""
import argparse
import base64
import pathlib
import re

# Construct labels separately so the scanner does not embed a private address.
FORBIDDEN = re.compile(rb"(?:[a-z0-9-]+\.)*internal(?:\.[a-z0-9-]+)+|(?:[a-z0-9-]+\.)+internal\b", re.I)
PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    failed = []
    count = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in {".git", ".artifacts", "__pycache__"} for part in relative.parts):
            continue
        if path.is_symlink():
            failed.append(str(relative) + " (symlink)")
            continue
        if not path.is_file():
            continue
        count += 1
        data = path.read_bytes()
        blocks = [data]
        for match in PEM.finditer(data):
            blocks.append(base64.b64decode(re.sub(rb"\s+", b"", match.group(2)), validate=True))
        if any(FORBIDDEN.search(block) for block in blocks):
            failed.append(str(relative))
    if failed:
        for path in failed:
            print("Private address or unsafe source path:", path)
        raise SystemExit(1)
    print(f"Public hostname scan passed: {count} files, including decoded PEM blocks")


if __name__ == "__main__":
    main()
