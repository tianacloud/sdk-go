#!/usr/bin/env python3
"""Export current source (including uncommitted changes), never Git history."""
import argparse
import pathlib
import shutil
import subprocess


def source_files(root):
    top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode == 0 and pathlib.Path(top.stdout.strip()).resolve() == root:
        result = subprocess.run(["git", "-C", str(root), "ls-files", "--cached",
                                 "--others", "--exclude-standard", "-z"],
                                capture_output=True, check=True)
        paths = sorted(set(pathlib.Path(p.decode()) for p in result.stdout.split(b"\0") if p))
    else:
        paths = sorted(p.relative_to(root) for p in root.rglob("*") if p.is_file() or p.is_symlink())
    return [p for p in paths if not any(part in {".git", ".artifacts", "__pycache__"} for part in p.parts)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    destination = args.destination.resolve()
    if destination == root or (destination.exists() and any(destination.iterdir())):
        parser.error("destination must be an empty directory outside the source files")
    paths = source_files(root)
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    for relative in paths:
        source = root / relative
        if source.is_symlink() or root not in source.resolve().parents:
            parser.error("source symlinks and paths outside the repository are not exportable")
        if not source.is_file():  # tracked deletions are intentionally absent
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
    print(f"Exported {count} current source files without Git history")


if __name__ == "__main__":
    main()
