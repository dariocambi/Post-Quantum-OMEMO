#!/usr/bin/env python3

import argparse
from pathlib import Path


def run(file_path: str, old: str, new: str) -> None:
    path = Path(file_path)
    new_path = path.with_name(path.name.replace(old, new))
    path.rename(new_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Rename File", description="Replaces old with new string in filename"
    )

    parser.add_argument("file_path")
    parser.add_argument("old")
    parser.add_argument("new")

    args = parser.parse_args()
    run(args.file_path, args.old, args.new)
