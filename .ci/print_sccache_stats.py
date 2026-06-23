#!/usr/bin/env python3

import argparse
import json
import numbers
import shutil
import subprocess
import sys


def sum_numbers(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, numbers.Number):
        return int(value)
    if isinstance(value, dict):
        return sum(sum_numbers(item) for item in value.values())
    if isinstance(value, list):
        return sum(sum_numbers(item) for item in value)
    return 0


def count_bucket(stats, name):
    value = stats.get(name, {})
    if isinstance(value, dict) and "counts" in value:
        value = value["counts"]
    return sum_numbers(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-requests", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if shutil.which("sccache") is None:
        print("sccache is not in PATH", file=sys.stderr)
        return 1 if args.require_requests else 0

    if args.verbose:
        subprocess.run(["sccache", "--show-stats"], check=False)

    stats_json = subprocess.check_output(
        ["sccache", "--show-stats", "--stats-format=json"],
        text=True,
    )
    data = json.loads(stats_json)
    stats = data.get("stats", {})
    compile_requests = int(stats.get("compile_requests") or 0)
    cache_hits = count_bucket(stats, "cache_hits")
    cache_misses = count_bucket(stats, "cache_misses")

    print(f"sccache compile_requests={compile_requests}")
    print(f"sccache aggregate_cache_hits={cache_hits}")
    print(f"sccache aggregate_cache_misses={cache_misses}")

    if args.require_requests and compile_requests <= 0:
        print("sccache did not observe compiler requests", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
