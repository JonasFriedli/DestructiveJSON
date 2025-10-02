#!/usr/bin/env python3
"""
destructive_json.py

Generates various "destructive" or malicious JSON payloads for authorized
security testing. Use responsibly and only on systems you are permitted to test.

Usage examples:
  python3 destructive_json.py nested -d 500 -o deep.json
  python3 destructive_json.py manykeys -n 50000 -o many.json
  python3 destructive_json.py longkey -l 10000 -o long.json
  python3 destructive_json.py dunder -t all -o dunder.json
  python3 destructive_json.py malformed -m unclosed -o broken.json
  python3 destructive_json.py all --outdir payloads

"""

import argparse
import json
import sys
import os
import random
import string
from collections import OrderedDict

# ------- Helper generators -------

def gen_deep(depth: int):
    """Generate nested JSON: {'n': {'n': {...}}} depth levels deep."""
    d = {}
    for _ in range(depth):
        d = {"n": d}
    return d

def gen_many_keys(count: int, prefix: str = "k"):
    """Generate an object with `count` keys: prefix000001 -> integer."""
    # Avoid building huge strings in memory if count very large? We return dict anyway.
    return {f"{prefix}{i:08d}": i for i in range(count)}

def gen_long_key(length: int, value: str = "v"):
    """Generate a single-key object with a very long key."""
    key = "k" * length
    return {key: value}

def gen_huge_array(length: int, element=0):
    """Generate a huge array as top-level JSON."""
    return {"arr": [element] * length}

def gen_duplicate_keys(key: str, values):
    """Generate JSON with duplicate keys. JSON libraries in Python will keep last occurrence.
    To produce a text with duplicate keys, we must craft the string manually."""
    parts = []
    for v in values:
        parts.append(json.dumps({key: v})[1:-1])  # strip {}
    # join with commas to create {"k":v1,"k":v2,...}
    return "{" + ",".join(parts) + "}"

def gen_control_char_keys(keys):
    """Generate JSON where keys contain whitespace/control chars."""
    d = {}
    for k, v in keys.items():
        d[k] = v
    return d

def gen_dunder_injection(payload_map):
    """
    payload_map: dict of keys and values to include, may include __class__, __dict__, etc.
    Returns a dict; if it includes __dict__ and we want to demonstrate merging behavior,
    callers may craft their payload accordingly.
    """
    return payload_map

def gen_malformed(case: str):
    """Generate some malformed JSON strings."""
    if case == "unclosed":
        return '{"a": 1, "b": [1,2,3]'
    if case == "trailing-comma":
        return '{"a":1,}'
    if case == "bad-token":
        return '{"a": NaN }'  # NaN is not valid JSON (but Python's parser may allow)
    if case == "broken-utf8":
        # produce bytes that are invalid UTF-8, return as bytes
        return b'{"a": "\xff\xff"}'
    return '{"malformed":'  # default

def gen_nan_inf():
    # Produce JSON with NaN and Infinity tokens (non-standard)
    # Represent as raw text - JSON encoder will convert to NaN but some parsers accept it.
    return '{"x": NaN, "y": Infinity, "z": -Infinity}'

def gen_mixed_dunder_and_many(count_keys: int, long_key_len: int):
    obj = gen_many_keys(count_keys, prefix="k")
    # Inject __dict__ to show mass-attribute behavior: choose a small map to keep file size reasonable
    obj["__dict__"] = {"injected": "pwn", "num": 123}
    # Also add an extremely long key
    obj["k_long"] = "k" * long_key_len
    return obj

# ------- File writing helpers -------

def write_text(path: str, content: str, binary=False):
    if binary:
        with open(path, "wb") as f:
            if isinstance(content, str):
                f.write(content.encode("utf-8", errors="replace"))
            else:
                f.write(content)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

def safe_json_dumps(obj, pretty=False):
    # Use ensure_ascii=False to keep unicode, but content may be large.
    if pretty:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

# ------- CLI entrypoint -------

def main():
    ap = argparse.ArgumentParser(prog="destructive_json.py",
                                 description="Generate destructive/malicious JSON payloads (authorized use only).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # nested
    ns = sub.add_parser("nested", help="Generate deeply nested JSON")
    ns.add_argument("-d", "--depth", type=int, default=500, help="Nesting depth")
    ns.add_argument("-o", "--output", default="nested.json", help="Output file (or - for stdout)")

    # many keys
    mk = sub.add_parser("manykeys", help="Generate JSON with many keys")
    mk.add_argument("-n", "--count", type=int, default=50000, help="Number of keys")
    mk.add_argument("-o", "--output", default="many.json", help="Output file (or - for stdout)")

    # long key
    lk = sub.add_parser("longkey", help="Generate JSON with an extremely long key")
    lk.add_argument("-l", "--length", type=int, default=5000, help="Key length")
    lk.add_argument("-o", "--output", default="longkey.json", help="Output file (or - for stdout)")

    # huge array
    ha = sub.add_parser("hugearray", help="Generate huge array JSON")
    ha.add_argument("-n", "--length", type=int, default=1000000, help="Array length (elements)")
    ha.add_argument("-o", "--output", default="hugearray.json", help="Output file (or - for stdout)")

    # duplicate keys (produces raw text)
    dk = sub.add_parser("duplicate", help="Generate JSON text with duplicate keys (raw output)")
    dk.add_argument("-k", "--key", default="dup", help="Duplicate key name")
    dk.add_argument("-v", "--values", type=int, default=5, help="Number of duplicate occurrences")
    dk.add_argument("-o", "--output", default="duplicate.json", help="Output file (or - for stdout)")

    # dunder injection
    dd = sub.add_parser("dunder", help="Generate payloads with magic keys like __dict__, __class__")
    dd.add_argument("-t", "--type", choices=["simple", "full", "all"], default="simple",
                    help="Type of dunder payload: simple (~few fields), full (include __dict__), all (mix)")
    dd.add_argument("-o", "--output", default="dunder.json", help="Output file (or - for stdout)")

    # malformed
    md = sub.add_parser("malformed", help="Generate malformed JSON strings")
    md.add_argument("-m", "--mode", choices=["unclosed", "trailing-comma", "bad-token", "broken-utf8"], default="unclosed")
    md.add_argument("-o", "--output", default="malformed.json", help="Output file (or - for stdout)")

    # NaN/Infinity
    ni = sub.add_parser("naninf", help="Generate JSON containing NaN/Infinity tokens (text)")
    ni.add_argument("-o", "--output", default="naninf.json", help="Output file (or - for stdout)")

    # mixed: many + dunder + long key
    mx = sub.add_parser("mixed", help="Generate a mixed malicious payload")
    mx.add_argument("-n", "--count", type=int, default=50000, help="Number of normal keys")
    mx.add_argument("-l", "--long", type=int, default=2000, help="Length of extra long key")
    mx.add_argument("-o", "--output", default="mixed.json", help="Output file (or - for stdout)")

    # all: produce multiple files into output dir
    al = sub.add_parser("all", help="Generate a set of payloads into a directory")
    al.add_argument("-d", "--outdir", default="payloads", help="Output directory")
    al.add_argument("--depth", type=int, default=200, help="Nested depth default")
    al.add_argument("--many", type=int, default=20000, help="Many keys default")
    al.add_argument("--long", type=int, default=2000, help="Long key default")

    args = ap.parse_args()

    if args.cmd == "nested":
        obj = gen_deep(args.depth)
        text = safe_json_dumps(obj)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "manykeys":
        obj = gen_many_keys(args.count)
        text = safe_json_dumps(obj)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "longkey":
        obj = gen_long_key(args.length)
        text = safe_json_dumps(obj)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "hugearray":
        obj = gen_huge_array(args.length)
        text = safe_json_dumps(obj)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "duplicate":
        values = []
        for i in range(args.values):
            # produce different v values
            values.append(f"{args.key}_{i}")
        text = gen_duplicate_keys(args.key, values)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote (raw) duplicate JSON to", args.output)

    elif args.cmd == "dunder":
        if args.type == "simple":
            payload = {"__class__": "pwn", "normal": "ok"}
        elif args.type == "full":
            payload = {"__dict__": {"injected": "pwn", "x": 1}, "normal": "ok"}
        else:  # all
            payload = {"__class__": "p", "__dict__": {"a": 1}, "__init__": "s", "normal": "ok"}
        text = safe_json_dumps(payload)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "malformed":
        val = gen_malformed(args.mode)
        if args.output == "-":
            if isinstance(val, bytes):
                sys.stdout.buffer.write(val)
            else:
                sys.stdout.write(val)
        else:
            if isinstance(val, bytes):
                write_text(args.output, val, binary=True)
            else:
                write_text(args.output, val)
            print("Wrote malformed JSON to", args.output)

    elif args.cmd == "naninf":
        text = gen_nan_inf()
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "mixed":
        obj = gen_mixed_dunder_and_many(args.count, args.long)
        text = safe_json_dumps(obj)
        if args.output == "-":
            sys.stdout.write(text)
        else:
            write_text(args.output, text)
            print("Wrote", args.output)

    elif args.cmd == "all":
        outdir = args.outdir
        os.makedirs(outdir, exist_ok=True)
        # nested
        nested = safe_json_dumps(gen_deep(args.depth))
        write_text(os.path.join(outdir, "nested.json"), nested)
        print("Wrote nested.json")
        many = safe_json_dumps(gen_many_keys(args.many))
        write_text(os.path.join(outdir, "many.json"), many)
        print("Wrote many.json")
        longk = safe_json_dumps(gen_long_key(args.long))
        write_text(os.path.join(outdir, "longkey.json"), longk)
        print("Wrote longkey.json")
        dunder = safe_json_dumps({"__dict__": {"pwn": 1}, "ok": "x"})
        write_text(os.path.join(outdir, "dunder.json"), dunder)
        print("Wrote dunder.json")
        malformed = gen_malformed("unclosed")
        write_text(os.path.join(outdir, "malformed_unclosed.json"), malformed)
        print("Wrote malformed_unclosed.json")
        naninf = gen_nan_inf()
        write_text(os.path.join(outdir, "naninf.json"), naninf)
        print("Wrote naninf.json")
        print("All files written to", outdir)

    else:
        ap.print_help()

if __name__ == "__main__":
    main()
