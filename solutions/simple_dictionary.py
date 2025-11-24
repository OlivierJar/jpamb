#!/usr/bin/env python3
"""
Simple dictionary-based SQL injection fuzzer.
Uses ONLY fixed payload list from PayloadBox - no combinations.
"""

from __future__ import annotations

import sys
from pathlib import Path
from collections import Counter

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from jpamb import jvm
from jpamb.model import Suite
from solutions.interpreter import StringInterpreter

# https://github.com/payloadbox/sql-injection-payload-list
SIMPLE_DICTIONARY = [
    # Benign (4)
    "", "test", "admin", "user",

    # Boolean-based (5)
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' OR '1'='1",
    "' OR 'x'='x",
    "') OR ('1'='1",

    # UNION-based (3)
    "' UNION SELECT NULL--",
    "' UNION SELECT password FROM users--",
    "1' UNION SELECT NULL,NULL--",

    # Stacked queries (3)
    "'; DROP TABLE users--",
    "1; DROP TABLE users--",
    "'; INSERT INTO logs VALUES('hacked')--",

    # Comment-based (4)
    "admin'--",
    "admin'#",
    "1' OR '1'='1'--",
    "1' OR '1'='1'#",

    # Time-based (2)
    "' OR SLEEP(5)--",
    "1' AND SLEEP(5)--",

    # Numeric (1)
    "1 OR 1=1",
]

QUERIES = [
    "ok",
    "divide by zero",
    "assertion error",
    "out of bounds",
    "null pointer",
    "vulnerable",
    "*",
]


def info() -> None:
    """Print analyzer metadata for JPAMB."""
    print("Simple Dictionary Fuzzer")
    print("1.0")
    print("DTU Group 13")
    print("dynamic,dictionary,sql-injection")
    print("no")


def analyze_method(method_str: str) -> dict[str, float]:

    suite = Suite(Path(".").absolute())
    method = jvm.Absolute.decode(method_str, jvm.MethodID.decode)

    param_types = [
        method.extension.params[i]
        for i in range(len(method.extension.params))
    ]

    string_param_indices = [
        idx
        for idx, t in enumerate(param_types)
        if isinstance(t, jvm.Object) and "String" in str(t.name)
    ]

    if not string_param_indices:
        return {
            "ok": 100.0,
            "divide by zero": 0.0,
            "assertion error": 0.0,
            "out of bounds": 0.0,
            "null pointer": 0.0,
            "vulnerable": 0.0,
            "*": 0.0,
        }

    counts = Counter()
    vulnerable_count = 0
    total = 0

    for payload in SIMPLE_DICTIONARY:
        # Build arguments - inject payload into string parameters
        args = []
        for idx, param in enumerate(param_types):
            if idx in string_param_indices:
                args.append(jvm.Value(
                    jvm.Object(jvm.ClassName.decode("java/lang/String")),
                    payload
                ))
            elif isinstance(param, jvm.Int):
                args.append(jvm.Value.int(0))
            elif isinstance(param, jvm.Boolean):
                args.append(jvm.Value.boolean(False))
            else:
                args.append(jvm.Value(param, None))

        try:
            interpreter = StringInterpreter(suite, verbose=False, detect_sql=True)
            result, state = interpreter.execute(method, args)

            if result == "sql injection vulnerability":
                vulnerable_count += 1
                counts["vulnerable"] += 1
            elif result == "error: divide by zero":
                counts["divide by zero"] += 1
            elif result == "error: null pointer":
                counts["null pointer"] += 1
            elif result == "error: assertion":
                counts["assertion error"] += 1
            elif result == "error: out of bounds":
                counts["out of bounds"] += 1
            elif result == "timeout":
                counts["*"] += 1
            else:
                if state.vulnerabilities:
                    vulnerable_count += 1
                    counts["vulnerable"] += 1
                elif any(q.is_vulnerable() for q in state.sql_queries):
                    vulnerable_count += 1
                    counts["vulnerable"] += 1
                else:
                    counts["ok"] += 1

            total += 1

        except Exception as e:
            counts["ok"] += 1
            total += 1

    predictions = {}
    for query in QUERIES:
        if query == "vulnerable":
            pct = 100.0 * vulnerable_count / total if total > 0 else 0.0
        else:
            pct = 100.0 * counts.get(query, 0) / total if total > 0 else 0.0
        predictions[query] = pct

    return predictions


def main(argv: list[str]) -> None:
    """Main entry point for JPAMB integration."""
    if len(argv) == 2 and argv[1] == "info":
        info()
        return

    if len(argv) != 2:
        print("Usage: simple_dictionary.py <method>", file=sys.stderr)
        sys.exit(1)

    method_str = argv[1]
    predictions = analyze_method(method_str)

    for query in QUERIES:
        pct = predictions.get(query, 0.0)
        print(f"{query};{pct:.0f}%")


if __name__ == "__main__":
    main(sys.argv)
