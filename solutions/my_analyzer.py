#!/usr/bin/env python3
"""
Dynamic SQL injection analyzer built on top of the string-aware interpreter.

Strategy:
    * Fuzz every String parameter with a curated list of SQL payloads
    * Execute the target method through StringInterpreter to track taint
    * Inspect interpreter state (taint, SQLQuery metadata, vulnerability flags)
    * Aggregate outcomes and emit JPAMB predictions
"""

from __future__ import annotations

import sys
import random
from pathlib import Path
import itertools
from typing import Iterator, Optional
from collections import Counter

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from jpamb import jvm
from jpamb.model import Suite
from solutions.interpreter import StringInterpreter
from solutions.interpreter import SQLQuery, EnhancedValue  # noqa: F401

CORE_PAYLOADS = {
    "benign": [
        "",
        "hello",
        "admin",
        "test@example.com",
    ],

    "boolean_based": [
        " OR 1=1",
        " OR 'x'='x",
        " AND 1=1",
        " AND 1=2",
    ],

    "union_based": [
        " UNION SELECT NULL",
        " UNION SELECT NULL,NULL",
        " UNION SELECT NULL, NULL, NULL",
        " UNION SELECT password FROM users",
    ],

    "stacked_queries": [
        "; DROP TABLE users",
        "; INSERT INTO logs VALUES('hacked')",
        "; UPDATE users SET role='admin'",
    ],

    "time_based": [
        " OR SLEEP(5)",
        "; WAITFOR DELAY '00:00:05'",
    ],

    "command_injection": [
        "; EXEC xp_cmdshell('whoami');",
    ],
}

SUFFIXES = [
    "--",
    "#",
    "/*",
]

CONTEXT_PREFIXES = {
    "quoted_single": [
        "'",
        "' ",
        "admin'",
    ],

    "quoted_double": [
        "\"",
        "\" ",
        "admin\"",
    ],

    "numeric": [
        "-1",
        "0",
        "1",
        "999",
    ],

    "none": [
        "",
    ],
}

QUERY_KEYWORDS = (
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "union",
    "where",
    "from",
    "into",
    "order by",
)

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
    print("SQL Fuzzer Analyzer")
    print("1.0")
    print("JPAMB Team")
    print("dynamic,fuzzing,taint")
    print("no")


class SQLFuzzer:
    def __init__(self, suite: Suite, method: jvm.Absolute[jvm.MethodID]):
        self.suite = suite
        self.method = method
        self.interpreter = StringInterpreter(suite, verbose=False, detect_sql=True)
        self.param_types = [
            self.method.extension.params[i]
            for i in range(len(self.method.extension.params))
        ]
        self.string_params = [
            idx
            for idx, t in enumerate(self.param_types)
            if isinstance(t, jvm.Object) and "String" in str(t.name)
        ]
        self.object_params = [
            idx
            for idx, t in enumerate(self.param_types)
            if isinstance(t, jvm.Object) and "String" not in str(t.name)
        ]
        self.random = random.Random(42)

    def run(self) -> dict:
        inputs = list(self._generate_inputs())
        if not inputs:
            inputs.append(tuple(self._default_value(t) for t in self.param_types))

        results = []
        vulnerable_runs = 0
        counts = Counter()

        for args in inputs:
            result, state = self.interpreter.execute(self.method, list(args))
            normalized = self._normalize_result(result)
            counts[normalized] += 1

            vulns = self._extract_vulnerabilities(result, state)
            if vulns:
                vulnerable_runs += 1
                counts["vulnerable"] += 1

            results.append(
                {
                    "args": args,
                    "result": normalized,
                    "vulnerabilities": vulns,
                    "queries": [str(q.query_string) for q in state.sql_queries],
                }
            )

        total = len(inputs)
        predictions = {}
        for query in QUERIES:
            if query == "vulnerable":
                pct = 100 * vulnerable_runs / total if total else 0
            else:
                pct = 100 * counts.get(query, 0) / total if total else 0
            predictions[query] = pct

        return {
            "runs": results,
            "predictions": predictions,
            "total_runs": total,
            "vulnerable": vulnerable_runs,
        }

    def _generate_inputs(self) -> Iterator[tuple[jvm.Value, ...]]:
        string_combos = list(self._string_payload_combos())
        int_combos = list(self._int_payload_combos())
        object_combos = list(self._object_payload_combos())

        if not string_combos:
            string_combos = [()]
        if not int_combos:
            int_combos = [()]
        if not object_combos:
            object_combos = [()]

        seen: set[tuple] = set()
        for str_combo in string_combos:
            for int_combo in int_combos:
                for obj_combo in object_combos:
                    args = self._build_args(str_combo, int_combo, obj_combo)
                    key = tuple(arg.value for arg in args)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield args

    def _string_payload_combos(self) -> Iterator[tuple[Optional[str], ...]]:  # noqa: C901
        if not self.string_params:
            return

        string_param_count = len(self.string_params)
        seen: set[tuple[Optional[str], ...]] = set()

        base_values: list[Optional[str]] = CORE_PAYLOADS["benign"] + [None]

        for combo in itertools.product(base_values, repeat=string_param_count):
            combo_tuple = tuple(combo)
            if combo_tuple in seen:
                continue
            seen.add(combo_tuple)
            yield combo_tuple

        attack_values: list[Optional[str]] = []
        for category_payloads in CORE_PAYLOADS.values():
            attack_values.extend(category_payloads)

        for _ in range(10):
            category = self.random.choice(list(CORE_PAYLOADS.keys()))
            if category == "benign":
                continue
            base = self.random.choice(CORE_PAYLOADS[category])
            prefix_category = self.random.choice(list(CONTEXT_PREFIXES.keys()))
            prefix = self.random.choice(CONTEXT_PREFIXES[prefix_category])
            suffix = self.random.choice(SUFFIXES)
            fuzz = f"{prefix}{base}{suffix}"
            attack_values.append(fuzz)

        attack_values.append(None)

        default_combo = [""] * string_param_count
        for param_index in range(string_param_count):
            for payload in attack_values:
                combo = list(default_combo)
                combo[param_index] = payload
                combo_tuple = tuple(combo)
                if combo_tuple in seen:
                    continue
                seen.add(combo_tuple)
                yield combo_tuple

    def _int_payload_combos(self) -> Iterator[tuple[int, ...]]:
        int_params = [
            idx
            for idx, t in enumerate(self.param_types)
            if isinstance(t, jvm.Int)
        ]
        if not int_params:
            return

        candidates = [0, 1, -1, 5, 10, 100, -100]
        yield from itertools.product(candidates, repeat=len(int_params))

    def _object_payload_combos(self) -> Iterator[tuple[Optional[int], ...]]:
        if not self.object_params:
            return

        candidates = [None, 123, 456, 0, -1]
        yield from itertools.product(candidates, repeat=len(self.object_params))

    def _build_args(
        self,
        string_combo: tuple[Optional[str], ...],
        int_combo: tuple[int, ...],
        object_combo: tuple[Optional[int], ...],
    ) -> tuple[jvm.Value, ...]:
        args: list[jvm.Value] = []
        string_iter = iter(string_combo)
        int_iter = iter(int_combo)
        object_iter = iter(object_combo)
        for idx, param in enumerate(self.param_types):
            if idx in self.string_params:
                args.append(self._string_value(next(string_iter)))
            elif isinstance(param, jvm.Int):
                try:
                    value = next(int_iter)
                except StopIteration:
                    value = 0
                args.append(jvm.Value.int(value))
            elif idx in self.object_params:
                try:
                    obj_value = next(object_iter)
                except StopIteration:
                    obj_value = None
                args.append(jvm.Value(param, obj_value))
            else:
                args.append(self._default_value(param))
        return tuple(args)

    def _string_value(self, value: Optional[str]) -> jvm.Value:
        return jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), value)

    def _default_value(self, t: jvm.Type, allow_null: bool = True) -> jvm.Value:
        match t:
            case jvm.Int():
                return jvm.Value.int(0)
            case jvm.Boolean():
                return jvm.Value.boolean(False)
            case jvm.Byte() | jvm.Short() | jvm.Char():
                return jvm.Value(t, 0)
            case jvm.Long():
                return jvm.Value(jvm.Long(), 0)
            case jvm.Float():
                return jvm.Value(jvm.Float(), 0.0)
            case jvm.Double():
                return jvm.Value(jvm.Double(), 0.0)
            case jvm.Object(obj_type):
                if "String" in str(obj_type.name):
                    return self._string_value("")
                if not allow_null:
                    return jvm.Value(t, 123)
                return jvm.Value(t, None)
            case _:
                return jvm.Value(t, None)

    def _normalize_result(self, result: str) -> str:
        mapping = {
            "sql injection vulnerability": "vulnerable",
            "error: divide by zero": "divide by zero",
            "error: null pointer": "null pointer",
        }
        for key, value in mapping.items():
            if result == key:
                return value
        return result

    def _extract_vulnerabilities(self, result: str, state) -> list[str]:
        findings = []
        if result in {"vulnerable", "sql injection vulnerability"}:
            findings.append("Interpreter flagged vulnerability")

        for query in state.sql_queries:
            if query.is_vulnerable() or self._looks_like_attack(query):
                findings.append(f"tainted query: {query.query_string}")

        findings.extend(state.vulnerabilities)
        return findings

    def _looks_like_attack(self, query: SQLQuery) -> bool:
        abstract = query.query_string
        if not abstract:
            return False
        value = abstract.value or ""
        lowered = value.lower()
        if abstract.tainted and any(keyword in lowered for keyword in QUERY_KEYWORDS):
            suspicious_tokens = ("' OR '", "\" OR \"", ";", "--")
            if any(token in value for token in suspicious_tokens):
                return True
        return False


def analyze(method_str: str) -> None:
    suite = Suite(Path(".").absolute())
    method = jvm.Absolute.decode(method_str, jvm.MethodID.decode)
    fuzzer = SQLFuzzer(suite, method)
    report = fuzzer.run()

    preds = report["predictions"]
    for query in QUERIES:
        pct = preds.get(query, 0)
        print(f"{query};{pct:.0f}%")


def main(argv: list[str]) -> None:
    if len(argv) == 2 and argv[1] == "info":
        info()
        return
    if len(argv) != 2:
        print("Usage: sql_fuzzer.py <method>", file=sys.stderr)
        sys.exit(1)
    analyze(argv[1])


if __name__ == "__main__":
    main(sys.argv)
