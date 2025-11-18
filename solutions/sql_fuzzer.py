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
from solutions.interpreters.string_interpreter import StringInterpreter
from solutions.interpreters.string_interpreter import SQLQuery, EnhancedValue  # noqa: F401

PAYLOADS = [
    "",
    "hello",
    "world",
    "admin",
    "test@example.com",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT password FROM users--",
    "'; EXEC xp_cmdshell('whoami'); --",
    "abc'); DELETE FROM accounts; --",
]

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
        self.random = random.Random(42)

    def run(self) -> dict:
        inputs = list(self._generate_inputs())
        if not inputs:
            # Ensure we run at least once even if no String params.
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
        if not self.string_params:
            yield tuple(self._default_value(t) for t in self.param_types)
            return

        string_param_count = len(self.string_params)
        seen: set[tuple[Optional[str], ...]] = set()

        base_values: list[Optional[str]] = [
            "",
            "hello",
            "world",
            "test",
            "admin",
            "' OR '1'='1",
            None,
        ]

        for combo in itertools.product(base_values, repeat=string_param_count):
            if combo in seen:
                continue
            seen.add(combo)
            yield self._build_args(combo)

        attack_values: list[Optional[str]] = list(PAYLOADS)
        for _ in range(5):
            base = self.random.choice(PAYLOADS)
            fuzz = f"{base}{self.random.randint(0, 999)}'--"
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
                yield self._build_args(combo_tuple)

    def _build_args(self, combo: tuple[Optional[str], ...]) -> tuple[jvm.Value, ...]:
        args: list[jvm.Value] = []
        combo_iter = iter(combo)
        for idx, param in enumerate(self.param_types):
            if idx in self.string_params:
                args.append(self._string_value(next(combo_iter)))
            else:
                args.append(self._default_value(param))
        return tuple(args)

    def _string_value(self, value: Optional[str]) -> jvm.Value:
        return jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), value)

    def _default_value(self, t: jvm.Type) -> jvm.Value:
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
