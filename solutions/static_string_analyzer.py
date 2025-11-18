#!/usr/bin/env python3
"""
Static String Analysis for SQL Injection Detection

This analyzer performs static analysis on Java bytecode to detect potential
SQL injection vulnerabilities by analyzing string operations and data flow
without executing the code.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import jpamb
from jpamb.jvm import base as jvm
from jpamb.jvm.opcode import Opcode


class AbstractValue(Enum):
    """Abstract values for string analysis"""
    CONSTANT = "constant"           # Known constant string
    PARAMETER = "parameter"         # Method parameter (potentially tainted)
    TAINTED = "tainted"            # Definitely tainted (user input)
    CONCATENATED = "concatenated"   # Result of concatenation
    UNKNOWN = "unknown"            # Unknown value
    TOP = "top"                    # Could be anything


@dataclass
class StringAbstraction:
    """Abstract representation of a string value"""
    value_type: AbstractValue
    tainted: bool = False
    may_contain_sql: bool = False
    constant_value: Optional[str] = None
    sources: Set[str] = field(default_factory=set)
    operations: List[str] = field(default_factory=list)
    
    def __repr__(self):
        if self.constant_value:
            return f"String({self.value_type.value}, '{self.constant_value}', tainted={self.tainted})"
        return f"String({self.value_type.value}, tainted={self.tainted})"
    
    def is_safe(self) -> bool:
        """Check if this string is safe to use in SQL queries"""
        return not self.tainted and self.value_type == AbstractValue.CONSTANT


@dataclass
class AbstractState:
    """Abstract state for static analysis"""
    locals: Dict[int, StringAbstraction] = field(default_factory=dict)
    stack: List[StringAbstraction] = field(default_factory=list)
    
    def copy(self):
        """Create a deep copy of this state"""
        return AbstractState(
            locals=self.locals.copy(),
            stack=self.stack.copy()
        )
    
    def merge(self, other: 'AbstractState') -> 'AbstractState':
        """Merge two abstract states (for join points in CFG)"""
        merged = AbstractState()
        
        # Merge locals
        all_keys = set(self.locals.keys()) | set(other.locals.keys())
        for key in all_keys:
            if key in self.locals and key in other.locals:
                merged.locals[key] = self._merge_abstractions(
                    self.locals[key], other.locals[key]
                )
            elif key in self.locals:
                merged.locals[key] = self.locals[key]
            else:
                merged.locals[key] = other.locals[key]
        
        return merged
    
    def _merge_abstractions(self, a1: StringAbstraction, a2: StringAbstraction) -> StringAbstraction:
        """Merge two string abstractions conservatively"""
        # Conservative: if either is tainted, result is tainted
        tainted = a1.tainted or a2.tainted
        
        # If both are same constant, keep it
        if (a1.value_type == AbstractValue.CONSTANT and 
            a2.value_type == AbstractValue.CONSTANT and
            a1.constant_value == a2.constant_value):
            return StringAbstraction(
                value_type=AbstractValue.CONSTANT,
                tainted=False,
                constant_value=a1.constant_value
            )
        
        # Otherwise, merge to TOP or TAINTED
        return StringAbstraction(
            value_type=AbstractValue.TAINTED if tainted else AbstractValue.TOP,
            tainted=tainted,
            sources=a1.sources | a2.sources
        )


class StaticStringAnalyzer:
    """Static analyzer for detecting SQL injection vulnerabilities"""
    
    def __init__(self, method_data: dict):
        self.method_data = method_data
        self.method_name = method_data.get("name", "unknown")
        self.bytecode = method_data.get("code", {}).get("bytecode", [])
        self.vulnerabilities: List[Dict] = []
        self.warnings: List[Dict] = []
        
        # SQL-related method patterns
        self.sql_execute_methods = {
            "executeQuery", "executeUpdate", "execute",
            "prepareStatement", "createStatement"
        }
        
        # String operation methods
        self.string_concat_methods = {"concat", "append", "makeConcatWithConstants"}
        self.string_methods = {"substring", "toLowerCase", "toUpperCase", "trim"}
    
    def analyze(self) -> Dict:
        """Perform static analysis on the method"""
        print(f"\n{'='*70}")
        print(f"Static Analysis: {self.method_name}")
        print(f"{'='*70}\n")
        
        # Initialize state with parameters as potentially tainted
        initial_state = self._create_initial_state()
        
        # Analyze bytecode
        state = self._analyze_bytecode(initial_state)
        
        # Generate report
        report = {
            "method": self.method_name,
            "vulnerabilities": self.vulnerabilities,
            "warnings": self.warnings,
            "safe": len(self.vulnerabilities) == 0
        }
        
        self._print_report(report)
        return report
    
    def _create_initial_state(self) -> AbstractState:
        """Create initial abstract state with parameters marked as tainted"""
        state = AbstractState()
        
        # Get method parameters
        params = self.method_data.get("params", [])
        
        # Mark all String parameters as potentially tainted
        for i, param in enumerate(params):
            param_type = param.get("type", {})
            if self._is_string_type(param_type):
                state.locals[i] = StringAbstraction(
                    value_type=AbstractValue.PARAMETER,
                    tainted=True,
                    sources={f"parameter_{i}"}
                )
                print(f"  Parameter {i} marked as tainted (user input)")
        
        return state
    
    def _is_string_type(self, type_info: dict) -> bool:
        """Check if type is String"""
        if isinstance(type_info, dict):
            # Handle the JSON representation
            name = type_info.get("name", "")
            kind = type_info.get("kind", "")
            
            if kind == "class" and name == "java/lang/String":
                return True
            
            # Also check dotted notation
            if name == "java.lang.String":
                return True
        
        return False
    
    def _analyze_bytecode(self, initial_state: AbstractState) -> AbstractState:
        """Analyze bytecode instructions"""
        state = initial_state
        
        for i, instruction in enumerate(self.bytecode):
            opr = instruction.get("opr", "")
            offset = instruction.get("offset", i)
            
            print(f"  [{offset:3d}] {opr:15s}", end=" ")
            
            try:
                state = self._analyze_instruction(instruction, state)
                print(f"✓")
            except Exception as e:
                print(f"⚠ {e}")
        
        return state
    
    def _analyze_instruction(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Analyze a single bytecode instruction"""
        opr = instruction.get("opr", "")
        
        if opr == "push":
            return self._handle_push(instruction, state)
        elif opr == "load":
            return self._handle_load(instruction, state)
        elif opr == "store":
            return self._handle_store(instruction, state)
        elif opr == "invoke":
            return self._handle_invoke(instruction, state)
        elif opr == "return":
            return self._handle_return(instruction, state)
        elif opr in ["if", "ifz", "goto"]:
            # Control flow - for now, we continue linearly
            return state
        else:
            # Unknown operation - conservative
            return state
    
    def _handle_push(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Handle push instruction (load constant)"""
        value = instruction.get("value", {})
        
        if value.get("type") == "string":
            string_value = value.get("value", "")
            abstraction = StringAbstraction(
                value_type=AbstractValue.CONSTANT,
                tainted=False,
                constant_value=string_value,
                may_contain_sql=self._looks_like_sql(string_value)
            )
            state.stack.append(abstraction)
            print(f"(const: '{string_value[:30]}...')", end=" ")
        else:
            # Non-string constant
            state.stack.append(StringAbstraction(
                value_type=AbstractValue.UNKNOWN,
                tainted=False
            ))
        
        return state
    
    def _handle_load(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Handle load instruction (load from local variable)"""
        index = instruction.get("index", 0)
        
        if index in state.locals:
            abstraction = state.locals[index]
            state.stack.append(abstraction)
            print(f"(local[{index}]: {abstraction.value_type.value})", end=" ")
        else:
            # Unknown local variable
            state.stack.append(StringAbstraction(
                value_type=AbstractValue.UNKNOWN,
                tainted=True  # Conservative: unknown is tainted
            ))
        
        return state
    
    def _handle_store(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Handle store instruction (store to local variable)"""
        index = instruction.get("index", 0)
        
        if state.stack:
            value = state.stack.pop()
            state.locals[index] = value
            print(f"(local[{index}] = {value.value_type.value})", end=" ")
        
        return state
    
    def _handle_invoke(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Handle method invocation"""
        method = instruction.get("method", {})
        method_name = method.get("name", "")
        
        if method_name in self.string_concat_methods:
            return self._handle_string_concat(instruction, state, method_name)
        elif method_name in self.sql_execute_methods:
            return self._handle_sql_execute(instruction, state, method_name)
        elif method_name in self.string_methods:
            return self._handle_string_operation(instruction, state, method_name)
        else:
            # Unknown method - conservative
            return self._handle_unknown_method(instruction, state, method_name)
    
    def _handle_string_concat(self, instruction: dict, state: AbstractState, 
                             method_name: str) -> AbstractState:
        """Handle string concatenation operations"""
        method = instruction.get("method", {})
        args = method.get("args", [])
        num_args = len(args)
        
        if len(state.stack) < num_args:
            return state
        
        # Pop arguments
        operands = [state.stack.pop() for _ in range(num_args)]
        operands.reverse()
        
        # Check if any operand is tainted
        is_tainted = any(op.tainted for op in operands)
        
        # Build concatenated value if all are constants
        constant_value = None
        if all(op.value_type == AbstractValue.CONSTANT for op in operands):
            constant_value = "".join(
                op.constant_value or "" for op in operands
            )
        
        # Create result
        result = StringAbstraction(
            value_type=AbstractValue.CONCATENATED if not constant_value else AbstractValue.CONSTANT,
            tainted=is_tainted,
            constant_value=constant_value,
            may_contain_sql=any(op.may_contain_sql for op in operands),
            sources=set().union(*[op.sources for op in operands]),
            operations=[f"concat({num_args} args)"]
        )
        
        state.stack.append(result)
        
        if is_tainted:
            print(f"(⚠ TAINTED CONCAT)", end=" ")
        else:
            print(f"(concat: safe)", end=" ")
        
        return state
    
    def _handle_sql_execute(self, instruction: dict, state: AbstractState,
                           method_name: str) -> AbstractState:
        """Handle SQL execution methods - check for vulnerabilities"""
        method = instruction.get("method", {})
        args = method.get("args", [])
        
        # Check if query string is on stack
        if state.stack:
            query_string = state.stack[-1] if state.stack else None
            
            if query_string and query_string.tainted:
                # VULNERABILITY DETECTED!
                vulnerability = {
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "method": method_name,
                    "description": f"Tainted string used in {method_name}",
                    "query_type": query_string.value_type.value,
                    "sources": list(query_string.sources),
                    "recommendation": "Use PreparedStatement with parameterized queries"
                }
                self.vulnerabilities.append(vulnerability)
                print(f"(🚨 SQL INJECTION VULNERABILITY)", end=" ")
            elif query_string and query_string.value_type != AbstractValue.CONSTANT:
                # Warning for non-constant queries
                warning = {
                    "type": "DYNAMIC_SQL",
                    "severity": "MEDIUM",
                    "method": method_name,
                    "description": f"Dynamic SQL query in {method_name}",
                    "recommendation": "Consider using parameterized queries"
                }
                self.warnings.append(warning)
                print(f"(⚠ Dynamic SQL)", end=" ")
            else:
                print(f"(✓ Safe SQL)", end=" ")
        
        return state
    
    def _handle_string_operation(self, instruction: dict, state: AbstractState,
                                 method_name: str) -> AbstractState:
        """Handle string operations like substring"""
        if state.stack:
            # String operations preserve taint
            operand = state.stack.pop()
            result = StringAbstraction(
                value_type=AbstractValue.CONCATENATED,
                tainted=operand.tainted,
                sources=operand.sources,
                operations=operand.operations + [method_name]
            )
            state.stack.append(result)
            
            if operand.tainted:
                print(f"({method_name}: tainted)", end=" ")
        
        return state
    
    def _handle_unknown_method(self, instruction: dict, state: AbstractState,
                              method_name: str) -> AbstractState:
        """Handle unknown method calls conservatively"""
        # Pop potential arguments and push unknown result
        method = instruction.get("method", {})
        args = method.get("args", [])
        
        for _ in range(min(len(args), len(state.stack))):
            state.stack.pop()
        
        # Push unknown result (conservative: tainted)
        state.stack.append(StringAbstraction(
            value_type=AbstractValue.UNKNOWN,
            tainted=True
        ))
        
        return state
    
    def _handle_return(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Handle return instruction"""
        if instruction.get("type") == "ref" and state.stack:
            return_value = state.stack[-1]
            print(f"(returns: {return_value.value_type.value}, tainted={return_value.tainted})", end=" ")
            
            # Check if returning a tainted SQL-like string
            if return_value.tainted and return_value.may_contain_sql:
                vulnerability = {
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "method": f"{self.method_name} (return value)",
                    "description": f"Method returns tainted SQL query string",
                    "query_type": return_value.value_type.value,
                    "sources": list(return_value.sources),
                    "recommendation": "Do not construct SQL queries by concatenating user input. Use PreparedStatement with parameterized queries."
                }
                self.vulnerabilities.append(vulnerability)
                print(f"(🚨 RETURNS VULNERABLE SQL)", end=" ")
        
        return state
    
    def _looks_like_sql(self, string: str) -> bool:
        """Check if a string looks like SQL"""
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
        upper_str = string.upper()
        return any(keyword in upper_str for keyword in sql_keywords)
    
    def _print_report(self, report: Dict):
        """Print analysis report"""
        print(f"\n{'='*70}")
        print(f"Analysis Report: {report['method']}")
        print(f"{'='*70}\n")
        
        if report['vulnerabilities']:
            print(f"🚨 VULNERABILITIES FOUND: {len(report['vulnerabilities'])}\n")
            for vuln in report['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Description: {vuln['description']}")
                if vuln.get('sources'):
                    print(f"    Taint sources: {', '.join(vuln['sources'])}")
                print(f"    💡 {vuln['recommendation']}\n")
        
        if report['warnings']:
            print(f"⚠️  WARNINGS: {len(report['warnings'])}\n")
            for warn in report['warnings']:
                print(f"  [{warn['severity']}] {warn['type']}")
                print(f"    Description: {warn['description']}")
                print(f"    💡 {warn['recommendation']}\n")
        
        if not report['vulnerabilities'] and not report['warnings']:
            print("✅ No security issues detected\n")
        
        print(f"{'='*70}\n")


def analyze_method(method_id: str) -> Dict:
    """Analyze a specific method for SQL injection vulnerabilities"""
    # Parse the method ID
    try:
        abs_method_id = jvm.AbsMethodID.decode(method_id)
        print(f"Analyzing: {abs_method_id}")
    except Exception as e:
        print(f"Error parsing method ID: {e}")
        return {}
    
    # Load the decompiled JSON
    class_name = abs_method_id.ref.dotted()
    json_path = Path("target/decompiled") / class_name.replace(".", "/") + ".json"
    
    if not json_path.exists():
        print(f"Error: JSON file not found: {json_path}")
        return {}
    
    with open(json_path) as f:
        class_data = json.load(f)
    
    # Find the method
    method_name = abs_method_id.name
    method_data = None
    
    for method in class_data.get("methods", []):
        if method.get("name") == method_name:
            # TODO: Also match method signature
            method_data = method
            break
    
    if not method_data:
        print(f"Error: Method {method_name} not found in {class_name}")
        return {}
    
    # Analyze
    analyzer = StaticStringAnalyzer(method_data)
    return analyzer.analyze()


def analyze_all_string_sql_methods():
    """Analyze all methods in StringSQL class"""
    print("\n" + "="*70)
    print("Static Analysis: StringSQL Class")
    print("="*70 + "\n")
    
    json_path = Path("target/decompiled/jpamb/cases/StringSQL.json")
    
    if not json_path.exists():
        print(f"Error: {json_path} not found")
        return
    
    with open(json_path) as f:
        class_data = json.load(f)
    
    results = []
    
    for method in class_data.get("methods", []):
        method_name = method.get("name", "")
        
        # Skip constructors and special methods
        if method_name.startswith("<"):
            continue
        
        analyzer = StaticStringAnalyzer(method)
        result = analyzer.analyze()
        results.append(result)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70 + "\n")
    
    total_methods = len(results)
    vulnerable_methods = sum(1 for r in results if r.get('vulnerabilities'))
    warning_methods = sum(1 for r in results if r.get('warnings'))
    safe_methods = total_methods - vulnerable_methods - warning_methods
    
    print(f"Total methods analyzed: {total_methods}")
    print(f"🚨 Vulnerable: {vulnerable_methods}")
    print(f"⚠️  Warnings: {warning_methods}")
    print(f"✅ Safe: {safe_methods}\n")
    
    return results


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Analyze specific method
        method_id = sys.argv[1]
        analyze_method(method_id)
    else:
        # Analyze all StringSQL methods
        analyze_all_string_sql_methods()
