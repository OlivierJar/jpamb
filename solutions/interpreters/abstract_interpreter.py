#!/usr/bin/env python3
"""
Abstract Interpreter for SQL Injection Detection

This implements abstract interpretation over JVM bytecode to detect
SQL injection vulnerabilities through abstract execution.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import jpamb
from jpamb.jvm import base as jvm
from jpamb.model import Suite


class Taint(Enum):
    """Taint levels for abstract values"""
    UNTAINTED = "untainted"    # Known safe
    TAINTED = "tainted"        # Known unsafe (user input)
    UNKNOWN = "unknown"        # Don't know
    
    def join(self, other: 'Taint') -> 'Taint':
        """Lattice join operation (least upper bound)"""
        if self == other:
            return self
        if self == Taint.TAINTED or other == Taint.TAINTED:
            return Taint.TAINTED
        if self == Taint.UNKNOWN or other == Taint.UNKNOWN:
            return Taint.UNKNOWN
        return Taint.UNTAINTED
    
    def meet(self, other: 'Taint') -> 'Taint':
        """Lattice meet operation (greatest lower bound)"""
        if self == other:
            return self
        if self == Taint.UNTAINTED or other == Taint.UNTAINTED:
            return Taint.UNTAINTED
        if self == Taint.UNKNOWN or other == Taint.UNKNOWN:
            return Taint.UNKNOWN
        return Taint.TAINTED


@dataclass(frozen=True)
class AbstractValue:
    """Abstract value in the abstract domain"""
    taint: Taint
    is_string: bool = False
    constant_value: Optional[str] = None
    may_be_sql: bool = False
    
    def join(self, other: 'AbstractValue') -> 'AbstractValue':
        """Join two abstract values"""
        return AbstractValue(
            taint=self.taint.join(other.taint),
            is_string=self.is_string or other.is_string,
            constant_value=self.constant_value if self.constant_value == other.constant_value else None,
            may_be_sql=self.may_be_sql or other.may_be_sql
        )
    
    def __repr__(self):
        parts = [self.taint.value]
        if self.is_string:
            parts.append("str")
        if self.constant_value:
            parts.append(f"'{self.constant_value[:20]}'")
        if self.may_be_sql:
            parts.append("SQL")
        return f"AV({', '.join(parts)})"


# Pre-defined abstract values for common cases
TOP = AbstractValue(taint=Taint.UNKNOWN)
BOTTOM = AbstractValue(taint=Taint.UNTAINTED)
TAINTED_STRING = AbstractValue(taint=Taint.TAINTED, is_string=True)
SAFE_STRING = AbstractValue(taint=Taint.UNTAINTED, is_string=True)


@dataclass
class AbstractState:
    """Abstract state: abstract values for locals and stack"""
    locals: Dict[int, AbstractValue] = field(default_factory=dict)
    stack: List[AbstractValue] = field(default_factory=list)
    
    def copy(self) -> 'AbstractState':
        """Deep copy of state"""
        return AbstractState(
            locals=self.locals.copy(),
            stack=self.stack.copy()
        )
    
    def join(self, other: 'AbstractState') -> 'AbstractState':
        """Join two abstract states (for merge points)"""
        result = AbstractState()
        
        # Join locals
        all_keys = set(self.locals.keys()) | set(other.locals.keys())
        for key in all_keys:
            val1 = self.locals.get(key, BOTTOM)
            val2 = other.locals.get(key, BOTTOM)
            result.locals[key] = val1.join(val2)
        
        # Stack must have same length at join points in valid bytecode
        # For simplicity, we take the shorter stack and join corresponding elements
        min_len = min(len(self.stack), len(other.stack))
        for i in range(min_len):
            result.stack.append(self.stack[i].join(other.stack[i]))
        
        return result
    
    def __eq__(self, other) -> bool:
        """Check equality for fixpoint detection"""
        if not isinstance(other, AbstractState):
            return False
        return self.locals == other.locals and self.stack == other.stack
    
    def __repr__(self):
        return f"State(locals={self.locals}, stack={self.stack})"


class AbstractInterpreter:
    """Abstract interpreter for JVM bytecode"""
    
    def __init__(self, method_data: dict, class_data: dict = None, verbose: bool = False):
        self.method_data = method_data
        self.class_data = class_data or {}
        self.method_name = method_data.get("name", "unknown")
        self.bytecode = method_data.get("code", {}).get("bytecode", [])
        self.verbose = verbose
        
        # Analysis results
        self.vulnerabilities: List[Dict] = []
        self.warnings: List[Dict] = []
        
        # Abstract states at each program point
        self.states: Dict[int, AbstractState] = {}
        
        # Worklist for fixpoint iteration
        self.worklist: Set[int] = set()
        
        # SQL-related patterns
        self.sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "DROP"]
        
        # Bootstrap methods for dynamic invocation
        self.bootstrap_methods = self.class_data.get("bootstrapmethods", [])
    
    def analyze(self) -> Dict:
        """Perform abstract interpretation"""
        if self.verbose:
            print(f"\n{'='*70}")
            print(f"Abstract Interpretation: {self.method_name}")
            print(f"{'='*70}\n")
        
        # Initialize entry state
        entry_state = self._create_entry_state()
        self.states[0] = entry_state
        self.worklist.add(0)
        
        # Fixpoint iteration
        iteration = 0
        while self.worklist and iteration < 1000:  # Safety limit
            iteration += 1
            
            # Get next instruction to process
            offset = min(self.worklist)
            self.worklist.remove(offset)
            
            # Find instruction with this offset
            instruction = self._find_instruction(offset)
            if instruction is None:
                continue
            
            # Get current state
            current_state = self.states.get(offset)
            if current_state is None:
                continue
            
            if self.verbose:
                print(f"[{offset:3d}] {instruction.get('opr', ''):15s} {current_state.stack[-2:] if len(current_state.stack) > 0 else '[]'}")
            
            # Abstract execute instruction
            try:
                next_states = self._abstract_execute(instruction, current_state, offset)
                
                # Propagate states to successors
                for next_offset, next_state in next_states:
                    if next_offset not in self.states:
                        self.states[next_offset] = next_state
                        self.worklist.add(next_offset)
                    else:
                        # Join with existing state
                        old_state = self.states[next_offset]
                        new_state = old_state.join(next_state)
                        
                        if new_state != old_state:
                            self.states[next_offset] = new_state
                            self.worklist.add(next_offset)
            
            except Exception as e:
                if self.verbose:
                    print(f"  ⚠ Error: {e}")
        
        if self.verbose:
            print(f"\n  Fixpoint reached after {iteration} iterations\n")
        
        # Generate report
        report = {
            "method": self.method_name,
            "vulnerabilities": self.vulnerabilities,
            "warnings": self.warnings,
            "safe": len(self.vulnerabilities) == 0,
            "iterations": iteration
        }
        
        self._print_report(report)
        return report
    
    def _create_entry_state(self) -> AbstractState:
        """Create initial abstract state for method entry"""
        state = AbstractState()
        
        # Mark method parameters
        params = self.method_data.get("params", [])
        is_static = "static" in self.method_data.get("access", [])
        
        # If non-static, slot 0 is 'this'
        local_idx = 0 if is_static else 1
        
        for i, param in enumerate(params):
            param_type = param.get("type", {})
            
            if self._is_string_type(param_type):
                # String parameters are considered tainted (user input)
                state.locals[local_idx] = TAINTED_STRING
                if self.verbose:
                    print(f"  Parameter {local_idx} marked as TAINTED STRING")
            else:
                state.locals[local_idx] = BOTTOM
            
            local_idx += 1
        
        return state
    
    def _is_string_type(self, type_info: dict) -> bool:
        """Check if type is String"""
        if isinstance(type_info, dict):
            name = type_info.get("name", "")
            kind = type_info.get("kind", "")
            return kind == "class" and name in ["java/lang/String", "java.lang.String"]
        return False
    
    def _find_instruction(self, offset: int) -> Optional[dict]:
        """Find instruction at given offset"""
        for inst in self.bytecode:
            if inst.get("offset") == offset:
                return inst
        return None
    
    def _get_next_offset(self, current_offset: int) -> Optional[int]:
        """Get offset of next sequential instruction"""
        for i, inst in enumerate(self.bytecode):
            if inst.get("offset") == current_offset:
                if i + 1 < len(self.bytecode):
                    return self.bytecode[i + 1].get("offset")
        return None
    
    def _abstract_execute(self, instruction: dict, state: AbstractState, 
                         offset: int) -> List[Tuple[int, AbstractState]]:
        """
        Abstract execute an instruction.
        Returns list of (next_offset, next_state) pairs.
        """
        opr = instruction.get("opr", "")
        next_state = state.copy()
        successors = []
        
        if opr == "push":
            next_state = self._exec_push(instruction, next_state)
        elif opr == "load":
            next_state = self._exec_load(instruction, next_state)
        elif opr == "store":
            next_state = self._exec_store(instruction, next_state)
        elif opr == "invoke":
            next_state = self._exec_invoke(instruction, next_state, offset)
        elif opr == "return":
            next_state = self._exec_return(instruction, next_state)
            return []  # No successors after return
        elif opr in ["if", "ifz"]:
            # Conditional branch: two successors
            target = instruction.get("target")
            fall_through = self._get_next_offset(offset)
            
            if target is not None:
                successors.append((target, next_state.copy()))
            if fall_through is not None:
                successors.append((fall_through, next_state.copy()))
            return successors
        elif opr == "goto":
            target = instruction.get("target")
            if target is not None:
                successors.append((target, next_state))
            return successors
        elif opr in ["dup", "pop", "swap"]:
            next_state = self._exec_stack_op(instruction, next_state, opr)
        elif opr in ["new", "get", "put", "throw"]:
            # Simplified handling
            pass
        
        # Default: fall through to next instruction
        next_offset = self._get_next_offset(offset)
        if next_offset is not None:
            successors.append((next_offset, next_state))
        
        return successors
    
    def _exec_push(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Execute push (load constant)"""
        value = instruction.get("value", {})
        
        if value.get("type") == "string":
            string_value = value.get("value", "")
            abstract_val = AbstractValue(
                taint=Taint.UNTAINTED,
                is_string=True,
                constant_value=string_value,
                may_be_sql=self._looks_like_sql(string_value)
            )
            state.stack.append(abstract_val)
        else:
            state.stack.append(BOTTOM)
        
        return state
    
    def _exec_load(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Execute load (load from local)"""
        index = instruction.get("index", 0)
        value = state.locals.get(index, TOP)
        state.stack.append(value)
        return state
    
    def _exec_store(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Execute store (store to local)"""
        index = instruction.get("index", 0)
        if state.stack:
            value = state.stack.pop()
            state.locals[index] = value
        return state
    
    def _exec_invoke(self, instruction: dict, state: AbstractState, offset: int) -> AbstractState:
        """Execute method invocation"""
        method = instruction.get("method", {})
        method_name = method.get("name", "")
        args = method.get("args", [])
        num_args = len(args)
        access = instruction.get("access", "")
        
        # Handle string concatenation (including dynamic)
        if method_name in ["concat", "append", "makeConcatWithConstants"]:
            # Check if it's a dynamic invocation with SQL template
            if access == "dynamic":
                index = instruction.get("index")
                if index is not None and index < len(self.bootstrap_methods):
                    bootstrap = self.bootstrap_methods[index]
                    bootstrap_args = bootstrap.get("method", {}).get("args", [])
                    
                    # Check if the template contains SQL
                    for arg in bootstrap_args:
                        if arg.get("type") == "string":
                            template = arg.get("value", "")
                            if self._looks_like_sql(template):
                                if self.verbose:
                                    print(f"  📝 SQL template detected: {template[:50]}...")
                                # Mark concatenation result as SQL
                                return self._exec_string_concat(num_args, state, is_sql_template=True)
            
            return self._exec_string_concat(num_args, state)
        
        # Handle string operations
        elif method_name in ["substring", "toLowerCase", "toUpperCase", "trim"]:
            return self._exec_string_operation(state)
        
        # Handle SQL execution
        elif method_name in ["executeQuery", "executeUpdate", "execute", "prepareStatement"]:
            self._check_sql_execution(state, method_name, offset)
            # Pop query argument
            if state.stack and num_args > 0:
                for _ in range(num_args):
                    if state.stack:
                        state.stack.pop()
            state.stack.append(TOP)  # Result
            return state
        
        # Unknown method: conservative approximation
        else:
            # Pop arguments
            for _ in range(min(num_args, len(state.stack))):
                state.stack.pop()
            
            # Push unknown result
            state.stack.append(TOP)
            return state
    
    def _exec_string_concat(self, num_args: int, state: AbstractState, is_sql_template: bool = False) -> AbstractState:
        """Execute string concatenation in abstract domain"""
        if len(state.stack) < num_args:
            return state
        
        # Pop operands
        operands = []
        for _ in range(num_args):
            operands.append(state.stack.pop())
        operands.reverse()
        
        # Compute abstract result
        result_taint = Taint.UNTAINTED
        is_string = True
        constant_value = None
        may_be_sql = is_sql_template  # If template is SQL, result is SQL
        
        for op in operands:
            result_taint = result_taint.join(op.taint)
            is_string = is_string and op.is_string
            may_be_sql = may_be_sql or op.may_be_sql
        
        # If all operands are constant, concatenate
        if all(op.constant_value is not None for op in operands):
            constant_value = "".join(op.constant_value for op in operands)
            may_be_sql = self._looks_like_sql(constant_value)
        
        result = AbstractValue(
            taint=result_taint,
            is_string=is_string,
            constant_value=constant_value,
            may_be_sql=may_be_sql
        )
        
        state.stack.append(result)
        return state
    
    def _exec_string_operation(self, state: AbstractState) -> AbstractState:
        """Execute string operation (preserves taint)"""
        if state.stack:
            operand = state.stack.pop()
            result = AbstractValue(
                taint=operand.taint,
                is_string=True,
                may_be_sql=operand.may_be_sql
            )
            state.stack.append(result)
        return state
    
    def _exec_stack_op(self, instruction: dict, state: AbstractState, opr: str) -> AbstractState:
        """Execute stack manipulation operations"""
        if opr == "dup":
            if state.stack:
                state.stack.append(state.stack[-1])
        elif opr == "pop":
            if state.stack:
                state.stack.pop()
        elif opr == "swap":
            if len(state.stack) >= 2:
                state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        return state
    
    def _exec_return(self, instruction: dict, state: AbstractState) -> AbstractState:
        """Execute return instruction"""
        if instruction.get("type") == "ref" and state.stack:
            return_value = state.stack[-1]
            
            # Check if returning tainted SQL-like string
            if (return_value.taint == Taint.TAINTED and 
                return_value.is_string and 
                return_value.may_be_sql):
                
                self.vulnerabilities.append({
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "location": f"{self.method_name} return",
                    "description": "Method returns tainted SQL query string",
                    "taint": return_value.taint.value,
                    "recommendation": "Use PreparedStatement with parameterized queries"
                })
                
                if self.verbose:
                    print(f"  🚨 VULNERABILITY: Returning tainted SQL string")
        
        return state
    
    def _check_sql_execution(self, state: AbstractState, method_name: str, offset: int):
        """Check if SQL execution uses tainted data"""
        if state.stack:
            query_arg = state.stack[-1]
            
            if query_arg.taint == Taint.TAINTED:
                self.vulnerabilities.append({
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "location": f"{self.method_name} offset {offset}",
                    "description": f"Tainted string passed to {method_name}",
                    "taint": query_arg.taint.value,
                    "recommendation": "Use PreparedStatement with parameterized queries"
                })
                
                if self.verbose:
                    print(f"  🚨 CRITICAL: Tainted data in SQL execution")
            
            elif query_arg.taint == Taint.UNKNOWN:
                self.warnings.append({
                    "type": "DYNAMIC_SQL",
                    "severity": "MEDIUM",
                    "location": f"{self.method_name} offset {offset}",
                    "description": f"Dynamic SQL query in {method_name}",
                    "recommendation": "Verify that query is properly sanitized"
                })
    
    def _looks_like_sql(self, string: str) -> bool:
        """Check if string looks like SQL"""
        upper_str = string.upper()
        return any(keyword in upper_str for keyword in self.sql_keywords)
    
    def _print_report(self, report: Dict):
        """Print analysis report"""
        print(f"\n{'='*70}")
        print(f"Abstract Interpretation Report: {report['method']}")
        print(f"{'='*70}\n")
        print(f"Iterations: {report['iterations']}\n")
        
        if report['vulnerabilities']:
            print(f"🚨 VULNERABILITIES: {len(report['vulnerabilities'])}\n")
            for vuln in report['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}")
                print(f"    Location: {vuln['location']}")
                print(f"    {vuln['description']}")
                print(f"    💡 {vuln['recommendation']}\n")
        
        if report['warnings']:
            print(f"⚠️  WARNINGS: {len(report['warnings'])}\n")
            for warn in report['warnings']:
                print(f"  [{warn['severity']}] {warn['type']}")
                print(f"    Location: {warn['location']}")
                print(f"    {warn['description']}")
                print(f"    💡 {warn['recommendation']}\n")
        
        if report['safe']:
            print("✅ No vulnerabilities detected\n")
        
        print(f"{'='*70}\n")


def analyze_method(method_id: str, verbose: bool = False) -> Dict:
    """Analyze a specific method using abstract interpretation"""
    try:
        abs_method_id = jvm.AbsMethodID.decode(method_id)
        print(f"Analyzing: {abs_method_id}")
    except Exception as e:
        print(f"Error parsing method ID: {e}")
        return {}
    
    # Load JSON
    class_name = abs_method_id.ref.dotted()
    json_path = Path("target/decompiled") / class_name.replace(".", "/") + ".json"
    
    if not json_path.exists():
        print(f"Error: JSON file not found: {json_path}")
        return {}
    
    with open(json_path) as f:
        class_data = json.load(f)
    
    # Find method
    method_name = abs_method_id.name
    method_data = None
    
    for method in class_data.get("methods", []):
        if method.get("name") == method_name:
            method_data = method
            break
    
    if not method_data:
        print(f"Error: Method {method_name} not found")
        return {}
    
    # Run abstract interpreter
    interpreter = AbstractInterpreter(method_data, class_data=class_data, verbose=verbose)
    return interpreter.analyze()


def analyze_all_string_sql_methods(verbose: bool = False):
    """Analyze all methods in StringSQL class"""
    print("\n" + "="*70)
    print("Abstract Interpretation: StringSQL Class")
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
        
        interpreter = AbstractInterpreter(method, class_data=class_data, verbose=verbose)
        result = interpreter.analyze()
        results.append(result)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70 + "\n")
    
    total = len(results)
    vulnerable = sum(1 for r in results if r['vulnerabilities'])
    warnings = sum(1 for r in results if r['warnings'])
    safe = total - vulnerable - warnings
    
    print(f"Total methods: {total}")
    print(f"🚨 Vulnerable: {vulnerable}")
    print(f"⚠️  Warnings: {warnings}")
    print(f"✅ Safe: {safe}\n")
    
    return results


if __name__ == "__main__":
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        # Analyze specific method
        method_id = sys.argv[1]
        analyze_method(method_id, verbose=verbose)
    else:
        # Analyze all StringSQL methods
        analyze_all_string_sql_methods(verbose=verbose)
