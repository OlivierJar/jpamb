#!/usr/bin/env python3
"""
String-Aware JVM Bytecode Interpreter with SQL Injection Detection

This interpreter extends the basic JVM interpreter with:
1. String provenance tracking (constant vs. tainted/user-input)
2. SQL query construction analysis
3. SQL injection vulnerability detection
4. Abstract string domain for symbolic representation

"""

import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any, Set, Union
from enum import Enum
import json
import re

# Ensure we're using the jpamb package from lib
try:
    from jpamb import jvm
    from jpamb.jvm import opcode
    from jpamb.model import Suite, Input
except ImportError:
    print("Error: jpamb package not found.", file=sys.stderr)
    print("Please run with: cd lib && uv run python ../solutions/string_interpreter.py <args>", file=sys.stderr)
    sys.exit(1)


class StringProvenance(Enum):
    """Tracks the origin and trustworthiness of string data"""
    CONSTANT = "constant"
    USER_INPUT = "user_input"
    COMPUTED = "computed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AbstractString:
    """
    Abstract representation of a string value with provenance tracking.
    
    This enables symbolic string representation for detecting SQL injection
    and other string-based vulnerabilities.
    """
    value: Optional[str]
    provenance: StringProvenance
    tainted: bool
    operations: tuple[str, ...] = field(default_factory=tuple)
    
    @staticmethod
    def constant(s: str) -> 'AbstractString':
        return AbstractString(s, StringProvenance.CONSTANT, False, ())
    
    @staticmethod
    def user_input(s: Optional[str] = None) -> 'AbstractString':
        return AbstractString(s, StringProvenance.USER_INPUT, True, ())
    
    @staticmethod
    def unknown() -> 'AbstractString':
        return AbstractString(None, StringProvenance.UNKNOWN, True, ())
    
    def concat(self, other: 'AbstractString') -> 'AbstractString':
        new_value = None
        if self.value is not None and other.value is not None:
            new_value = self.value + other.value
        
        tainted = self.tainted or other.tainted
        ops = self.operations + other.operations + (f"concat({self.value}, {other.value})",)
        
        return AbstractString(
            new_value,
            StringProvenance.COMPUTED,
            tainted,
            ops
        )
    
    def substring(self, start: int, end: Optional[int] = None) -> 'AbstractString':
        new_value = None
        if self.value is not None:
            new_value = self.value[start:end]
        
        ops = self.operations + (f"substring({start}, {end})",)
        
        return AbstractString(
            new_value,
            StringProvenance.COMPUTED,
            self.tainted,
            ops
        )
    
    def __str__(self):
        taint_marker = "⚠️ TAINTED" if self.tainted else "✓ SAFE"
        value_str = f'"{self.value}"' if self.value else "<unknown>"
        return f"{value_str} [{taint_marker}]"


@dataclass
class SQLQuery:
    """Represents a SQL query being constructed"""
    query_string: AbstractString
    is_parameterized: bool = False
    parameters: list[Any] = field(default_factory=list)
    
    def is_vulnerable(self) -> bool:
        return self.query_string.tainted and not self.is_parameterized
    
    def get_vulnerability_details(self) -> str:
        if not self.is_vulnerable():
            return "No SQL injection vulnerability detected."
        
        details = [
            "🚨 SQL INJECTION VULNERABILITY DETECTED 🚨",
            f"Query: {self.query_string}",
            f"Operations: {' -> '.join(self.query_string.operations)}",
            "",
            "Explanation:",
            "  User input is directly concatenated into SQL query without parameterization.",
            "  This allows attackers to inject malicious SQL code.",
            "",
            "Example attack:",
            "  Input: ' OR '1'='1",
            f"  Resulting query: {self.query_string.value}",
            "",
            "Fix: Use prepared statements with parameterized queries.",
        ]
        return "\n".join(details)


@dataclass
class EnhancedValue:
    """
    Wraps jvm.Value with additional string analysis information
    """
    jvm_value: jvm.Value
    abstract_string: Optional[AbstractString] = None
    
    @staticmethod
    def from_jvm(v: jvm.Value) -> 'EnhancedValue':
        abs_str = None
        
        if isinstance(v.type, jvm.Object) and "String" in str(v.type.classname):
            if isinstance(v.value, str):
                abs_str = AbstractString.constant(v.value)
            else:
                abs_str = AbstractString.unknown()
        
        return EnhancedValue(v, abs_str)
    
    @staticmethod
    def string_constant(s: str) -> 'EnhancedValue':
        return EnhancedValue(
            jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), s),
            AbstractString.constant(s)
        )
    
    @staticmethod
    def string_input(s: str) -> 'EnhancedValue':
        return EnhancedValue(
            jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), s),
            AbstractString.user_input(s)
        )
    
    def is_string(self) -> bool:
        return self.abstract_string is not None
    
    def __str__(self):
        if self.abstract_string:
            return f"{self.jvm_value.value} [{self.abstract_string.provenance.value}]"
        return str(self.jvm_value)


@dataclass
class Stack:
    """Operand stack with enhanced values"""
    items: list[EnhancedValue] = field(default_factory=list)

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        return cls([])

    def peek(self) -> EnhancedValue:
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items[-1]

    def pop(self) -> EnhancedValue:
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items.pop(-1)

    def push(self, value: EnhancedValue):
        self.items.append(value)
        return self

    def __str__(self):
        if not self:
            return "ε"
        return "".join(f"({v})" for v in self.items)


@dataclass
class PC:
    """Program Counter"""
    method: jvm.Absolute[jvm.MethodID]
    offset: int

    def __iadd__(self, delta):
        self.offset += delta
        return self

    def __add__(self, delta):
        return PC(self.method, self.offset + delta)

    def jump_to(self, target_offset: int):
        self.offset = target_offset

    def __str__(self):
        return f"{self.method}:{self.offset}"


@dataclass
class Frame:
    """Stack frame with enhanced tracking"""
    locals: dict[int, EnhancedValue]
    stack: Stack
    pc: PC

    def __str__(self):
        locals_str = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals_str}}}, {self.stack}, {self.pc}>"


@dataclass
class Bytecode:
    """Bytecode context"""
    suite: Suite
    methods: dict[jvm.Absolute[jvm.MethodID], list[opcode.Opcode]] = field(default_factory=dict)
    offset_maps: dict[jvm.Absolute[jvm.MethodID], dict[int, int]] = field(default_factory=dict)

    def __getitem__(self, pc: PC) -> opcode.Opcode:
        if pc.method not in self.methods:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes
            self.offset_maps[pc.method] = {op.offset: i for i, op in enumerate(opcodes)}
        
        if pc.offset < 0 or pc.offset >= len(self.methods[pc.method]):
            raise RuntimeError(f"Invalid index {pc.offset} in {pc.method}")
        
        return self.methods[pc.method][pc.offset]
    
    def offset_to_index(self, method: jvm.Absolute[jvm.MethodID], offset: int) -> int:
        if method not in self.offset_maps:
            opcodes = list(self.suite.method_opcodes(method))
            self.methods[method] = opcodes
            self.offset_maps[method] = {op.offset: i for i, op in enumerate(opcodes)}
        
        index = self.offset_maps[method].get(offset)
        if index is None:
            raise RuntimeError(f"Invalid offset {offset} in {method}")
        return index


@dataclass
class State:
    """Complete program state with SQL tracking"""
    heap: dict[int, EnhancedValue]
    frames: Stack
    next_addr: int = 1000
    sql_queries: list[SQLQuery] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    def alloc(self, value: EnhancedValue) -> int:
        addr = self.next_addr
        self.next_addr += 1
        self.heap[addr] = value
        return addr
    
    def record_sql_query(self, query: SQLQuery):
        self.sql_queries.append(query)
        if query.is_vulnerable():
            vuln = query.get_vulnerability_details()
            self.vulnerabilities.append(vuln)

    def __str__(self):
        if not self.frames:
            return "<empty>"
        return f"State(frames={len(self.frames.items)}, heap={len(self.heap)}, queries={len(self.sql_queries)})"


class StringInterpreter:
    """
    Enhanced interpreter with string tracking and SQL injection detection
    """

    def __init__(self, suite: Suite, verbose: bool = False, detect_sql: bool = True):
        self.bc = Bytecode(suite)
        self.verbose = verbose
        self.detect_sql = detect_sql
        self.step_count = 0

    def step(self, state: State) -> Union[State, str]:
        if not state.frames:
            return "ok"

        frame = state.frames.peek()
        op = self.bc[frame.pc]
        
        self.step_count += 1
        if self.verbose:
            print(f"[{self.step_count}] {frame.pc.offset:3d}: {op}", file=sys.stderr)
            print(f"     Stack: {frame.stack}", file=sys.stderr)

        try:
            result = self._execute_opcode(op, state)
            return result if result is not None else state
        except Exception as e:
            return f"error: {e}"

    def _execute_opcode(self, op: opcode.Opcode, state: State) -> Optional[Union[State, str]]:
        frame = state.frames.peek()

        match op:
            case opcode.Push(value=v):
                enhanced = EnhancedValue.from_jvm(v)
                frame.stack.push(enhanced)
                frame.pc += 1

            case opcode.Load(type=t, index=n):
                v = frame.locals.get(n)
                if v is None:
                    return f"uninitialized local variable {n}"
                frame.stack.push(v)
                frame.pc += 1

            case opcode.Store(type=t, index=n):
                v = frame.stack.pop()
                frame.locals[n] = v
                frame.pc += 1

            case opcode.Binary(type=jvm.Int(), operant=op_type):
                v2 = frame.stack.pop()
                v1 = frame.stack.pop()
                
                if v2.jvm_value.value == 0 and op_type in (opcode.BinaryOpr.Div, opcode.BinaryOpr.Rem):
                    return "divide by zero"
                
                match op_type:
                    case opcode.BinaryOpr.Add:
                        result = v1.jvm_value.value + v2.jvm_value.value
                    case opcode.BinaryOpr.Sub:
                        result = v1.jvm_value.value - v2.jvm_value.value
                    case opcode.BinaryOpr.Mul:
                        result = v1.jvm_value.value * v2.jvm_value.value
                    case opcode.BinaryOpr.Div:
                        result = int(v1.jvm_value.value / v2.jvm_value.value)
                    case opcode.BinaryOpr.Rem:
                        result = v1.jvm_value.value % v2.jvm_value.value
                    case _:
                        return f"unsupported binary operation {op_type}"
                
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value.int(result)))
                frame.pc += 1

            case opcode.Dup(words=1):
                v = frame.stack.peek()
                frame.stack.push(v)
                frame.pc += 1

            case opcode.NewArray(type=t, dim=1):
                length = frame.stack.pop()
                if length.jvm_value.value < 0:
                    return "negative array size"
                
                arr_list = [self._default_value(t).jvm_value.value for _ in range(length.jvm_value.value)]
                arr = jvm.Value(jvm.Array(t), arr_list)
                addr = state.alloc(EnhancedValue.from_jvm(arr))
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value(jvm.Reference(), addr)))
                frame.pc += 1

            case opcode.ArrayStore(type=t):
                value = frame.stack.pop()
                index = frame.stack.pop()
                arrayref = frame.stack.pop()
                
                if arrayref.jvm_value.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.jvm_value.value]
                if not isinstance(arr.jvm_value.value, list):
                    arr.jvm_value.value = list(arr.jvm_value.value)
                
                if index.jvm_value.value < 0 or index.jvm_value.value >= len(arr.jvm_value.value):
                    return "out of bounds"
                
                arr.jvm_value.value[index.jvm_value.value] = value.jvm_value.value
                frame.pc += 1

            case opcode.ArrayLoad(type=t):
                index = frame.stack.pop()
                arrayref = frame.stack.pop()
                
                if arrayref.jvm_value.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.jvm_value.value]
                if index.jvm_value.value < 0 or index.jvm_value.value >= len(arr.jvm_value.value):
                    return "out of bounds"
                
                elem = arr.jvm_value.value[index.jvm_value.value]
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value(t, elem)))
                frame.pc += 1

            case opcode.ArrayLength():
                arrayref = frame.stack.pop()
                if arrayref.jvm_value.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.jvm_value.value]
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value.int(len(arr.jvm_value.value))))
                frame.pc += 1

            case opcode.If(condition=cond, target=target):
                v2 = frame.stack.pop()
                v1 = frame.stack.pop()
                
                jump = False
                match cond:
                    case "eq": jump = v1.jvm_value.value == v2.jvm_value.value
                    case "ne": jump = v1.jvm_value.value != v2.jvm_value.value
                    case "lt": jump = v1.jvm_value.value < v2.jvm_value.value
                    case "le": jump = v1.jvm_value.value <= v2.jvm_value.value
                    case "gt": jump = v1.jvm_value.value > v2.jvm_value.value
                    case "ge": jump = v1.jvm_value.value >= v2.jvm_value.value
                
                if jump:
                    idx = self.bc.offset_to_index(frame.pc.method, target)
                    frame.pc.offset = idx
                else:
                    frame.pc += 1

            case opcode.Ifz(condition=cond, target=target):
                v = frame.stack.pop()
                
                jump = False
                match cond:
                    case "eq": jump = v.jvm_value.value == 0 or v.jvm_value.value is None
                    case "ne": jump = v.jvm_value.value != 0 and v.jvm_value.value is not None
                    case "lt": jump = v.jvm_value.value < 0
                    case "le": jump = v.jvm_value.value <= 0
                    case "gt": jump = v.jvm_value.value > 0
                    case "ge": jump = v.jvm_value.value >= 0
                    case "is": jump = v.jvm_value.value is None
                    case "isnot": jump = v.jvm_value.value is not None
                
                if jump:
                    idx = self.bc.offset_to_index(frame.pc.method, target)
                    frame.pc.offset = idx
                else:
                    frame.pc += 1

            case opcode.Goto(target=target):
                idx = self.bc.offset_to_index(frame.pc.method, target)
                frame.pc.offset = idx

            case opcode.Incr(index=n, amount=amt):
                v = frame.locals.get(n, EnhancedValue.from_jvm(jvm.Value.int(0)))
                frame.locals[n] = EnhancedValue.from_jvm(jvm.Value.int(v.jvm_value.value + amt))
                frame.pc += 1

            case opcode.New(classname=cn):
                obj = jvm.Value(jvm.Reference(), {"class": cn, "fields": {}})
                addr = state.alloc(EnhancedValue.from_jvm(obj))
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value(jvm.Reference(), addr)))
                frame.pc += 1

            case opcode.Get(static=True, field=f):
                if f.extension.name == "$assertionsDisabled" or f.extension.name == "assertionsDisabled":
                    frame.stack.push(EnhancedValue.from_jvm(jvm.Value.boolean(False)))
                else:
                    frame.stack.push(self._default_value(f.extension.type))
                frame.pc += 1

            case opcode.Get(static=False, field=f):
                objectref = frame.stack.pop()
                if objectref.jvm_value.value is None:
                    return "null pointer"
                frame.stack.push(self._default_value(f.extension.type))
                frame.pc += 1

            case opcode.Cast(from_=from_t, to_=to_t):
                v = frame.stack.pop()
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value(to_t, v.jvm_value.value)))
                frame.pc += 1

            case opcode.Return(type=None):
                state.frames.pop()
                if not state.frames:
                    return "ok"
                else:
                    state.frames.peek().pc += 1

            case opcode.Return(type=t):
                v = frame.stack.pop()
                state.frames.pop()
                if not state.frames:
                    return "ok"
                else:
                    state.frames.peek().stack.push(v)
                    state.frames.peek().pc += 1

            case opcode.Throw():
                exc = frame.stack.pop()
                if exc.jvm_value.value is None:
                    return "null pointer"
                return "assertion error"

            case opcode.InvokeVirtual() | opcode.InvokeStatic() | opcode.InvokeSpecial() | opcode.InvokeInterface():
                result = self._handle_method_invocation(op, state)
                if isinstance(result, str):
                    return result
                frame.pc += 1

            case _:
                return f"unsupported opcode: {op}"

        return None

    def _handle_method_invocation(self, op, state: State) -> Optional[str]:
        frame = state.frames.peek()
        method = op.method
        num_args = len(method.extension.params)
        
        args = []
        for _ in range(num_args):
            args.insert(0, frame.stack.pop())
        
        receiver = None
        if not isinstance(op, opcode.InvokeStatic):
            receiver = frame.stack.pop()
            if receiver.jvm_value.value is None:
                return "null pointer"
        
        method_name = method.extension.name
        class_name = str(method.classname)
        
        if "StringBuilder" in class_name or "StringBuffer" in class_name:
            if method_name == "append" and len(args) > 0:
                if receiver and receiver.is_string() and args[0].is_string():
                    new_abs_str = receiver.abstract_string.concat(args[0].abstract_string)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/StringBuilder")), receiver.jvm_value.value),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
            elif method_name == "toString":
                if receiver:
                    frame.stack.push(receiver)
                    return None
        
        if "String" in class_name:
            if method_name == "concat" and len(args) > 0:
                if receiver and receiver.is_string() and args[0].is_string():
                    new_abs_str = receiver.abstract_string.concat(args[0].abstract_string)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), 
                                receiver.jvm_value.value + args[0].jvm_value.value),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
            elif method_name == "substring":
                if receiver and receiver.is_string():
                    start = args[0].jvm_value.value if len(args) > 0 else 0
                    end = args[1].jvm_value.value if len(args) > 1 else None
                    new_abs_str = receiver.abstract_string.substring(start, end)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")),
                                receiver.jvm_value.value[start:end]),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
        
        if self.detect_sql and ("Statement" in class_name or "Connection" in class_name):
            if method_name in ["executeQuery", "executeUpdate", "execute", "prepareStatement"]:
                if len(args) > 0 and args[0].is_string():
                    query = SQLQuery(
                        query_string=args[0].abstract_string,
                        is_parameterized=("prepare" in method_name.lower())
                    )
                    state.record_sql_query(query)
                    
                    if query.is_vulnerable():
                        if self.verbose:
                            print(f"\n{query.get_vulnerability_details()}", file=sys.stderr)
                        return "sql injection vulnerability"
        
        if method.extension.return_type is not None:
            frame.stack.push(self._default_value(method.extension.return_type))
        
        return None

    def _default_value(self, t: jvm.Type) -> EnhancedValue:
        match t:
            case jvm.Int() | jvm.Byte() | jvm.Short() | jvm.Char():
                return EnhancedValue.from_jvm(jvm.Value.int(0))
            case jvm.Boolean():
                return EnhancedValue.from_jvm(jvm.Value.boolean(False))
            case jvm.Long():
                return EnhancedValue.from_jvm(jvm.Value(jvm.Long(), 0))
            case jvm.Float():
                return EnhancedValue.from_jvm(jvm.Value(jvm.Float(), 0.0))
            case jvm.Double():
                return EnhancedValue.from_jvm(jvm.Value(jvm.Double(), 0.0))
            case _:
                return EnhancedValue.from_jvm(jvm.Value(jvm.Reference(), None))

    def execute(self, methodid: jvm.Absolute[jvm.MethodID], args: list[jvm.Value], 
                taint_params: bool = True) -> tuple[str, State]:
        """
        Execute method with arguments.
        
        Args:
            methodid: Method to execute
            args: Method arguments
            taint_params: If True, mark parameters as tainted user input
        
        Returns:
            Tuple of (result, final_state)
        """
        # Create initial frame with enhanced values
        locals = {}
        for i, arg in enumerate(args):
            if taint_params and isinstance(arg.type, jvm.Object) and "String" in str(arg.type.classname):
                # Mark string parameters as tainted user input
                locals[i] = EnhancedValue.string_input(arg.value)
            else:
                locals[i] = EnhancedValue.from_jvm(arg)
        
        frame = Frame(
            locals=locals,
            stack=Stack.empty(),
            pc=PC(methodid, 0)
        )
        
        state = State(
            heap={},
            frames=Stack([frame])
        )
        
        if self.verbose:
            print(f"\n=== Executing {methodid} ===", file=sys.stderr)
            print(f"Arguments: {args}", file=sys.stderr)
            print("", file=sys.stderr)
        
        # Run until termination
        max_steps = 10000
        while self.step_count < max_steps:
            result = self.step(state)
            
            if isinstance(result, str):
                if self.verbose:
                    print(f"\n=== Result: {result} ===", file=sys.stderr)
                    
                    # Print SQL analysis results
                    if state.sql_queries:
                        print(f"\n=== SQL Analysis ===", file=sys.stderr)
                        print(f"Queries analyzed: {len(state.sql_queries)}", file=sys.stderr)
                        for i, query in enumerate(state.sql_queries, 1):
                            print(f"\nQuery {i}:", file=sys.stderr)
                            print(f"  {query.query_string}", file=sys.stderr)
                            print(f"  Parameterized: {query.is_parameterized}", file=sys.stderr)
                            print(f"  Vulnerable: {query.is_vulnerable()}", file=sys.stderr)
                    
                    if state.vulnerabilities:
                        print(f"\n=== Vulnerabilities Found: {len(state.vulnerabilities)} ===", file=sys.stderr)
                
                return result, state
        
        return "timeout", state


def main():
    if len(sys.argv) < 3:
        print("Usage: python string_interpreter.py <method> <input> [--verbose] [--no-sql-check]", file=sys.stderr)
        print('Example: python string_interpreter.py "jpamb.cases.Simple.assertFalse:()V" "()"', file=sys.stderr)
        sys.exit(1)
    
    method_str = sys.argv[1]
    input_str = sys.argv[2]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    detect_sql = "--no-sql-check" not in sys.argv
    
    script_dir = Path(__file__).parent
    workspace = script_dir.parent.parent
    
    suite = Suite(workspace)
    
    try:
        methodid = jvm.Absolute.decode(method_str, jvm.MethodID.decode)
    except Exception as e:
        print(f"Error parsing method: {e}", file=sys.stderr)
        sys.exit(1)
    
    try:
        input_obj = Input.decode(input_str)
        args = list(input_obj.values)
    except Exception as e:
        print(f"Error parsing input: {e}", file=sys.stderr)
        sys.exit(1)
    
    interp = StringInterpreter(suite, verbose=verbose, detect_sql=detect_sql)
    result, final_state = interp.execute(methodid, args)
    
    print(result)
    
    if final_state.vulnerabilities and not verbose:
        print(f"\n⚠️  {len(final_state.vulnerabilities)} SQL injection vulnerabilities detected", file=sys.stderr)
    
    sys.exit(0 if result == "ok" else 1)


if __name__ == "__main__":
    main()
