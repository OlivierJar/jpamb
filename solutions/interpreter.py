#!/usr/bin/env python3
"""
String-Aware JVM Bytecode Interpreter with SQL Injection Detection

This interpreter extends the basic JVM interpreter with:
1. String provenance tracking (constant vs. tainted/user-input)
2. SQL query construction analysis
3. SQL injection vulnerability detection
4. Abstract string domain for symbolic representation

Usage:
    python interpreter.py "ClassName.methodName:(params)returnType" "(arg1, arg2, ...)"
    
Example:

    python interpreter.py "jpamb.cases.SQLTest.executeQuery:(Ljava/lang/String;)V" "(\"admin\")"
"""

import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any, Set, Union
from enum import Enum
import json
import re

try:
    from jpamb import jvm
    from jpamb.jvm import opcode
    from jpamb.jvm.base import (
        StringProvenance, AbstractString, SQLQuery, EnhancedValue,
        Stack, PC, Frame
    )
    from jpamb.model import Suite, Input
except ImportError:
    print("Error: jpamb was not found", file=sys.stderr)
    print("Please run with: cd solutions/interpreters && uv run python interpreter.py <args>", file=sys.stderr)
    sys.exit(1)


# ============================================================================
# Enhanced State Components (Interpreter-specific)
# ============================================================================


@dataclass
class Bytecode:
    """Bytecode context"""

    suite: Suite
    methods: dict[jvm.Absolute[jvm.MethodID], list[opcode.Opcode]] = field(default_factory=dict)
    offset_maps: dict[jvm.Absolute[jvm.MethodID], dict[int, int]] = field(default_factory=dict)
    class_data: dict[jvm.ClassName, dict] = field(default_factory=dict)

    def get_class_data(self, classname: jvm.ClassName) -> dict:
        """Get class data including bootstrap methods"""
        if classname not in self.class_data:
            import json
            path = self.suite.decompiledfile(classname)
            with open(path) as f:
                self.class_data[classname] = json.load(f)
        return self.class_data[classname]

    def __getitem__(self, pc: PC) -> opcode.Opcode:
        """Get bytecode instruction at PC"""
        if pc.method not in self.methods:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes
            self.offset_maps[pc.method] = {op.offset: i for i, op in enumerate(opcodes)}

        if pc.offset < 0 or pc.offset >= len(self.methods[pc.method]):
            raise RuntimeError(f"Invalid index {pc.offset} in {pc.method}")

        return self.methods[pc.method][pc.offset]

    def offset_to_index(self, method: jvm.Absolute[jvm.MethodID], target: int) -> int:
        """Convert bytecode target (offset or instruction index) to list index"""
        if method not in self.methods:
            opcodes = list(self.suite.method_opcodes(method))
            self.methods[method] = opcodes
        if 0 <= target < len(self.methods[method]):
            return target

        if method not in self.offset_maps:
            self.offset_maps[method] = {op.offset: i for i, op in enumerate(self.methods[method])}

        # First try treating the target as a real bytecode offset
        index = self.offset_maps[method].get(target)
        if index is None:
            # Some decompilers encode jump targets as instruction indexes.
            if 0 <= target < len(self.methods[method]):
                return target

            # Fall back to the nearest valid offset (old behaviour)
            valid_offsets = sorted(self.offset_maps[method].keys())
            for valid_offset in valid_offsets:
                if valid_offset >= target:
                    return self.offset_maps[method][valid_offset]
            raise RuntimeError(f"Invalid offset {target} in {method}")
        return index


@dataclass
class State:
    """Complete program state with SQL tracking"""
    
    heap: dict[int, EnhancedValue]
    frames: Stack[EnhancedValue]
    next_addr: int = 1000
    sql_queries: list[SQLQuery] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    def alloc(self, value: EnhancedValue) -> int:
        """Allocate value on heap, return reference"""
        addr = self.next_addr
        self.next_addr += 1
        self.heap[addr] = value
        return addr
    
    def record_sql_query(self, query: SQLQuery) -> None:
        """Record a SQL query for analysis"""
        self.sql_queries.append(query)
        if query.is_vulnerable():
            vuln = query.get_vulnerability_details()
            self.vulnerabilities.append(vuln)

    def __str__(self) -> str:
        if not self.frames:
            return "<empty>"
        return f"State(frames={len(self.frames.items)}, heap={len(self.heap)}, queries={len(self.sql_queries)})"


# ============================================================================
# String-Aware Interpreter
# ============================================================================

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
        """Single step execution"""
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
        """Execute single opcode with string tracking"""
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

            case opcode.Pop():
                # Pop value(s) from stack and discard
                for _ in range(op.words):
                    frame.stack.pop()
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
                vuln_result = self._analyze_return_value(frame.pc.method, v, state)
                if vuln_result:
                    return vuln_result
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
                # Inspect the actual exception object to classify outcome
                exc_obj = state.heap.get(exc.jvm_value.value)
                exc_class = None
                if exc_obj and isinstance(exc_obj.jvm_value.value, dict):
                    exc_class = exc_obj.jvm_value.value.get("class")
                if isinstance(exc_class, jvm.ClassName):
                    exc_class = str(exc_class)

                if exc_class and "NullPointerException" in exc_class:
                    return "null pointer"
                if exc_class and (
                    "ArrayIndexOutOfBoundsException" in exc_class
                    or "StringIndexOutOfBoundsException" in exc_class
                    or "IndexOutOfBoundsException" in exc_class
                ):
                    return "out of bounds"
                if exc_class and "AssertionError" in exc_class:
                    return "assertion error"
                return "assertion error"

            case opcode.InvokeVirtual() | opcode.InvokeStatic() | opcode.InvokeSpecial() | opcode.InvokeInterface() | opcode.InvokeDynamic():
                result = self._handle_method_invocation(op, state)
                if isinstance(result, str):
                    return result
                frame.pc += 1

            case _:
                return f"unsupported opcode: {op}"

        return None

    def _handle_method_invocation(self, op, state: State) -> Optional[str]:
        """Handle method invocations with special handling for string and SQL operations"""
        frame = state.frames.peek()

        # Handle InvokeDynamic separately
        if isinstance(op, opcode.InvokeDynamic):
            method_name = op.method.get("name", "")

            # Handle string concatenation via invokedynamic
            if method_name == "makeConcatWithConstants":
                # Pop all arguments
                num_args = len(op.method.get("args", []))
                args = []
                for _ in range(num_args):
                    args.insert(0, frame.stack.pop())

                # Get the bootstrap method template
                bootstrap_index = op.index
                class_data = self.bc.get_class_data(frame.pc.method.classname)
                bootstrap_methods = class_data.get("bootstrapmethods", [])
                template = ""

                for bm in bootstrap_methods:
                    if bm.get("index") == bootstrap_index:
                        # Get the template string from bootstrap method args
                        bm_args = bm.get("method", {}).get("args", [])
                        if bm_args and isinstance(bm_args[0], dict) and bm_args[0].get("type") == "string":
                            template = bm_args[0].get("value", "")
                        break

                result_segments: list[str] = []
                current_abs: Optional[AbstractString] = None
                cursor = 0

                for i, arg in enumerate(args, start=1):
                    placeholder = chr(i)
                    pos = template.find(placeholder, cursor)
                    if pos == -1:
                        continue

                    literal = template[cursor:pos]
                    if literal:
                        result_segments.append(literal)
                        current_abs = self._concat_abstract(current_abs, AbstractString.constant(literal))

                    arg_value = ""
                    if arg.jvm_value.value is not None:
                        arg_value = str(arg.jvm_value.value)
                    result_segments.append(arg_value)

                    arg_abs = arg.abstract_string or AbstractString.constant(arg_value)
                    current_abs = self._concat_abstract(current_abs, arg_abs)
                    cursor = pos + 1

                if cursor < len(template):
                    tail = template[cursor:]
                    result_segments.append(tail)
                    if tail:
                        current_abs = self._concat_abstract(current_abs, AbstractString.constant(tail))

                result_value = "".join(result_segments)
                if current_abs is None:
                    current_abs = AbstractString.constant(result_value)

                # Push concatenated result
                result = EnhancedValue(
                    jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), result_value),
                    current_abs
                )
                frame.stack.push(result)
                return None

            # For other invokedynamic, push default return value
            if "returns" in op.method and op.method["returns"]:
                return_type_json = op.method["returns"]
                return_type = jvm.Type.from_json_type(return_type_json)
                frame.stack.push(self._default_value(return_type))
            return None

        method = op.method
        num_args = len(method.extension.params)

        # Pop arguments
        args = []
        for _ in range(num_args):
            args.insert(0, frame.stack.pop())

        # Pop receiver for non-static
        receiver = None
        if not isinstance(op, opcode.InvokeStatic):
            receiver = frame.stack.pop()
            if receiver.jvm_value.value is None:
                return "null pointer"
        
        # Special handling for string operations
        method_name = method.extension.name
        class_name = str(method.classname)
        
        if class_name == "jpamb/cases/StringSQL" and method_name == "detectVulnerability":
            if not args:
                return None

            query_arg = args[0]
            query_value = query_arg.jvm_value.value or ""
            abstract_query = query_arg.abstract_string or AbstractString.constant(query_value)
            query = SQLQuery(query_string=abstract_query, is_parameterized=False)
            state.record_sql_query(query)

            raw_inputs: list[str] = []
            if len(args) > 1:
                array_ref = args[1]
                if array_ref.jvm_value.value is not None:
                    arr_value = state.heap.get(array_ref.jvm_value.value)
                    if arr_value and isinstance(arr_value.jvm_value.value, list):
                        for element in arr_value.jvm_value.value:
                            if isinstance(element, str):
                                raw_inputs.append(element)

            contains_input = any(inp and inp in query_value for inp in raw_inputs)
            if contains_input or query.is_vulnerable():
                state.vulnerabilities.append("detectVulnerability helper flagged SQL injection")
                return "vulnerable"
            return None

        if "StringBuilder" in class_name or "StringBuffer" in class_name:
            if method_name == "append" and len(args) > 0:
                # String concatenation
                if receiver and receiver.is_string() and args[0].is_string():
                    new_abs_str = receiver.abstract_string.concat(args[0].abstract_string)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/StringBuilder")), receiver.jvm_value.value),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
            elif method_name == "toString":
                # Convert to string
                if receiver:
                    frame.stack.push(receiver)
                    return None
        
        if "String" in class_name:
            if method_name == "concat" and len(args) > 0:
                # String concatenation
                if receiver and receiver.is_string() and args[0].is_string():
                    new_abs_str = receiver.abstract_string.concat(args[0].abstract_string)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")), 
                                receiver.jvm_value.value + args[0].jvm_value.value),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
            elif method_name == "contains" and len(args) > 0:
                # String.contains handles null argument explicitly
                substring = args[0]
                if substring.jvm_value.value is None:
                    return "null pointer"
                if receiver and receiver.is_string():
                    haystack = receiver.jvm_value.value or ""
                    needle = substring.jvm_value.value
                    contains = needle in haystack
                    frame.stack.push(EnhancedValue.from_jvm(jvm.Value.boolean(contains)))
                    return None
            elif method_name == "substring":
                # Substring extraction
                if receiver and receiver.is_string():
                    value = receiver.jvm_value.value or ""
                    start = args[0].jvm_value.value if len(args) > 0 else 0
                    end = args[1].jvm_value.value if len(args) > 1 else len(value)
                    
                    if start < 0 or end < 0 or start > end or end > len(value):
                        return "out of bounds"
                    
                    new_abs_str = receiver.abstract_string.substring(start, end)
                    result = EnhancedValue(
                        jvm.Value(jvm.Object(jvm.ClassName.decode("java/lang/String")),
                                value[start:end]),
                        new_abs_str
                    )
                    frame.stack.push(result)
                    return None
            elif method_name == "length":
                if receiver and receiver.is_string():
                    value = receiver.jvm_value.value or ""
                    frame.stack.push(EnhancedValue.from_jvm(jvm.Value.int(len(value))))
                else:
                    frame.stack.push(EnhancedValue.from_jvm(jvm.Value.int(0)))
                return None
            elif method_name == "charAt" and len(args) > 0:
                if receiver and receiver.is_string():
                    value = receiver.jvm_value.value or ""
                    index = args[0].jvm_value.value
                    if index < 0 or index >= len(value):
                        return "out of bounds"
                    ch = value[index]
                    frame.stack.push(EnhancedValue.from_jvm(jvm.Value(jvm.Char(), ord(ch))))
                    return None
            elif method_name == "equals" and len(args) > 0:
                other = args[0].jvm_value.value
                current = receiver.jvm_value.value if receiver else None
                frame.stack.push(EnhancedValue.from_jvm(jvm.Value.boolean(current == other)))
                return None
        
        # SQL injection detection
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
        
        # Default: push return value if not void
        if method.extension.return_type is not None:
            frame.stack.push(self._default_value(method.extension.return_type))
        
        return None

    def _analyze_return_value(
        self,
        methodid: jvm.Absolute[jvm.MethodID],
        value: EnhancedValue,
        state: State,
    ) -> Optional[str]:
        """Inspect returned strings and flag SQL injection vulnerabilities."""
        if not self.detect_sql:
            return None
        if not value.is_string() or not value.abstract_string:
            return None

        abs_str = value.abstract_string
        if not abs_str.tainted:
            return None

        if self._looks_like_sql(abs_str.value):
            query = SQLQuery(query_string=abs_str, is_parameterized=False)
            state.record_sql_query(query)
            return "vulnerable"

        return None

    @staticmethod
    def _concat_abstract(
        current: Optional[AbstractString],
        addition: AbstractString,
    ) -> AbstractString:
        if current is None:
            return addition
        return current.concat(addition)

    @staticmethod
    def _looks_like_sql(query: Optional[str]) -> bool:
        """Heuristic check to see if a string resembles SQL."""
        if not query:
            return False

        lowered = query.lower()
        keywords = (
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "union",
            "where",
            "into",
        )
        return any(keyword in lowered for keyword in keywords)

    def _default_value(self, t: jvm.Type) -> EnhancedValue:
        """Get default value for type"""
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
            if taint_params and isinstance(arg.type, jvm.Object) and "String" in str(arg.type.name):
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


# Main entry point

def main():
    if len(sys.argv) < 3:
        print("Usage: python interpreter.py <method> <input> [--verbose] [--no-sql-check]", file=sys.stderr)
        print('Example: python interpreter.py "jpamb.cases.Simple.assertFalse:()V" "()"', file=sys.stderr)
        sys.exit(1)
    
    method_str = sys.argv[1]
    input_str = sys.argv[2]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    detect_sql = "--no-sql-check" not in sys.argv
    
    script_dir = Path(__file__).parent
    workspace = script_dir.parent
    
    suite = Suite(workspace)
    
    # Parse method
    try:
        methodid = jvm.Absolute.decode(method_str, jvm.MethodID.decode)
    except Exception as e:
        print(f"Error parsing method: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse input
    try:
        input_obj = Input.decode(input_str)
        args = list(input_obj.values)
    except Exception as e:
        print(f"Error parsing input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create interpreter and execute
    interp = StringInterpreter(suite, verbose=verbose, detect_sql=detect_sql)
    result, final_state = interp.execute(methodid, args)
    
    # Print result
    print(result)
    
    # Print vulnerability summary if any found
    if final_state.vulnerabilities and not verbose:
        print(f"\n⚠️  {len(final_state.vulnerabilities)} SQL injection vulnerabilities detected", file=sys.stderr)
    
    expected_results = {
        "ok",
        "divide by zero",
        "assertion error",
        "out of bounds",
        "null pointer",
        "*",
        "vulnerable",
        "sql injection vulnerability",
    }

    # Exit with appropriate code
    sys.exit(0 if result in expected_results else 1)


if __name__ == "__main__":
    main()
