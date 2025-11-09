#!/usr/bin/env python3
"""
Standalone JVM Bytecode Interpreter

This interpreter implements the operational semantics of a simplified JVM
as described in the course materials. It executes Java bytecode methods
and can detect runtime errors like division by zero, null pointer exceptions,
and array out of bounds errors.

Usage:
    python interpreter.py "ClassName.methodName:(params)returnType" "(arg1, arg2, ...)"
    
Example:
    python interpreter.py "jpamb.cases.Simple.addIntegers:(II)I" "(5, 3)"
    python interpreter.py "jpamb.cases.Simple.assertFalse:()V" "()"
"""

import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any
import json

# Ensure we're using the jpamb package from lib
# The script should be run with: uv run --directory lib python ../solutions/interpreter.py
try:
    from jpamb import jvm
    from jpamb.jvm import opcode
    from jpamb.model import Suite, Input
except ImportError:
    print("Error: jpamb package not found.", file=sys.stderr)
    print("Please run with: cd lib && uv run python ../solutions/interpreter.py <args>", file=sys.stderr)
    print("Or install jpamb: cd lib && uv pip install -e .", file=sys.stderr)
    sys.exit(1)


# ============================================================================
# State Components (following operational semantics)
# ============================================================================

@dataclass
class Stack:
    """Operand stack - stores intermediate computation values"""
    items: list[jvm.Value] = field(default_factory=list)

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        return cls([])

    def peek(self) -> jvm.Value:
        """Look at top of stack without removing"""
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items[-1]

    def pop(self) -> jvm.Value:
        """Remove and return top of stack"""
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items.pop(-1)

    def push(self, value: jvm.Value):
        """Push value onto stack"""
        self.items.append(value)
        return self

    def __str__(self):
        if not self:
            return "ε"
        return "".join(f"({v})" for v in self.items)


@dataclass
class PC:
    """Program Counter - tracks current instruction"""
    method: jvm.AbsMethodID
    offset: int

    def __iadd__(self, delta):
        """In-place increment"""
        self.offset += delta
        return self

    def __add__(self, delta):
        """Create new PC with offset"""
        return PC(self.method, self.offset + delta)

    def jump_to(self, target_offset: int):
        """Jump to target offset"""
        self.offset = target_offset

    def __str__(self):
        return f"{self.method}:{self.offset}"


@dataclass
class Frame:
    """Stack frame - λ, σ, ι from operational semantics"""
    locals: dict[int, jvm.Value]  # λ - local variables
    stack: Stack  # σ - operand stack
    pc: PC  # ι - program counter

    def __str__(self):
        locals_str = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals_str}}}, {self.stack}, {self.pc}>"


@dataclass
class Bytecode:
    """Bytecode context - bc from operational semantics"""
    suite: Suite
    methods: dict[jvm.AbsMethodID, list[opcode.Opcode]] = field(default_factory=dict)
    offset_maps: dict[jvm.AbsMethodID, dict[int, int]] = field(default_factory=dict)

    def __getitem__(self, pc: PC) -> opcode.Opcode:
        """Get bytecode instruction at PC: bc[ι]"""
        if pc.method not in self.methods:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes
            self.offset_maps[pc.method] = {op.offset: i for i, op in enumerate(opcodes)}
        
        # pc.offset is already an index into the list, not a bytecode offset
        if pc.offset < 0 or pc.offset >= len(self.methods[pc.method]):
            raise RuntimeError(f"Invalid index {pc.offset} in {pc.method} (max {len(self.methods[pc.method])})")
        
        return self.methods[pc.method][pc.offset]
    
    def offset_to_index(self, method: jvm.AbsMethodID, offset: int) -> int:
        """Convert bytecode offset to list index"""
        if method not in self.offset_maps:
            # Trigger loading
            opcodes = list(self.suite.method_opcodes(method))
            self.methods[method] = opcodes
            self.offset_maps[method] = {op.offset: i for i, op in enumerate(opcodes)}
        
        index = self.offset_maps[method].get(offset)
        if index is None:
            raise RuntimeError(f"Invalid offset {offset} in {method}")
        return index


@dataclass
class State:
    """Complete program state - ⟨η, μ⟩ from operational semantics"""
    heap: dict[int, jvm.Value]  # η - heap memory
    frames: Stack  # μ - call stack
    next_addr: int = 1000  # Next available heap address

    def alloc(self, value: jvm.Value) -> int:
        """Allocate value on heap, return reference"""
        addr = self.next_addr
        self.next_addr += 1
        self.heap[addr] = value
        return addr

    def __str__(self):
        if not self.frames:
            return "<empty>"
        return f"State(frames={len(self.frames.items)}, heap={len(self.heap)})"


# ============================================================================
# Interpreter - implements bc ⊢ s → s' 
# ============================================================================

class Interpreter:
    """
    JVM Bytecode Interpreter implementing operational semantics.
    
    Judgment: bc ⊢ ⟨η, μ⟩ → ⟨η', μ'⟩ | ok | err('msg')
    """

    def __init__(self, suite: Suite, verbose: bool = False):
        self.bc = Bytecode(suite)
        self.verbose = verbose
        self.step_count = 0

    def step(self, state: State) -> State | str:
        """
        Single step execution: bc ⊢ s → s'
        
        Returns:
            - State: next state
            - "ok": successful termination
            - "error_msg": error termination
        """
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

    def _execute_opcode(self, op: opcode.Opcode, state: State) -> Optional[State | str]:
        """Execute single opcode based on operational semantics"""
        frame = state.frames.peek()

        match op:
            # ===== Push constant =====
            # bc[ι] = (push:I v)
            # ──────────────────────────────────── (pushI)
            # bc ⊢ ⟨λ, σ, ι⟩ → ⟨λ, σ(int v), ι+1⟩
            case opcode.Push(value=v):
                frame.stack.push(v)
                frame.pc += 1

            # ===== Load from locals =====
            # bc[ι] = (load:I n)    (int v) = λ[n]
            # ──────────────────────────────────── (loadI)
            # bc ⊢ ⟨λ, σ, ι⟩ → ⟨λ, σ(int v), ι+1⟩
            case opcode.Load(type=t, index=n):
                v = frame.locals.get(n)
                if v is None:
                    return f"uninitialized local variable {n}"
                frame.stack.push(v)
                frame.pc += 1

            # ===== Store to locals =====
            # bc[ι] = (store:I n)
            # ──────────────────────────────────── (storeI)
            # bc ⊢ ⟨λ, σ(int v), ι⟩ → ⟨λ[n←v], σ, ι+1⟩
            case opcode.Store(type=t, index=n):
                v = frame.stack.pop()
                frame.locals[n] = v
                frame.pc += 1

            # ===== Binary operations =====
            case opcode.Binary(type=jvm.Int(), operant=op_type):
                v2 = frame.stack.pop()
                v1 = frame.stack.pop()
                
                if v2.value == 0 and op_type in (opcode.BinaryOpr.Div, opcode.BinaryOpr.Rem):
                    return "divide by zero"
                
                match op_type:
                    case opcode.BinaryOpr.Add:
                        result = v1.value + v2.value
                    case opcode.BinaryOpr.Sub:
                        result = v1.value - v2.value
                    case opcode.BinaryOpr.Mul:
                        result = v1.value * v2.value
                    case opcode.BinaryOpr.Div:
                        result = int(v1.value / v2.value)
                    case opcode.BinaryOpr.Rem:
                        result = v1.value % v2.value
                    case _:
                        return f"unsupported binary operation {op_type}"
                
                frame.stack.push(jvm.Value.int(result))
                frame.pc += 1

            # ===== Duplicate top of stack =====
            # bc[ι] = (dup 1)
            # ──────────────────────────────────── (dup1)
            # bc ⊢ ⟨λ, σ(v), ι⟩ → ⟨λ, σ(v)(v), ι+1⟩
            case opcode.Dup(words=1):
                v = frame.stack.peek()
                frame.stack.push(v)
                frame.pc += 1

            # ===== Array operations =====
            case opcode.NewArray(type=t, dim=1):
                length = frame.stack.pop()
                if length.value < 0:
                    return "negative array size"
                
                # Create array on heap (use list, not tuple for mutability)
                arr_list = [self._default_value(t).value for _ in range(length.value)]
                arr = jvm.Value(jvm.Array(t), arr_list)
                addr = state.alloc(arr)
                frame.stack.push(jvm.Value(jvm.Reference(), addr))
                frame.pc += 1

            case opcode.ArrayStore(type=t):
                value = frame.stack.pop()
                index = frame.stack.pop()
                arrayref = frame.stack.pop()
                
                if arrayref.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.value]
                # Ensure array value is a list
                if not isinstance(arr.value, list):
                    arr.value = list(arr.value)
                
                if index.value < 0 or index.value >= len(arr.value):
                    return "out of bounds"
                
                arr.value[index.value] = value.value
                frame.pc += 1

            case opcode.ArrayLoad(type=t):
                index = frame.stack.pop()
                arrayref = frame.stack.pop()
                
                if arrayref.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.value]
                if index.value < 0 or index.value >= len(arr.value):
                    return "out of bounds"
                
                elem = arr.value[index.value]
                frame.stack.push(jvm.Value(t, elem))
                frame.pc += 1

            case opcode.ArrayLength():
                arrayref = frame.stack.pop()
                if arrayref.value is None:
                    return "null pointer"
                
                arr = state.heap[arrayref.value]
                frame.stack.push(jvm.Value.int(len(arr.value)))
                frame.pc += 1

            # ===== Conditional branches =====
            case opcode.If(condition=cond, target=target):
                v2 = frame.stack.pop()
                v1 = frame.stack.pop()
                
                jump = False
                match cond:
                    case "eq": jump = v1.value == v2.value
                    case "ne": jump = v1.value != v2.value
                    case "lt": jump = v1.value < v2.value
                    case "le": jump = v1.value <= v2.value
                    case "gt": jump = v1.value > v2.value
                    case "ge": jump = v1.value >= v2.value
                
                if jump:
                    idx = self.bc.offset_to_index(frame.pc.method, target)
                    frame.pc.offset = idx
                else:
                    frame.pc += 1

            case opcode.Ifz(condition=cond, target=target):
                v = frame.stack.pop()
                
                jump = False
                match cond:
                    case "eq": jump = v.value == 0 or v.value is None
                    case "ne": jump = v.value != 0 and v.value is not None
                    case "lt": jump = v.value < 0
                    case "le": jump = v.value <= 0
                    case "gt": jump = v.value > 0
                    case "ge": jump = v.value >= 0
                    case "is": jump = v.value is None
                    case "isnot": jump = v.value is not None
                
                if jump:
                    idx = self.bc.offset_to_index(frame.pc.method, target)
                    frame.pc.offset = idx
                else:
                    frame.pc += 1

            case opcode.Goto(target=target):
                idx = self.bc.offset_to_index(frame.pc.method, target)
                frame.pc.offset = idx

            # ===== Increment local variable =====
            case opcode.Incr(index=n, amount=amt):
                v = frame.locals.get(n, jvm.Value.int(0))
                frame.locals[n] = jvm.Value.int(v.value + amt)
                frame.pc += 1

            # ===== Object creation =====
            case opcode.New(classname=cn):
                # Create uninitialized object
                obj = jvm.Value(jvm.Reference(), {"class": cn, "fields": {}})
                addr = state.alloc(obj)
                frame.stack.push(jvm.Value(jvm.Reference(), addr))
                frame.pc += 1

            # ===== Field access =====
            case opcode.Get(static=True, field=f):
                # Special case: $assertionsDisabled is always false
                if f.extension.name == "$assertionsDisabled" or f.extension.name == "assertionsDisabled":
                    frame.stack.push(jvm.Value.boolean(False))
                else:
                    # For now, push default value
                    frame.stack.push(self._default_value(f.extension.type))
                frame.pc += 1

            case opcode.Get(static=False, field=f):
                objectref = frame.stack.pop()
                if objectref.value is None:
                    return "null pointer"
                # Push field value or default
                frame.stack.push(self._default_value(f.extension.type))
                frame.pc += 1

            # ===== Type casting =====
            case opcode.Cast(from_=from_t, to_=to_t):
                v = frame.stack.pop()
                # Simple cast - just change type wrapper
                frame.stack.push(jvm.Value(to_t, v.value))
                frame.pc += 1

            # ===== Return =====
            # bc[ι] = (return:I)    μ = ε
            # ──────────────────────────────────── (returnε)
            # bc ⊢ ⟨η, ε⟨λ, σ(int v), ι⟩⟩ → ok
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

            # ===== Throw exception =====
            case opcode.Throw():
                exc = frame.stack.pop()
                if exc.value is None:
                    return "null pointer"
                return "assertion error"

            # ===== Method invocation (simplified) =====
            case opcode.InvokeVirtual() | opcode.InvokeStatic() | opcode.InvokeSpecial() | opcode.InvokeInterface():
                # For simplicity, pop arguments and push mock result
                method = op.method
                num_args = len(method.extension.params)
                
                # Pop arguments
                for _ in range(num_args):
                    frame.stack.pop()
                
                # Pop receiver for non-static
                if not isinstance(op, opcode.InvokeStatic):
                    receiver = frame.stack.pop()
                    if receiver.value is None:
                        return "null pointer"
                
                # Push return value if not void
                if method.extension.return_type is not None:
                    frame.stack.push(self._default_value(method.extension.return_type))
                
                frame.pc += 1

            case _:
                return f"unsupported opcode: {op}"

        return None  # Continue execution

    def _default_value(self, t: jvm.Type) -> jvm.Value:
        """Get default value for type"""
        match t:
            case jvm.Int() | jvm.Byte() | jvm.Short() | jvm.Char():
                return jvm.Value.int(0)
            case jvm.Boolean():
                return jvm.Value.boolean(False)
            case jvm.Long():
                return jvm.Value(jvm.Long(), 0)
            case jvm.Float():
                return jvm.Value(jvm.Float(), 0.0)
            case jvm.Double():
                return jvm.Value(jvm.Double(), 0.0)
            case _:
                return jvm.Value(jvm.Reference(), None)

    def execute(self, methodid: jvm.AbsMethodID, args: list[jvm.Value]) -> str:
        """
        Execute method with arguments.
        
        Returns final result: "ok" or error message
        """
        # Create initial frame
        locals = {i: arg for i, arg in enumerate(args)}
        frame = Frame(
            locals=locals,
            stack=Stack.empty(),
            pc=PC(methodid, 0)
        )
        
        # Create initial state
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
                # Terminated
                if self.verbose:
                    print(f"\n=== Result: {result} ===", file=sys.stderr)
                return result
        
        return "timeout"


# ============================================================================
# Main entry point
# ============================================================================

def main():
    if len(sys.argv) < 3:
        print("Usage: python interpreter.py <method> <input>", file=sys.stderr)
        print('Example: python interpreter.py "jpamb.cases.Simple.assertFalse:()V" "()"', file=sys.stderr)
        sys.exit(1)
    
    method_str = sys.argv[1]
    input_str = sys.argv[2]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    
    # Find workspace root
    script_dir = Path(__file__).parent
    workspace = script_dir.parent
    
    # Load suite
    suite = Suite(workspace)
    
    # Parse method
    try:
        methodid = jvm.AbsMethodID.decode(method_str)
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
    interp = Interpreter(suite, verbose=verbose)
    result = interp.execute(methodid, args)
    
    # Print result
    print(result)
    
    # Exit with appropriate code
    sys.exit(0 if result == "ok" else 1)


if __name__ == "__main__":
    main()
