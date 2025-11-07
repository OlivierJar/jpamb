# Import necessary modules and classes
import jpamb
from jpamb import jvm
from dataclasses import dataclass

import sys
from loguru import logger

# Configure logger for debugging
logger.remove()
logger.add(sys.stderr, format="[{level}] {message}")

# Retrieve the method ID and input values for analysis
methodid, input = jpamb.getcase()


# Define the Program Counter (PC) class to track the current method and offset
@dataclass
class PC:
    method: jvm.AbsMethodID
    offset: int

    def __iadd__(self, delta):
        # Increment the offset by a given delta
        self.offset += delta
        return self

    def __add__(self, delta):
        # Return a new PC with an incremented offset
        return PC(self.method, self.offset + delta)

    def __str__(self):
        # String representation of the PC
        return f"{self.method}:{self.offset}"


# Define the Bytecode class to manage opcodes for methods
@dataclass
class Bytecode:
    suite: jpamb.Suite
    methods: dict[jvm.AbsMethodID, list[jvm.Opcode]]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        # Retrieve the opcode at the given program counter
        try:
            opcodes = self.methods[pc.method]
        except KeyError:
            # If not cached, fetch and cache the opcodes for the method
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes

        return opcodes[pc.offset]


# Define a generic stack class to manage stack operations
@dataclass
class Stack[T]:
    items: list[T]

    def __bool__(self) -> bool:
        # Check if the stack is non-empty
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        # Create an empty stack
        return cls([])

    def peek(self) -> T:
        # Peek at the top item of the stack
        return self.items[-1]

    def pop(self) -> T:
        # Pop the top item from the stack
        return self.items.pop(-1)

    def push(self, value):
        # Push a value onto the stack
        self.items.append(value)
        return self

    def __str__(self):
        # String representation of the stack
        if not self:
            return "ϵ"
        return "".join(f"{v}" for v in self.items)


# Initialize the suite and bytecode
suite = jpamb.Suite()
bc = Bytecode(suite, dict())


# Define the Frame class to represent a method frame
@dataclass
class Frame:
    locals: dict[int, jvm.Value]
    stack: Stack[jvm.Value]
    pc: PC

    def __str__(self):
        # String representation of the frame
        locals = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals}}}, {self.stack}, {self.pc}>"
