"""
jpamb.jvm.base

This module provides primitives to talk about the contents of java bytefiles,
as well as names and types.

It is recommended to import this module qualified

from jpamb import jvm

"""

from collections import namedtuple
from functools import total_ordering
import re
from abc import ABC
from dataclasses import dataclass, field
from typing import *  # type: ignore
from enum import Enum


@dataclass(frozen=True, order=True)
class ClassName:
    """The name of a class, inner classes must use the $ syntax"""

    _as_string: str

    @property
    def packages(self) -> list[str]:
        """Get a list of packages"""
        return self.parts[:-1]

    @property
    def name(self) -> str:
        """Get the unqualified name"""
        return self.parts[-1]

    @property
    def parts(self) -> list[str]:
        """Get the elements of the name"""
        return self._as_string.split(".")

    def encode(self) -> str:
        return self._as_string

    def slashed(self) -> str:
        return "/".join(self.parts)

    def dotted(self) -> str:
        return self._as_string

    def __str__(self) -> str:
        return self.dotted()

    @staticmethod
    def decode(input: str) -> "ClassName":
        return ClassName(input)

    @staticmethod
    def from_parts(*args: str) -> "ClassName":
        return ClassName(".".join(args))


@total_ordering
class Type(ABC):
    """A jvm type"""

    def encode(self) -> str: ...

    def is_stacktype(self) -> bool:
        """Check if this type is valid as a stack type"""
        return True  # Default: most types are valid stack types

    @staticmethod
    def decode(input) -> tuple["Type", str]:
        r, stack = None, []
        i = 0
        r = None
        while i < len(input):
            match input[i]:
                case "Z":
                    r = Boolean()
                case "I":
                    r = Int()
                case "B":
                    r = Byte()
                case "C":
                    r = Char()
                case "S":
                    r = Short()
                case "J":
                    r = Long()
                case "F":
                    r = Float()
                case "D":
                    r = Double()
                case "L":  # Object type (e.g., Ljava/lang/String;)
                    end_idx = input.find(";", i)
                    if end_idx == -1:
                        raise ValueError(f"Malformed object type: missing semicolon in {input[i:]}")
                    # Extract class name 
                    classname_str = input[i+1:end_idx]
                    classname = ClassName(classname_str.replace("/", "."))
                    r = Object(classname)
                    i = end_idx 
                case "[":  # ]
                    stack.append(Array)
                    i += 1
                    continue # Position at semicolon, will be incremented below
                case _:
                    raise ValueError(f"Unknown type {input[i]}")
            break
        else:
            raise ValueError(f"Could not decode {input}")

        assert r is not None

        for k in reversed(stack):
            r = k(r)

        return r, input[i + 1 :]

    def __lt__(self, other):
        return self.encode() <= other.encode()

    def __eq__(self, other):
        return self.encode() <= other.encode()

    @staticmethod
    def from_json(json: str | dict) -> "Type":
        # Handle dict type representations
        if isinstance(json, dict):
            return Type.from_json_type(json)

        match json:
            case "integer":
                return Int()
            case "int":
                return Int()
            case "char":
                return Char()
            case "short":
                return Short()
            case "ref":
                return Reference()
            case "boolean":
                return Boolean()
            case "string":
                return Object(ClassName("java.lang.String"))
            case typestr:
                raise NotImplementedError(f"Not yet implemented {typestr}")

    @staticmethod
    def from_json_type(json: dict | str) -> "Type":
        # Handle string type representations
        if isinstance(json, str):
            return Type.from_json(json)

        if "base" in json:
            return Type.from_json(json["base"])
        match json["kind"]:
            case "array":
                array_type = json["type"]
                if isinstance(array_type, str):
                    element_type = Type.from_json(array_type)
                else:
                    element_type = Type.from_json_type(array_type)
                return Array(element_type)
            case "class":
                # Handle Object types (e.g., java/lang/String)
                classname_str = json["name"].replace("/", ".")
                return Object(ClassName(classname_str))

        raise NotImplementedError(f"Not yet implemented {json}")

    def __str__(self) -> str:
        return self.encode()


@dataclass(frozen=True)
class Boolean(Type):
    """
    A boolean
    """

    _instance = None

    def __new__(cls) -> "Boolean":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "Z"


@dataclass(frozen=True)
class Int(Type):
    """
    A 32bit signed integer
    """

    _instance = None

    def __new__(cls) -> "Int":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "I"


@dataclass(frozen=True)
class Byte(Type):
    """
    An 8bit signed integer
    """

    _instance = None

    def __new__(cls) -> "Byte":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "B"


@dataclass(frozen=True)
class Char(Type):
    """
    An 16bit character
    """

    _instance = None

    def __new__(cls) -> "Char":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "C"


@dataclass(frozen=True)
class Short(Type):
    """
    An 16bit signed integer
    """

    _instance = None

    def __new__(cls) -> "Short":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "S"


@dataclass(frozen=True, order=True)
class Reference(Type):
    """An unknown reference"""

    _instance = None

    def __new__(cls) -> "Reference":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "A"


@dataclass(frozen=True, order=True)
class Object(Type):
    """
    A list of types
    """

    _instance = dict()

    def __new__(cls, subtype) -> "Array":
        if subtype not in cls._instance:
            cls._instance[subtype] = super().__new__(cls)
        return cls._instance[subtype]

    name: ClassName

    def __post_init__(self):
        assert self.name is not None

    def encode(self):
        return "L" + self.name.slashed() + ";"  # ]


@dataclass(frozen=True, order=True)
class Array(Type):
    """
    A list of types
    """

    _instance = dict()

    def __new__(cls, subtype) -> "Array":
        if subtype not in cls._instance:
            cls._instance[subtype] = super().__new__(cls)
        return cls._instance[subtype]

    contains: Type

    def __post_init__(self):
        assert self.contains is not None

    def encode(self):
        return "[" + self.contains.encode()  # ]


@dataclass(frozen=True)
class Long(Type):
    """
    A 64bit signed integer
    """

    _instance = None

    def __new__(cls) -> "Long":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "J"  # J is used for long in JVM


@dataclass(frozen=True)
class Float(Type):
    """
    A 32bit floating point number
    """

    _instance = None

    def __new__(cls) -> "Float":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "F"


@dataclass(frozen=True)
class Double(Type):
    """
    A 64bit floating point number
    """

    _instance = None

    def __new__(cls) -> "Double":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def encode(self):
        return "D"


@dataclass(frozen=True, order=True)
class ParameterType:
    """A list of parameters types"""

    _elements: tuple[Type, ...]

    def __getitem__(self, index):
        return self._elements.__getitem__(index)

    def __len__(self):
        return self._elements.__len__()

    def encode(self):
        return "".join(e.encode() for e in self._elements)

    @staticmethod
    def decode(input: str) -> "ParameterType":
        params = []
        while input:
            (tt, input) = Type.decode(input)
            params.append(tt)

        return ParameterType(tuple(params))

    @staticmethod
    def from_json(inputs: list[dict | str], annotated: bool = False) -> "ParameterType":
        params = []
        for t in inputs:
            if isinstance(t, str):
                # Handle simple string type representation
                # Could be either JVM encoding (I, Z, etc.) or JSON names (int, boolean, etc.)
                try:
                    tt, _ = Type.decode(t)
                except ValueError:
                    # Try as JSON type name
                    tt = Type.from_json(t)
            elif isinstance(t, dict):
                # Handle nested type structure
                if "type" in t:
                    # t is a parameter with a type field
                    type_spec = t["type"]
                    if isinstance(type_spec, dict):
                        tt = Type.from_json_type(type_spec)
                    else:
                        # Could be string type
                        tt = Type.from_json_type(type_spec)
                else:
                    # t is the type spec itself
                    tt = Type.from_json_type(t)
            else:
                raise ValueError(f"Unexpected type format: {t}")
            params.append(tt)

        return ParameterType(tuple(params))


METHOD_ID_RE_RAW = r"(?P<method_name>.*)\:\((?P<params>.*)\)(?P<return>.*)"
METHOD_ID_RE = re.compile(METHOD_ID_RE_RAW)


@dataclass(frozen=True, order=True)
class MethodID:
    """A method ID consist of a name, a list of parameter types and a return type."""

    name: str
    params: ParameterType
    return_type: Type | None

    @staticmethod
    def decode(input: str):
        if (match := METHOD_ID_RE.match(input)) is None:
            raise ValueError("invalid method name: %r", input)

        return_type = None
        if match["return"] != "V":
            return_type, more = Type.decode(match["return"])
            if more:
                raise ValueError(
                    f"could not decode method id, bad return type {match['return']!r}"
                )

        return MethodID(
            name=match["method_name"],
            params=ParameterType.decode(match["params"]),
            return_type=return_type,
        )

    def encode(self) -> str:
        rt = self.return_type.encode() if self.return_type is not None else "V"
        return f"{self.name}:({self.params.encode()}){rt}"


class Encodable(Protocol):
    def encode(self) -> str: ...


ABSOLUTE_RE = re.compile(r"(?P<class_name>.+)\.(?P<rest>.*)")


@dataclass(frozen=True, order=True)
class Absolute[T: Encodable]:
    classname: ClassName
    extension: T

    @staticmethod
    def decode(input, decode: Callable[[str], T]) -> "Absolute":
        if (match := ABSOLUTE_RE.match(input)) is None:
            raise ValueError("invalid absolute method name: %r", input)

        return Absolute(ClassName.decode(match["class_name"]), decode(match["rest"]))

    def encode(self) -> str:
        return f"{self.classname.encode()}.{self.extension.encode()}"

    def __str__(self):
        return self.encode()


@dataclass(frozen=True, order=True)
class Value:
    type: Type
    value: object

    @staticmethod
    def decode_many(input) -> list["Value"]:
        vp = ValueParser(input)
        values = vp.parse_comma_seperated_values()
        vp.eof()
        return values

    @staticmethod
    def decode(input) -> list["Value"]:
        vp = ValueParser(input)
        value = vp.parse_comma_seperated_values()
        vp.eof()
        return value

    def encode(self) -> str:
        if self.value is None:
            return "null"
        
        match self.type:
            case Boolean():
                return "true" if self.value else "false"
            case Int():
                return str(self.value)
            case Char():
                return f"'{self.value}'"
            case Array(content):
                match content:
                    case Int():
                        ints = ", ".join(map(str, self.value))
                        return f"[I:{ints}]"
                    case Char():
                        chars = ", ".join(map(lambda a: f"'{a}'", self.value))
                        return f"[C:{chars}]"
                    case _:
                        raise NotImplemented()
            case Object(name):
                # Handle String objects
                if "String" in str(name):
                    return f'"{self.value}"'
                else:
                    raise NotImplementedError(f"Object encoding not implemented for {name}")

        return str(self.value)

    @classmethod
    def int(cls, n: int) -> Self:
        return cls(Int(), n)

    @classmethod
    def boolean(cls, n: bool) -> Self:
        return cls(Boolean(), n)

    @classmethod
    def char(cls, char: str) -> Self:
        assert len(char) == 1
        return cls(Char(), char)

    @classmethod
    def array(cls, type: Type, content: Iterable) -> Self:
        return cls(Array(type), tuple(content))

    @classmethod
    def from_json(cls, json: dict | None) -> Self:
        if json is None:
            return cls(Reference(), None)
        type = Type.from_json(json["type"])
        return cls(type, json["value"])

    def __str__(self) -> str:
        return f"{self.value}:{self.type}"


@dataclass
class ValueParser:
    Token = namedtuple("Token", "kind value")

    input: str
    head: Optional["ValueParser.Token"]
    _tokens: Iterator["ValueParser.Token"]

    def __init__(self, input) -> None:
        self.input = input
        self._tokens = ValueParser.tokenize(input)
        self.next()

    @staticmethod
    def tokenize(string):
        token_specification = [
            ("OPEN_ARRAY", r"\[[IC]:"),
            ("CLOSE_ARRAY", r"\]"),
            ("STRING", r'"(?:[^"\\]|\\.)*"'),  # String literals with escape support
            ("INT", r"-?\d+"),
            ("BOOL", r"true|false"),
            ("CHAR", r"'[^']'"),
            ("NULL", r"null"),
            ("COMMA", r","),
            ("SKIP", r"[ \t]+"),
        ]
        tok_regex = "|".join(f"(?P<{n}>{m})" for n, m in token_specification)

        for m in re.finditer(tok_regex, string):
            kind, value = m.lastgroup, m.group()
            if kind == "SKIP":
                continue
            yield ValueParser.Token(kind, value)

    @staticmethod
    def parse(string) -> list[Value]:
        return ValueParser(string).parse_comma_seperated_values()

    def next(self):
        try:
            self.head = next(self._tokens)
        except StopIteration:
            self.head = None

    def expected(self, expected) -> NoReturn:
        raise ValueError(f"Expected {expected} but got {self.head} in {self.input}")

    def expect(self, expect) -> Token:
        head = self.head
        if head is None:
            self.expected(repr(expect))
        elif expect != head.kind:
            self.expected(repr(expect))
        self.next()
        return head

    def eof(self):
        if self.head is None:
            return
        self.expected("end of file")

    def parse_value(self):
        next = self.head or self.expected("token")
        match next.kind:
            case "INT":
                return Value.int(self.parse_int())
            case "CHAR":
                return Value.char(self.parse_char())
            case "BOOL":
                return Value.boolean(self.parse_bool())
            case "STRING":
                return self.parse_string()
            case "NULL":
                return self.parse_null()
            case "OPEN_ARRAY":
                return self.parse_array()
        self.expected("value")

    def parse_int(self):
        tok = self.expect("INT")
        return int(tok.value)

    def parse_bool(self):
        tok = self.expect("BOOL")
        return tok.value == "true"

    def parse_char(self):
        tok = self.expect("CHAR")
        return tok.value[1]

    def parse_string(self):
        tok = self.expect("STRING")
        # Remove surrounding quotes and handle escape sequences
        string_value = tok.value[1:-1]  # Remove quotes
        # Unescape common escape sequences
        string_value = string_value.replace('\\"', '"')
        string_value = string_value.replace('\\n', '\n')
        string_value = string_value.replace('\\t', '\t')
        string_value = string_value.replace('\\\\', '\\')
        return Value(Object(ClassName.decode("java/lang/String")), string_value)

    def parse_null(self):
        self.expect("NULL")
        return Value(Reference(), None)

    def parse_array(self):
        key = self.expect("OPEN_ARRAY")
        if key.value == "[I:":  # ]
            type = Array(Int())
            parser = self.parse_int
        elif key.value == "[C:":  # ]
            type = Array(Char())
            parser = self.parse_char
        else:
            self.expected("int or char array")

        inputs = self.parse_comma_seperated_values(parser, "CLOSE_ARRAY")

        self.expect("CLOSE_ARRAY")

        return Value(type, tuple(inputs))

    def parse_comma_seperated_values(self, parser=None, end_by=None):
        if self.head is None:
            return []

        if end_by is not None and self.head.kind == end_by:
            return []

        parser = parser or self.parse_value
        inputs = [parser()]

        while self.head and self.head.kind == "COMMA":
            self.next()
            inputs.append(parser())

        return inputs


@dataclass(frozen=True, order=True)
class FieldID:
    """A field ID consists of a name and a type."""

    name: str
    type: Type

    def encode(self) -> str:
        return f"{self.name}:{self.type.encode()}"

    @staticmethod
    def decode(input: str) -> "FieldID":
        if ":" not in input:
            raise ValueError(f"invalid field id format: {input}")
        name, type_str = input.split(":", 1)
        type_obj, remaining = Type.decode(type_str)
        if remaining:
            raise ValueError(f"extra characters in field type: {remaining}")
        return FieldID(name=name, type=type_obj)

    def __str__(self) -> str:
        return self.encode()


class AbsMethodID(Absolute[MethodID]):
    """Absolute method identifier (ClassName.MethodID)"""

    @classmethod
    def decode(cls, input) -> Self:
        return super().decode(input, MethodID.decode)

    @property
    def methodid(self):
        return self.extension

    @classmethod
    def from_json(cls, json: dict) -> Self:
        return cls(
            classname=ClassName.decode(json["ref"]["name"]),
            extension=MethodID(
                name=json["name"],
                params=ParameterType.from_json(json["args"]),
                return_type=(
                    Type.from_json(json["returns"])
                    if json["returns"] is not None
                    else None
                ),
            ),
        )


class AbsFieldID(Absolute[FieldID]):
    """Absolute field identifier (ClassName.FieldID)"""

    @classmethod
    def decode(cls, input) -> Self:
        return super().decode(input, FieldID.decode)

    @property
    def fieldid(self):
        return self.extension


# String Provenance and Abstract Domains

class StringProvenance(Enum):
    """Tracks the origin and trustworthiness of string data"""
    
    CONSTANT = "constant"
    USER_INPUT = "user_input"
    COMPUTED = "computed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AbstractString:
    """Abstract string representation with provenance tracking"""
    
    value: Optional[str]
    provenance: StringProvenance
    tainted: bool
    operations: tuple[str, ...] = field(default_factory=tuple)
    
    @staticmethod
    def constant(s: str) -> "AbstractString":
        """Create a constant string (safe)"""
        return AbstractString(s, StringProvenance.CONSTANT, False, ())
    
    @staticmethod
    def user_input(s: Optional[str] = None) -> "AbstractString":
        """Create a user input string (tainted)"""
        return AbstractString(s, StringProvenance.USER_INPUT, True, ())
    
    @staticmethod
    def unknown() -> "AbstractString":
        """Create an unknown string"""
        return AbstractString(None, StringProvenance.UNKNOWN, True, ())
    
    def concat(self, other: "AbstractString") -> "AbstractString":
        """Concatenate with another abstract string"""
        new_value = None
        if self.value is not None and other.value is not None:
            new_value = self.value + other.value
        
        tainted = self.tainted or other.tainted
        ops = self.operations + other.operations + (f"concat({self.value}, {other.value})",)
        
        return AbstractString(new_value, StringProvenance.COMPUTED, tainted, ops)
    
    def substring(self, start: int, end: Optional[int] = None) -> "AbstractString":
        """Extract substring"""
        new_value = None
        if self.value is not None:
            new_value = self.value[start:end]
        
        ops = self.operations + (f"substring({start}, {end})",)
        
        return AbstractString(new_value, StringProvenance.COMPUTED, self.tainted, ops)
    
    def __str__(self) -> str:
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
        """Check if this query is vulnerable to SQL injection"""
        return self.query_string.tainted and not self.is_parameterized
    
    def get_vulnerability_details(self) -> str:
        """Get detailed vulnerability report"""
        if not self.is_vulnerable():
            return "No SQL injection vulnerability detected."
        
        details = [
            "🚨 SQL INJECTION VULNERABILITY!!!!! 🚨",
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
    """Wraps jvm.Value with additional string analysis information"""
    
    jvm_value: "Value"
    abstract_string: Optional[AbstractString] = None
    
    @staticmethod
    def from_jvm(v: "Value") -> "EnhancedValue":
        """Create from regular JVM value"""
        abs_str = None
        
        if isinstance(v.type, Object) and "String" in str(v.type.name):
            if isinstance(v.value, str):
                abs_str = AbstractString.constant(v.value)
            else:
                abs_str = AbstractString.unknown()
        
        return EnhancedValue(v, abs_str)
    
    @staticmethod
    def string_constant(s: str) -> "EnhancedValue":
        """Create a constant string value"""
        return EnhancedValue(
            Value(Object(ClassName.decode("java/lang/String")), s),
            AbstractString.constant(s)
        )
    
    @staticmethod
    def string_input(s: str) -> "EnhancedValue":
        """Create a user input string value"""
        return EnhancedValue(
            Value(Object(ClassName.decode("java/lang/String")), s),
            AbstractString.user_input(s)
        )
    
    def is_string(self) -> bool:
        """Check if this value represents a string"""
        return self.abstract_string is not None
    
    def __str__(self) -> str:
        if self.abstract_string:
            return f"{self.jvm_value.value} [{self.abstract_string.provenance.value}]"
        return str(self.jvm_value)


# ============================================================================
# Interpreter State Components
# ============================================================================

@dataclass
class Stack[T]:
    """Operand stack - stores intermediate computation values"""
    
    items: list[T] = field(default_factory=list)

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls) -> "Stack[T]":
        return cls([])

    def peek(self) -> T:
        """Look at top of stack without removing"""
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items[-1]

    def pop(self) -> T:
        """Remove and return top of stack"""
        if not self.items:
            raise RuntimeError("Stack underflow")
        return self.items.pop(-1)

    def push(self, value: T) -> "Stack[T]":
        """Push value onto stack"""
        self.items.append(value)
        return self

    def __str__(self) -> str:
        if not self:
            return "ε"
        return "".join(f"({v})" for v in self.items)


@dataclass
class PC:
    """Program Counter - tracks current instruction"""
    
    method: "Absolute[MethodID]"
    offset: int

    def __iadd__(self, delta: int) -> "PC":
        """In-place increment"""
        self.offset += delta
        return self

    def __add__(self, delta: int) -> "PC":
        """Create new PC with offset"""
        return PC(self.method, self.offset + delta)

    def jump_to(self, target_offset: int) -> None:
        """Jump to target offset"""
        self.offset = target_offset

    def __str__(self) -> str:
        return f"{self.method}:{self.offset}"


@dataclass
class Frame[T]:
    """Stack frame - λ, σ, ι from operational semantics"""
    
    locals: dict[int, T]
    stack: Stack[T]
    pc: PC

    def __str__(self) -> str:
        locals_str = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals_str}}}, {self.stack}, {self.pc}>"
