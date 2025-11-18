### Example 1: Basic Test
```bash
uv run python string_interpreter.py \
    "jpamb.cases.Simple.assertFalse:()V" "()"
```
### Example 2: safeString 

```bash
uv run string_interpreter.py "jpamb.cases.StringSQL.safeString:(Ljava/lang/String;)V" '("hello
")' --verbose 
```

### Example 3

```bash
uv run jpamb interpret -W solutions/interpreters/string_interpreter.py
```

### Example 4: run fuzzer 

```bash
uv run jpamb test -W solutions/sql_fuzzer.py
```