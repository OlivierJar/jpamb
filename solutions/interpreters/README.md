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
--verbose shows full output