#Verify Everytyhing works
    uv run jpamb checkhealth


#Run a case (Found in src/main/java/jpamb/cases)
    python ./project.py "jpamb.cases.Simple.divideByZero:()I"


#Test the analyzer
    uv run jpamb test --filter "Simple" <your-intepreter> project.py
        or with python:
    uv run jpamb test --filter "Simple" --with-python project.py

#Test the interpreter
    $ uv run interpreter.py "jpamb.cases.Simple.assertInteger:(I)V" "(1)"
    $ uv run jpamb interpret -W --filter Simple interpreter.py
#Improving Analyzer
    1.Find the class and method in the class in src/main/java/jpamb/cases/<class>.java.
        you might use a regular expression to find the content of a method. r"assertFalse.*{([^}]*)}" and pythons re library.

    2.Now, Look at java code and make better prediction
    Useful:
        uv run jpamb plot --report <your-report.json> 
    If multiple reports: 
        uv run jpamb plot --directory <your-report-directory> 

#Using JPAMB Library

    Sourcefile
        Use: src=jpamb.sourcefile(methodid)
            txt = open(src).read()
            to get the sourcefile of a method or class

#Testing the analyzer

    # Test on simple cases first
    uv run jpamb test --filter "Simple" -W my_analyzer.py

    # Test on all cases  
    uv run jpamb test -W my_analyzer.py

    # Generate final evaluation report
    uv run jpamb evaluate -W my_analyzer.py > my_results.json

#Advanced: Analyzing Approaches
    Source Code Analysis
        Java source code is in src/main/java/jpamb/cases/
        Example: solutions/syntaxer.py uses tree-sitter to parse Java

    Bytecode Analysis
        Pre-decompiled JVM bytecode in target/decompiled/ directory
        Example: solutions/bytecoder.py analyzes JVM opcodes
        Python interface: lib/jpamb/jvm/opcode.py

    Statistics or Cheat-Based
        Historical data in target/stats/distribution.csv
        Example: solutions/apriori.py uses statistical patterns

#Adding Cases

To get started with adding your own cases, please make sure to download either docker or podman (recommended).

You can add your own cases to the benchmark suite by adding them in the source folder:
    src/main/java/jpamb/cases
        ├── Arrays.java
        ├── Calls.java
        ├── Loops.java
        ├── Simple.java
        └── Tricky.java
Then Running:
$ uv run jpamb build