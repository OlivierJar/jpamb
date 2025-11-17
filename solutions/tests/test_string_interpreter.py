#!/usr/bin/env python3
"""
Test suite for the String-Aware Interpreter

This file contains unit tests and integration tests for the string interpreter,
demonstrating its capabilities in tracking string provenance and detecting
SQL injection vulnerabilities.
"""

import sys
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "lib"))

# Import from the string_interpreter module directly
import importlib.util
spec = importlib.util.spec_from_file_location("string_interpreter", 
                                               Path(__file__).parent.parent / "interpreters" / "string_interpreter.py")
string_interpreter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(string_interpreter)

AbstractString = string_interpreter.AbstractString
StringProvenance = string_interpreter.StringProvenance
SQLQuery = string_interpreter.SQLQuery
EnhancedValue = string_interpreter.EnhancedValue
StringInterpreter = string_interpreter.StringInterpreter


def test_abstract_string_constant():
    """Test constant string creation"""
    s = AbstractString.constant("SELECT * FROM users")
    assert s.value == "SELECT * FROM users"
    assert s.provenance == StringProvenance.CONSTANT
    assert s.tainted == False
    print("✓ Constant string test passed")


def test_abstract_string_user_input():
    """Test user input string creation"""
    s = AbstractString.user_input("admin")
    assert s.value == "admin"
    assert s.provenance == StringProvenance.USER_INPUT
    assert s.tainted == True
    print("✓ User input string test passed")


def test_string_concatenation_taint_propagation():
    """Test that taint propagates through concatenation"""
    safe = AbstractString.constant("SELECT * FROM ")
    tainted = AbstractString.user_input("users")
    
    result = safe.concat(tainted)
    
    assert result.tainted == True
    assert result.provenance == StringProvenance.COMPUTED
    assert result.value == "SELECT * FROM users"
    print("✓ Taint propagation test passed")


def test_string_concatenation_safe():
    """Test concatenation of two safe strings"""
    s1 = AbstractString.constant("Hello ")
    s2 = AbstractString.constant("World")
    
    result = s1.concat(s2)
    
    assert result.tainted == False
    assert result.value == "Hello World"
    print("✓ Safe concatenation test passed")


def test_substring_preserves_taint():
    """Test that substring operation preserves taint"""
    tainted = AbstractString.user_input("admin' OR '1'='1")
    
    result = tainted.substring(0, 5)
    
    assert result.tainted == True
    assert result.value == "admin"
    print("✓ Substring taint preservation test passed")


def test_sql_query_vulnerable():
    """Test SQL injection vulnerability detection"""
    tainted_string = AbstractString.user_input("admin")
    query = SQLQuery(
        query_string=tainted_string,
        is_parameterized=False
    )
    
    assert query.is_vulnerable() == True
    print("✓ SQL vulnerability detection test passed")


def test_sql_query_safe_parameterized():
    """Test that parameterized queries are considered safe"""
    tainted_string = AbstractString.user_input("admin")
    query = SQLQuery(
        query_string=tainted_string,
        is_parameterized=True
    )
    
    assert query.is_vulnerable() == False
    print("✓ Parameterized query safety test passed")


def test_sql_query_safe_constant():
    """Test that queries with only constants are safe"""
    safe_string = AbstractString.constant("SELECT * FROM users")
    query = SQLQuery(
        query_string=safe_string,
        is_parameterized=False
    )
    
    assert query.is_vulnerable() == False
    print("✓ Constant query safety test passed")


def test_operation_history():
    """Test that operation history is tracked"""
    s1 = AbstractString.constant("Hello")
    s2 = AbstractString.user_input("World")
    
    result = s1.concat(s2)
    result = result.substring(0, 10)
    
    assert len(result.operations) >= 2
    assert any("concat" in op for op in result.operations)
    assert any("substring" in op for op in result.operations)
    print("✓ Operation history test passed")


def test_enhanced_value_string_constant():
    """Test EnhancedValue creation from string constant"""
    value = EnhancedValue.string_constant("test")
    
    assert value.is_string() == True
    assert value.abstract_string.tainted == False
    assert value.jvm_value.value == "test"
    print("✓ EnhancedValue string constant test passed")


def test_enhanced_value_string_input():
    """Test EnhancedValue creation from user input"""
    value = EnhancedValue.string_input("test")
    
    assert value.is_string() == True
    assert value.abstract_string.tainted == True
    assert value.jvm_value.value == "test"
    print("✓ EnhancedValue string input test passed")


def test_complex_concatenation_chain():
    """Test complex chain of concatenations"""
    base = AbstractString.constant("SELECT * FROM users WHERE ")
    field = AbstractString.constant("username = '")
    user_input = AbstractString.user_input("admin")
    closing = AbstractString.constant("'")
    
    # Build query: SELECT * FROM users WHERE username = 'admin'
    query = base.concat(field).concat(user_input).concat(closing)
    
    assert query.tainted == True
    assert "admin" in query.value
    print("✓ Complex concatenation chain test passed")


def test_vulnerability_report():
    """Test vulnerability report generation"""
    tainted = AbstractString.user_input("admin' OR '1'='1")
    safe = AbstractString.constant("SELECT * FROM users WHERE username = '")
    query_str = safe.concat(tainted)
    
    query = SQLQuery(query_string=query_str, is_parameterized=False)
    
    report = query.get_vulnerability_details()
    
    assert "SQL INJECTION VULNERABILITY" in report
    assert "TAINTED" in report
    print("✓ Vulnerability report test passed")


def run_all_tests():
    """Run all unit tests"""
    print("\n" + "="*60)
    print("Running String Interpreter Unit Tests")
    print("="*60 + "\n")
    
    tests = [
        test_abstract_string_constant,
        test_abstract_string_user_input,
        test_string_concatenation_taint_propagation,
        test_string_concatenation_safe,
        test_substring_preserves_taint,
        test_sql_query_vulnerable,
        test_sql_query_safe_parameterized,
        test_sql_query_safe_constant,
        test_operation_history,
        test_enhanced_value_string_constant,
        test_enhanced_value_string_input,
        test_complex_concatenation_chain,
        test_vulnerability_report,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


def demo_sql_injection():
    """Demonstrate SQL injection detection"""
    print("\n" + "="*60)
    print("SQL Injection Detection Demo")
    print("="*60 + "\n")
    
    print("Scenario 1: Vulnerable Query (Direct Concatenation)")
    print("-" * 60)
    base = AbstractString.constant("SELECT * FROM users WHERE username = '")
    user_input = AbstractString.user_input("admin' OR '1'='1")
    closing = AbstractString.constant("'")
    
    query_str = base.concat(user_input).concat(closing)
    query = SQLQuery(query_string=query_str, is_parameterized=False)
    
    print(f"Query String: {query_str}")
    print(f"Is Vulnerable: {query.is_vulnerable()}")
    print(f"\n{query.get_vulnerability_details()}")
    
    print("\n" + "="*60)
    print("Scenario 2: Safe Query (Parameterized)")
    print("-" * 60)
    safe_query_str = AbstractString.constant("SELECT * FROM users WHERE username = ?")
    safe_query = SQLQuery(query_string=safe_query_str, is_parameterized=True)
    
    print(f"Query String: {safe_query_str}")
    print(f"Is Vulnerable: {safe_query.is_vulnerable()}")
    print(safe_query.get_vulnerability_details())
    
    print("\n" + "="*60)


def demo_string_operations():
    """Demonstrate string operation tracking"""
    print("\n" + "="*60)
    print("String Operations Tracking Demo")
    print("="*60 + "\n")
    
    print("Building a SQL query with multiple operations:")
    print("-" * 60)
    
    # Start with base query
    query = AbstractString.constant("SELECT * FROM ")
    print(f"Step 1: {query}")
    
    # Add table name from user input (simulating table parameter)
    table = AbstractString.user_input("users")
    query = query.concat(table)
    print(f"Step 2: {query}")
    print(f"        Operations: {query.operations}")
    
    # Add WHERE clause
    where = AbstractString.constant(" WHERE id = ")
    query = query.concat(where)
    print(f"Step 3: {query}")
    print(f"        Operations: {query.operations}")
    
    # Add user input for ID
    user_id = AbstractString.user_input("1")
    query = query.concat(user_id)
    print(f"Step 4: {query}")
    print(f"        Operations: {query.operations}")
    print(f"        Is Tainted: {query.tainted}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    # Run unit tests
    success = run_all_tests()
    
    # Run demos
    demo_sql_injection()
    demo_string_operations()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)
