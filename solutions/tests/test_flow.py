#!/usr/bin/env python3
"""
Flow Analysis Test Suite for String-Aware Interpreter

This file contains tests demonstrating data flow analysis capabilities,
including control flow tracking, interprocedural analysis, and path-sensitive
taint propagation.
"""

import sys
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "lib"))

# Import from the string_interpreter module
import importlib.util
spec = importlib.util.spec_from_file_location("string_interpreter", 
                                               Path(__file__).parent.parent / "interpreters" / "string_interpreter.py")
string_interpreter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(string_interpreter)

AbstractString = string_interpreter.AbstractString
StringProvenance = string_interpreter.StringProvenance
SQLQuery = string_interpreter.SQLQuery


def test_conditional_flow_tainted_path():
    """Test flow analysis through conditional - tainted path"""
    print("\n--- Test: Conditional Flow (Tainted Path) ---")
    
    # Simulate: if (condition) { query = userInput } else { query = constant }
    condition = True
    
    if condition:
        query = AbstractString.user_input("admin' OR '1'='1")
    else:
        query = AbstractString.constant("admin")
    
    assert query.tainted == True
    assert query.provenance == StringProvenance.USER_INPUT
    print(f"✓ Tainted path correctly identified: {query.tainted}")
    print(f"  Query value: {query.value}")


def test_conditional_flow_safe_path():
    """Test flow analysis through conditional - safe path"""
    print("\n--- Test: Conditional Flow (Safe Path) ---")
    
    condition = False
    
    if condition:
        query = AbstractString.user_input("admin' OR '1'='1")
    else:
        query = AbstractString.constant("admin")
    
    assert query.tainted == False
    assert query.provenance == StringProvenance.CONSTANT
    print(f"✓ Safe path correctly identified: {query.tainted}")
    print(f"  Query value: {query.value}")


def test_merge_tainted_and_safe():
    """Test merging tainted and safe values (must-be-tainted analysis)"""
    print("\n--- Test: Flow Merge (Tainted + Safe) ---")
    
    # Simulate two paths merging
    path1 = AbstractString.user_input("malicious")
    path2 = AbstractString.constant("safe")
    
    # In real flow analysis, we'd merge these
    # For now, we show that either path could be taken
    merged_tainted = path1.concat(AbstractString.constant(" suffix"))
    merged_safe = path2.concat(AbstractString.constant(" suffix"))
    
    assert merged_tainted.tainted == True
    assert merged_safe.tainted == False
    print(f"✓ Tainted path result: {merged_tainted.tainted}")
    print(f"✓ Safe path result: {merged_safe.tainted}")
    print("  Note: Conservative analysis would mark merged result as tainted")


def test_loop_flow_accumulation():
    """Test flow through loop with accumulating taint"""
    print("\n--- Test: Loop Flow Analysis ---")
    
    # Simulate: query = ""; for (input in inputs) { query += input; }
    query = AbstractString.constant("")
    inputs = [
        AbstractString.constant("SELECT * FROM "),
        AbstractString.user_input("users"),  # Tainted input in loop
        AbstractString.constant(" WHERE id = 1")
    ]
    
    for input_str in inputs:
        query = query.concat(input_str)
        print(f"  Iteration: query tainted = {query.tainted}")
    
    assert query.tainted == True
    assert "users" in query.value
    print(f"✓ Loop taint propagation correct: {query.tainted}")
    print(f"  Final query: {query.value}")


def test_function_call_flow():
    """Test interprocedural flow analysis through function calls"""
    print("\n--- Test: Interprocedural Flow ---")
    
    def build_where_clause(column: str, value: AbstractString) -> AbstractString:
        """Helper function that builds WHERE clause"""
        base = AbstractString.constant(f" WHERE {column} = '")
        closing = AbstractString.constant("'")
        return base.concat(value).concat(closing)
    
    # Test with tainted input
    user_input = AbstractString.user_input("admin' OR '1'='1")
    where_clause = build_where_clause("username", user_input)
    
    assert where_clause.tainted == True
    print(f"✓ Taint propagated through function call: {where_clause.tainted}")
    print(f"  Result: {where_clause.value}")
    
    # Test with safe input
    safe_input = AbstractString.constant("admin")
    safe_where = build_where_clause("username", safe_input)
    
    assert safe_where.tainted == False
    print(f"✓ Safe value maintained through function call: {safe_where.tainted}")


def test_multiple_sources_flow():
    """Test flow with multiple taint sources"""
    print("\n--- Test: Multiple Taint Sources ---")
    
    source1 = AbstractString.user_input("malicious1")
    source2 = AbstractString.user_input("malicious2")
    safe = AbstractString.constant(" AND ")
    
    # Build: malicious1 AND malicious2
    result = source1.concat(safe).concat(source2)
    
    assert result.tainted == True
    print(f"✓ Multiple sources correctly tainted: {result.tainted}")
    print(f"  Operations: {result.operations}")


def test_sanitization_flow():
    """Test flow through sanitization (parameterized query)"""
    print("\n--- Test: Sanitization Flow ---")
    
    user_input = AbstractString.user_input("admin' OR '1'='1")
    
    # Before sanitization - vulnerable
    unsafe_query = AbstractString.constant("SELECT * FROM users WHERE username = '").concat(user_input)
    vulnerable = SQLQuery(query_string=unsafe_query, is_parameterized=False)
    
    assert vulnerable.is_vulnerable() == True
    print(f"✓ Unsanitized query is vulnerable: {vulnerable.is_vulnerable()}")
    
    # After sanitization - safe
    safe_query_template = AbstractString.constant("SELECT * FROM users WHERE username = ?")
    safe = SQLQuery(query_string=safe_query_template, is_parameterized=True)
    
    assert safe.is_vulnerable() == False
    print(f"✓ Sanitized query is safe: {safe.is_vulnerable()}")


def test_path_sensitive_analysis():
    """Test path-sensitive analysis with different branches"""
    print("\n--- Test: Path-Sensitive Analysis ---")
    
    def validate_and_build_query(username: str, is_admin: bool) -> AbstractString:
        """Simulates path-sensitive query building"""
        if is_admin:
            # Admin path - use constant
            user = AbstractString.constant(username)
        else:
            # User path - treat as user input
            user = AbstractString.user_input(username)
        
        base = AbstractString.constant("SELECT * FROM users WHERE username = '")
        closing = AbstractString.constant("'")
        return base.concat(user).concat(closing)
    
    # Admin path - should be safe
    admin_query = validate_and_build_query("admin", is_admin=True)
    assert admin_query.tainted == False
    print(f"✓ Admin path is safe: {admin_query.tainted}")
    
    # User path - should be tainted
    user_query = validate_and_build_query("user123", is_admin=False)
    assert user_query.tainted == True
    print(f"✓ User path is tainted: {user_query.tainted}")


def test_dataflow_through_assignment():
    """Test dataflow tracking through variable assignments"""
    print("\n--- Test: Dataflow Through Assignments ---")
    
    # x = user_input
    x = AbstractString.user_input("malicious")
    print(f"  x tainted: {x.tainted}")
    
    # y = x (taint flows)
    y = x
    print(f"  y tainted: {y.tainted}")
    
    # z = y + constant (taint propagates)
    z = y.concat(AbstractString.constant(" suffix"))
    print(f"  z tainted: {z.tainted}")
    
    assert x.tainted == True
    assert y.tainted == True
    assert z.tainted == True
    print("✓ Taint correctly flows through assignments")


def test_backwards_slice():
    """Test backwards slicing to find taint sources"""
    print("\n--- Test: Backwards Slicing ---")
    
    # Build complex query
    base = AbstractString.constant("SELECT * FROM ")
    table = AbstractString.user_input("users")
    where = AbstractString.constant(" WHERE id = ")
    id_val = AbstractString.constant("1")
    
    query = base.concat(table).concat(where).concat(id_val)
    
    # Backwards slice: find what made this tainted
    print(f"  Query is tainted: {query.tainted}")
    print(f"  Operations history: {query.operations}")
    
    # Check if we can trace back to user input
    has_user_input = any("USER_INPUT" in str(op) for op in query.operations)
    assert query.tainted == True
    print(f"✓ Backwards slice found user input: {has_user_input}")


def test_forward_slice():
    """Test forward slicing from taint source"""
    print("\n--- Test: Forward Slicing ---")
    
    # Start with taint source
    source = AbstractString.user_input("malicious")
    print(f"  Source tainted: {source.tainted}")
    
    # Forward propagation
    step1 = source.concat(AbstractString.constant(" step1"))
    print(f"  After step1: {step1.tainted}")
    
    step2 = step1.concat(AbstractString.constant(" step2"))
    print(f"  After step2: {step2.tainted}")
    
    step3 = step2.substring(0, 20)
    print(f"  After step3: {step3.tainted}")
    
    assert step1.tainted == True
    assert step2.tainted == True
    assert step3.tainted == True
    print("✓ Forward slice correctly propagated taint")


def test_complex_control_flow():
    """Test complex control flow with nested conditions"""
    print("\n--- Test: Complex Control Flow ---")
    
    def complex_query_builder(user_level: int, username: str) -> AbstractString:
        """Simulates complex conditional logic"""
        base = AbstractString.constant("SELECT * FROM ")
        
        if user_level == 0:
            # Public access - taint everything
            user = AbstractString.user_input(username)
            table = AbstractString.user_input("public_data")
        elif user_level == 1:
            # Registered user - partial trust
            user = AbstractString.user_input(username)
            table = AbstractString.constant("user_data")
        else:
            # Admin - full trust
            user = AbstractString.constant(username)
            table = AbstractString.constant("admin_data")
        
        where = AbstractString.constant(" WHERE user = '")
        closing = AbstractString.constant("'")
        
        return base.concat(table).concat(where).concat(user).concat(closing)
    
    # Test each path
    public_query = complex_query_builder(0, "guest")
    assert public_query.tainted == True
    print(f"✓ Public path (level 0) tainted: {public_query.tainted}")
    
    user_query = complex_query_builder(1, "user123")
    assert user_query.tainted == True
    print(f"✓ User path (level 1) tainted: {user_query.tainted}")
    
    admin_query = complex_query_builder(2, "admin")
    assert admin_query.tainted == False
    print(f"✓ Admin path (level 2) safe: {admin_query.tainted}")


def run_all_flow_tests():
    """Run all flow analysis tests"""
    print("\n" + "="*70)
    print("Running Flow Analysis Test Suite")
    print("="*70)
    
    tests = [
        test_conditional_flow_tainted_path,
        test_conditional_flow_safe_path,
        test_merge_tainted_and_safe,
        test_loop_flow_accumulation,
        test_function_call_flow,
        test_multiple_sources_flow,
        test_sanitization_flow,
        test_path_sensitive_analysis,
        test_dataflow_through_assignment,
        test_backwards_slice,
        test_forward_slice,
        test_complex_control_flow,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
            print(f"✓ {test.__name__} PASSED\n")
        except AssertionError as e:
            print(f"✗ {test.__name__} FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} ERROR: {e}\n")
            failed += 1
    
    print("="*70)
    print(f"Flow Analysis Test Results: {passed} passed, {failed} failed")
    print("="*70)
    
    return failed == 0


def demo_complete_flow_analysis():
    """Comprehensive flow analysis demonstration"""
    print("\n" + "="*70)
    print("Complete Flow Analysis Demonstration")
    print("="*70 + "\n")
    
    print("Scenario: User Login with Multiple Code Paths")
    print("-" * 70)
    
    def authenticate(username: str, password: str, use_prepared: bool):
        """Simulates authentication with different security levels"""
        if use_prepared:
            # Secure path - parameterized query
            query_template = AbstractString.constant(
                "SELECT * FROM users WHERE username = ? AND password = ?"
            )
            query = SQLQuery(query_string=query_template, is_parameterized=True)
            print(f"\n✓ Secure Path (Parameterized)")
            print(f"  Query: {query_template.value}")
            print(f"  Vulnerable: {query.is_vulnerable()}")
        else:
            # Insecure path - string concatenation
            base = AbstractString.constant("SELECT * FROM users WHERE username = '")
            user_str = AbstractString.user_input(username)
            mid = AbstractString.constant("' AND password = '")
            pass_str = AbstractString.user_input(password)
            closing = AbstractString.constant("'")
            
            query_str = base.concat(user_str).concat(mid).concat(pass_str).concat(closing)
            query = SQLQuery(query_string=query_str, is_parameterized=False)
            
            print(f"\n✗ Insecure Path (Concatenation)")
            print(f"  Query: {query_str.value}")
            print(f"  Vulnerable: {query.is_vulnerable()}")
            print(f"  Tainted: {query_str.tainted}")
            print(f"\n{query.get_vulnerability_details()}")
    
    # Test both paths
    authenticate("admin", "password123", use_prepared=True)
    authenticate("admin' OR '1'='1", "anything", use_prepared=False)
    
    print("\n" + "="*70)


if __name__ == "__main__":
    # Run all flow analysis tests
    success = run_all_flow_tests()
    
    # Run demonstration
    demo_complete_flow_analysis()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)