package jpamb.cases;

import jpamb.utils.Case;

/**
 * Test cases for string operations and SQL injection detection
 */
public class StringSQL {

    @Case("(\"hello\") -> ok")
    public static void safeString(String str) {
        // Just use a safe string constant
        String query = "SELECT * FROM users WHERE id = 1";
    }

    @Case("(\"admin\") -> ok")
    public static void concatenateStrings(String str1) {
        // Concatenate strings
        String str2 = "world";
        String result = str1 + " " + str2;
    }

    @Case("(\"test\") -> ok")
    public static void substringOperation(String str) {
        // Extract substring
        if (str.length() > 2) {
            String sub = str.substring(0, 2);
        }
    }

    @Case("() -> ok")
    public static void stringBuilder() {
        // Use StringBuilder
        StringBuilder sb = new StringBuilder();
        sb.append("Hello");
        sb.append(" ");
        sb.append("World");
        String result = sb.toString();
    }

    @Case("(\"value\") -> ok")
    public static void stringComparison(String str) {
        // String equality check
        assert !str.equals("different");
    }
}
