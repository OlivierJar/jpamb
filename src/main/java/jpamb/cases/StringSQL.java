package jpamb.cases;

import jpamb.utils.Case;

/**
 * Test cases i made to check SQL injection
 */
public class StringSQL {

    @Case("(\"hello\") -> ok")
    public static void safeString(String str) {
        String query = "SELECT * FROM users WHERE id = 1";
    }

    @Case("(\"admin\") -> ok")
    public static void concatenateStrings(String str1) {
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
        StringBuilder sb = new StringBuilder();
        sb.append("Hello");
        sb.append(" ");
        sb.append("World");
        String result = sb.toString();
    }

    @Case("(\"value\") -> ok")
    public static void stringComparison(String str) {
        assert !str.equals("different");
    }

    @Case("(\"admin' OR '1'='1\") -> vulnerable")
    public static String vulnerableQuery(String userInput) {
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        return query;
    }

    @Case("(\"hello\", 1) -> 'e'")
    @Case("(\"hello\", -1) -> StringIndexOutOfBoundsException")
    @Case("(\"hello\", 5) -> StringIndexOutOfBoundsException")
    @Case("(null, 0) -> NullPointerException")
    public static char testCharAt(String str, int index) {
        if (str == null) {
            throw new NullPointerException("String is null");
        }
        if (index < 0 || index >= str.length()) {
            throw new StringIndexOutOfBoundsException("Index out of bounds");
        }
        return str.charAt(index);
    }

    @Case("(\"hello\", \"world\") -> \"helloworld\"")
    @Case("(\"\", \"world\") -> \"world\"")
    @Case("(\"hello\", \"\") -> \"hello\"")
    @Case("(\"\", \"\") -> \"\"")
    @Case("(null, \"world\") -> NullPointerException")
    @Case("(\"hello\", null) -> NullPointerException")
    public static String concatenateStrings(String str1, String str2) {
        if (str1 == null || str2 == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str1 + str2;
    }

    @Case("(\"hello world\", \"world\") -> true")
    @Case("(\"hello world\", \"hello\") -> true")
    @Case("(\"hello world\", \"\") -> true")
    @Case("(\"hello world\", \"test\") -> false")
    @Case("(\"\", \"\") -> true")
    @Case("(\"\", \"test\") -> false")
    @Case("(null, \"test\") -> NullPointerException")
    @Case("(\"hello world\", null) -> NullPointerException")
    public static boolean containsSubstring(String str, String substring) {
        if (str == null || substring == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str.contains(substring);
    }
}
