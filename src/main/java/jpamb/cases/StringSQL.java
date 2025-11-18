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
//charAt
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
//contentEquals
    @Case("(\"hello\", \"hello\") -> true")
    @Case("(\"hello\", \"world\") -> false")
    @Case("(\"hello\", \"\") -> false")
    @Case("(\"\", \"\") -> true")
    @Case("(null, \"hello\") -> NullPointerException")
    @Case("(\"hello\", null) -> NullPointerException")
    public static boolean contentEqualsString(String str, String other) {
        if (str == null || other == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str.contentEquals(other);
    }
//concatenate
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
//contains
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
//equals
    @Case("(\"hello\", \"hello\") -> true")
    @Case("(\"hello\", \"world\") -> false")
    @Case("(\"hello\", \"\") -> false")
    @Case("(\"\", \"\") -> true")
    @Case("(null, \"hello\") -> NullPointerException")
    @Case("(\"hello\", null) -> NullPointerException")
    public static boolean equalsStrings(String str1, String str2) {
        if (str1 == null || str2 == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str1.equals(str2);
    }
//endsWith
    @Case("(\"hello\", \"lo\") -> true")
    @Case("(\"hello\", \"hello\") -> true")
    @Case("(\"hello\", \"world\") -> false")
    @Case("(\"hello\", \"\") -> true")
    @Case("(\"\", \"\") -> true")
    @Case("(\"\", \"test\") -> false")
    @Case("(null, \"test\") -> NullPointerException")
    @Case("(\"hello\", null) -> NullPointerException")
    public static boolean endsWithString(String str, String suffix) {
        if (str == null || suffix == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str.endsWith(suffix);
    }
//isEmpty
    @Case("(\"\") -> true")
    @Case("(\"hello\") -> false")
    @Case("(null) -> NullPointerException")
    public static boolean isEmptyString(String str) {
        if (str == null) {
            throw new NullPointerException("The string is null");
        }
        return str.isEmpty();
    }
//toString
    @Case("(123) -> \"123\"")
    @Case("(null) -> NullPointerException")
    public static String toStringValue(Object obj) {
        if (obj == null) {
            throw new NullPointerException("The object is null");
        }
        return obj.toString();
    }
//substring
    @Case("(\"hello\", 0, 2) -> \"he\"")
    @Case("(\"hello\", 2, 5) -> \"llo\"")
    @Case("(\"hello\", 0, 0) -> \"\"")
    @Case("(\"hello\", 0, 10) -> StringIndexOutOfBoundsException")
    @Case("(\"hello\", -1, 2) -> StringIndexOutOfBoundsException")
    @Case("(null, 0, 2) -> NullPointerException")
    public static String substringValue(String str, int beginIndex, int endIndex) {
        if (str == null) {
            throw new NullPointerException("The string is null");
        }
        return str.substring(beginIndex, endIndex);
    }
//length
    @Case("(\"hello\") -> 5")
    @Case("(\"\") -> 0")
    @Case("(null) -> NullPointerException")
    public static int stringLength(String str) {
        if (str == null) {
            throw new NullPointerException("The string is null");
        }
        return str.length();
    }
//startsWith
    @Case("(\"hello\", \"he\") -> true")
    @Case("(\"hello\", \"hello\") -> true")
    @Case("(\"hello\", \"world\") -> false")
    @Case("(\"hello\", \"\") -> true")
    @Case("(\"\", \"\") -> true")
    @Case("(\"\", \"test\") -> false")
    @Case("(null, \"test\") -> NullPointerException")
    @Case("(\"hello\", null) -> NullPointerException")
    public static boolean startsWithString(String str, String prefix) {
        if (str == null || prefix == null) {
            throw new NullPointerException("One of the strings is null");
        }
        return str.startsWith(prefix);
    }
//toLowerCase
    @Case("(\"HELLO\") -> \"hello\"")
    @Case("(\"Hello\") -> \"hello\"")
    @Case("(\"hello\") -> \"hello\"")
    @Case("(\"\") -> \"\"")
    @Case("(null) -> NullPointerException")
    public static String toLowerCaseString(String str) {
        if (str == null) {
            throw new NullPointerException("The string is null");
        }
        return str.toLowerCase();
    }
//toUpperCase
    @Case("(\"hello\") -> \"HELLO\"")
    @Case("(\"Hello\") -> \"HELLO\"")
    @Case("(\"HELLO\") -> \"HELLO\"")
    @Case("(\"\") -> \"\"")
    @Case("(null) -> NullPointerException")
    public static String toUpperCaseString(String str) {
        if (str == null) {
            throw new NullPointerException("The string is null");
        }
        return str.toUpperCase();
    }
}
