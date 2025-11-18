package jpamb.cases;

import jpamb.utils.Case;
import jpamb.utils.VulnerabilityException;

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
        detectVulnerability(query, userInput);
        return query;
    }

    @Case("(\"' OR '1'='1\") -> vulnerable")
    public static String sqlInjectionBasic(String userInput) {
        // Classic SQL injection - always returns true
        String query = "SELECT * FROM users WHERE username = '" + userInput + "' AND password = 'anything'";
        detectVulnerability(query, userInput);
        return query;
    }

    @Case("(\"admin\") -> vulnerable")
    public static String sqlInjectionLogin(String username) {
        // Vulnerable login query - concatenates user input directly
        String password = "' OR '1'='1";
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        detectVulnerability(query, username);
        return query;
    }

    @Case("(\"1; DROP TABLE users--\") -> vulnerable")
    public static String sqlInjectionDropTable(String userId) {
        // SQL injection with command stacking - attempts to drop table
        String query = "SELECT * FROM products WHERE id = " + userId;
        detectVulnerability(query, userId);
        return query;
    }

    @Case("(\"' UNION SELECT password FROM admin--\") -> vulnerable")
    public static String sqlInjectionUnion(String searchTerm) {
        // UNION-based SQL injection to extract sensitive data
        String query = "SELECT title, content FROM articles WHERE title LIKE '%" + searchTerm + "%'";
        detectVulnerability(query, searchTerm);
        return query;
    }

    @Case("(\"admin\") -> vulnerable")
    public static String sqlInjectionUpdate(String newEmail) {
        // Vulnerable UPDATE statement
        String userId = "1' OR '1'='1";
        String query = "UPDATE users SET email = '" + newEmail + "' WHERE id = '" + userId + "'";
        detectVulnerability(query, newEmail);
        return query;
    }

    @Case("(\"value\") -> vulnerable")
    public static String sqlInjectionDelete(String categoryName) {
        // Vulnerable DELETE statement - could delete all records
        String query = "DELETE FROM items WHERE category = '" + categoryName + "'";
        detectVulnerability(query, categoryName);
        return query;
    }

    @Case("(\"admin\") -> ok")
    public static String safeParameterizedQuery(String username) {
        // Safe query using parameterized approach (simulated)
        String query = "SELECT * FROM users WHERE username = ?";
        // In real code, this would use PreparedStatement
        return query;
    }

    @Case("(\"admin\") -> vulnerable")
    public static String sqlInjectionOrderBy(String sortColumn) {
        // SQL injection via ORDER BY clause
        String query = "SELECT * FROM users ORDER BY " + sortColumn;
        detectVulnerability(query, sortColumn);
        return query;
    }

    @Case("(\"admin\") -> vulnerable")
    public static String sqlInjectionInsert(String username) {
        // Vulnerable INSERT statement
        String email = "test@example.com', 'admin', 'password123'); --";
        String query = "INSERT INTO users (username, email) VALUES ('" + username + "', '" + email + "')";
        detectVulnerability(query, username);
        return query;
    }

    @Case("(\"hello\", 1) -> ok")
    @Case("(\"hello\", -1) -> out of bounds")
    @Case("(\"hello\", 5) -> out of bounds")
    @Case("(null, 0) -> null pointer")
    public static void testCharAt(String str, int index) {
        if (str == null) {
            throw new NullPointerException("String is null");
        }
        if (index < 0 || index >= str.length()) {
            throw new StringIndexOutOfBoundsException("Index out of bounds");
        }
        char c = str.charAt(index);
        assert c == 'e';
    }

    @Case("(\"hello\", \"world\") -> ok")
    @Case("(\"\", \"world\") -> ok")
    @Case("(\"hello\", \"\") -> ok")
    @Case("(\"\", \"\") -> ok")
    @Case("(null, \"world\") -> null pointer")
    @Case("(\"hello\", null) -> null pointer")
    public static void testConcatenateStrings(String str1, String str2) {
        if (str1 == null || str2 == null) {
            throw new NullPointerException("One of the strings is null");
        }
        String result = str1 + str2;
        assert result != null;
    }

    @Case("(\"hello world\", \"world\") -> ok")
    @Case("(\"hello world\", \"hello\") -> ok")
    @Case("(\"hello world\", \"\") -> ok")
    @Case("(\"hello world\", \"test\") -> assertion error")
    @Case("(\"\", \"\") -> ok")
    @Case("(\"\", \"test\") -> assertion error")
    @Case("(null, \"test\") -> null pointer")
    @Case("(\"hello world\", null) -> null pointer")
    public static void testContainsSubstring(String str, String substring) {
        if (str == null || substring == null) {
            throw new NullPointerException("One of the strings is null");
        }
        assert str.contains(substring);
    }

    private static void detectVulnerability(String query, String... inputs) {
        if (query == null) {
            return;
        }
        for (String input : inputs) {
            if (input == null || input.isEmpty()) {
                continue;
            }
            if (query.contains(input)) {
                throw new VulnerabilityException("SQL injection vulnerability detected: " + query);
            }
        }
    }
}
