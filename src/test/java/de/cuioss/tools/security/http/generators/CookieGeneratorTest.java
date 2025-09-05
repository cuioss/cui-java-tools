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
package de.cuioss.tools.security.http.generators;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link CookieGenerator}
 */
class CookieGeneratorTest {

    private final CookieGenerator generator = new CookieGenerator();

    @Test
    void shouldReturnCookieType() {
        assertEquals(Cookie.class, generator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        for (int i = 0; i < 100; i++) {
            Cookie cookie = generator.next();
            assertNotNull(cookie, "Generated Cookie should not be null");
            assertNotNull(cookie.name(), "Cookie name should not be null");
            assertNotNull(cookie.value(), "Cookie value should not be null");
            assertNotNull(cookie.attributes(), "Cookie attributes should not be null");
        }
    }

    @Test
    void shouldGenerateVariedCookies() {
        Set<Cookie> generatedCookies = new HashSet<>();

        // Generate many cookies to test variety
        for (int i = 0; i < 300; i++) {
            generatedCookies.add(generator.next());
        }

        // We should have good variety
        assertTrue(generatedCookies.size() >= 100,
                "Generator should produce varied cookies, got: " + generatedCookies.size());
    }

    @Test
    void shouldGenerateStandardCookieNames() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test standard names
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for standard cookie names
        boolean hasJSessionId = generated.stream().anyMatch(c -> "JSESSIONID".equals(c.name()));
        boolean hasSessionId = generated.stream().anyMatch(c -> "session_id".equals(c.name()));
        boolean hasAuthToken = generated.stream().anyMatch(c -> "auth_token".equals(c.name()));
        boolean hasCsrfToken = generated.stream().anyMatch(c -> "csrf_token".equals(c.name()));
        boolean hasUserId = generated.stream().anyMatch(c -> "user_id".equals(c.name()));

        assertTrue(hasJSessionId, "Should generate JSESSIONID cookies");
        assertTrue(hasSessionId, "Should generate session_id cookies");
        assertTrue(hasAuthToken, "Should generate auth_token cookies");
        assertTrue(hasCsrfToken, "Should generate csrf_token cookies");
        assertTrue(hasUserId, "Should generate user_id cookies");
    }

    @Test
    void shouldGenerateSafeValues() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test safe values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for safe cookie values
        boolean hasSessionValue = generated.stream().anyMatch(c -> c.value().contains("session_"));
        boolean hasTrueValue = generated.stream().anyMatch(c -> "true".equals(c.value()));
        boolean hasLangValue = generated.stream().anyMatch(c -> c.value().contains("en_US"));
        boolean hasThemeValue = generated.stream().anyMatch(c -> "dark".equals(c.value()) || "light".equals(c.value()));

        assertTrue(hasSessionValue, "Should generate session-like values");
        assertTrue(hasTrueValue, "Should generate boolean values");
        assertTrue(hasLangValue, "Should generate language values");
        assertTrue(hasThemeValue, "Should generate theme values");
    }

    @Test
    void shouldGenerateAttackValues() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test attack values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack pattern values
        boolean hasXssAttack = generated.stream().anyMatch(c -> c.value().contains("<script>"));
        boolean hasSqlInjection = generated.stream().anyMatch(c -> c.value().contains("DROP TABLE"));
        boolean hasPathTraversal = generated.stream().anyMatch(c -> c.value().contains("../../../"));
        boolean hasNullByte = generated.stream().anyMatch(c -> c.value().contains("\u0000"));
        boolean hasJndiAttack = generated.stream().anyMatch(c -> c.value().contains("${jndi:"));

        assertTrue(hasXssAttack, "Should generate XSS attack values");
        assertTrue(hasSqlInjection, "Should generate SQL injection attack values");
        assertTrue(hasPathTraversal, "Should generate path traversal attack values");
        assertTrue(hasNullByte, "Should generate null byte attack values");
        assertTrue(hasJndiAttack, "Should generate JNDI attack values");
    }

    @Test
    void shouldGenerateSpecialCookieNames() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test special names
        for (int i = 0; i < 300; i++) {
            generated.add(generator.next());
        }

        // Check for special cookie name patterns
        boolean hasEmptyName = generated.stream().anyMatch(c -> c.name().isEmpty());
        boolean hasWhitespaceName = generated.stream().anyMatch(c -> c.name().trim().isEmpty() && !c.name().isEmpty());
        boolean hasSpacesInName = generated.stream().anyMatch(c -> c.name().contains("cookie with spaces"));
        boolean hasEqualsInName = generated.stream().anyMatch(c -> c.name().contains("="));
        boolean hasSemicolonInName = generated.stream().anyMatch(c -> c.name().contains(";"));

        assertTrue(hasEmptyName, "Should generate empty cookie names");
        assertTrue(hasWhitespaceName, "Should generate whitespace cookie names");
        assertTrue(hasSpacesInName, "Should generate cookie names with spaces");
        assertTrue(hasEqualsInName, "Should generate cookie names with equals");
        assertTrue(hasSemicolonInName, "Should generate cookie names with semicolons");
    }

    @Test
    void shouldGenerateSpecialCharactersInNames() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test special characters in names
        for (int i = 0; i < 300; i++) {
            generated.add(generator.next());
        }

        // Check for special characters in cookie names
        boolean hasCommaInName = generated.stream().anyMatch(c -> c.name().contains(","));
        boolean hasQuoteInName = generated.stream().anyMatch(c -> c.name().contains("\""));
        boolean hasTabInName = generated.stream().anyMatch(c -> c.name().contains("\t"));
        boolean hasNewlineInName = generated.stream().anyMatch(c -> c.name().contains("\n"));
        boolean hasBracketsInName = generated.stream().anyMatch(c -> c.name().contains("["));

        assertTrue(hasCommaInName, "Should generate cookie names with commas");
        assertTrue(hasQuoteInName, "Should generate cookie names with quotes");
        assertTrue(hasTabInName, "Should generate cookie names with tabs");
        assertTrue(hasNewlineInName, "Should generate cookie names with newlines");
        assertTrue(hasBracketsInName, "Should generate cookie names with brackets");
    }

    @Test
    void shouldGenerateCookieAttributes() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test attributes
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for various cookie attributes
        boolean hasNoAttributes = generated.stream().anyMatch(c -> c.attributes().isEmpty());
        boolean hasDomainAttribute = generated.stream().anyMatch(c -> c.attributes().contains("Domain="));
        boolean hasPathAttribute = generated.stream().anyMatch(c -> c.attributes().contains("Path="));
        boolean hasSecureAttribute = generated.stream().anyMatch(c -> c.attributes().contains("Secure"));
        boolean hasHttpOnlyAttribute = generated.stream().anyMatch(c -> c.attributes().contains("HttpOnly"));

        assertTrue(hasNoAttributes, "Should generate cookies with no attributes");
        assertTrue(hasDomainAttribute, "Should generate cookies with Domain attribute");
        assertTrue(hasPathAttribute, "Should generate cookies with Path attribute");
        assertTrue(hasSecureAttribute, "Should generate cookies with Secure attribute");
        assertTrue(hasHttpOnlyAttribute, "Should generate cookies with HttpOnly attribute");
    }

    @Test
    void shouldGenerateMaliciousAttributes() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test malicious attributes
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for malicious attribute patterns
        boolean hasEvilDomain = generated.stream().anyMatch(c -> c.attributes().contains(".evil.com"));
        boolean hasPathTraversalInPath = generated.stream().anyMatch(c -> c.attributes().contains("../../../"));
        boolean hasNegativeMaxAge = generated.stream().anyMatch(c -> c.attributes().contains("Max-Age=-1"));
        boolean hasHeaderInjection = generated.stream().anyMatch(c -> c.attributes().contains("\r\n"));
        boolean hasNullByteInPath = generated.stream().anyMatch(c -> c.attributes().contains("\u0000"));

        assertTrue(hasEvilDomain, "Should generate malicious domain attributes");
        assertTrue(hasPathTraversalInPath, "Should generate path traversal in path attributes");
        assertTrue(hasNegativeMaxAge, "Should generate negative Max-Age attributes");
        assertTrue(hasHeaderInjection, "Should generate header injection attributes");
        assertTrue(hasNullByteInPath, "Should generate null bytes in path attributes");
    }

    @Test
    void shouldGenerateHeaderInjectionAttacks() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test header injection
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for header injection patterns
        boolean hasValueInjection = generated.stream().anyMatch(c -> c.value().contains("\r\nSet-Cookie:"));
        boolean hasHttpResponseInjection = generated.stream().anyMatch(c -> c.value().contains("HTTP/1.1 200 OK"));
        boolean hasEncodedInjection = generated.stream().anyMatch(c -> c.value().contains("%0d%0a"));

        assertTrue(hasValueInjection, "Should generate header injection in values");
        assertTrue(hasHttpResponseInjection, "Should generate HTTP response injection");
        assertTrue(hasEncodedInjection, "Should generate encoded header injection");
    }

    @Test
    void shouldGenerateLongValues() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test long values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for very long cookie values and names
        boolean hasLongValue = generated.stream().anyMatch(c -> c.value().length() > 5000);
        boolean hasLongName = generated.stream().anyMatch(c -> c.name().length() > 100);

        assertTrue(hasLongValue, "Should generate very long cookie values");
        assertTrue(hasLongName, "Should generate very long cookie names");
    }

    @Test
    void shouldGenerateUnicodeAttacks() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test Unicode attacks
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for Unicode-based attacks
        boolean hasDirectionOverride = generated.stream().anyMatch(c -> c.value().contains("\u202e"));

        assertTrue(hasDirectionOverride, "Should generate Unicode direction override attacks");
    }

    @Test
    void shouldGenerateSecurityTestPatterns() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test security patterns
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for security test patterns
        boolean hasJavaScriptProtocol = generated.stream().anyMatch(c -> c.value().contains("javascript:"));
        boolean hasDataUrl = generated.stream().anyMatch(c -> c.value().contains("data:text/html"));

        assertTrue(hasJavaScriptProtocol, "Should generate JavaScript protocol attacks");
        assertTrue(hasDataUrl, "Should generate data URL attacks");
    }

    @Test
    void shouldGenerateValidRecordStructure() {
        // Test that all generated cookies have valid record structure
        for (int i = 0; i < 100; i++) {
            Cookie cookie = generator.next();

            // Test record methods work correctly
            assertNotNull(cookie.name(), "Cookie name should not be null");
            assertNotNull(cookie.value(), "Cookie value should not be null");
            assertNotNull(cookie.attributes(), "Cookie attributes should not be null");

            // Test toString method works (records auto-generate this)
            String toString = cookie.toString();
            assertTrue(toString.contains("Cookie"), "toString should contain record name");
            assertTrue(toString.contains(cookie.name()), "toString should contain cookie name");
            assertTrue(toString.contains(cookie.value()), "toString should contain cookie value");

            // Test equals and hashCode work (records auto-generate these)
            Cookie duplicate = new Cookie(cookie.name(), cookie.value(), cookie.attributes());
            assertEquals(cookie, duplicate, "Equal cookies should be equal");
            assertEquals(cookie.hashCode(), duplicate.hashCode(), "Equal cookies should have same hash code");
        }
    }

    @Test
    void shouldGenerateReasonableVariety() {
        Set<Cookie> generated = new HashSet<>();

        // Generate a large set to test overall variety
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have cookies from different categories
        boolean hasStandardNames = generated.stream().anyMatch(c ->
                "JSESSIONID".equals(c.name()) || "auth_token".equals(c.name()) || "csrf_token".equals(c.name()));
        boolean hasSpecialNames = generated.stream().anyMatch(c ->
                c.name().contains("=") || c.name().contains(";") || c.name().contains(" "));
        boolean hasSafeValues = generated.stream().anyMatch(c ->
                c.value().matches("\\w+_\\d+|true|false|\\w+_\\w+"));
        boolean hasAttackValues = generated.stream().anyMatch(c ->
                c.value().contains("<") || c.value().contains("../") || c.value().contains("DROP"));

        assertTrue(hasStandardNames, "Should generate standard cookie names");
        assertTrue(hasSpecialNames, "Should generate special character cookie names");
        assertTrue(hasSafeValues, "Should generate safe cookie values");
        assertTrue(hasAttackValues, "Should generate attack cookie values");

        // Should generate reasonable variety
        assertTrue(generated.size() >= 150, "Should generate reasonable variety of cookies");
    }
}