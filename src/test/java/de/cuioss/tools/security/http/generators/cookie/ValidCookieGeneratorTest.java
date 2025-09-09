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

import de.cuioss.tools.security.http.data.Cookie;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ValidCookieGenerator}
 * Tests framework-compliant generator for legitimate cookie patterns.
 */
class ValidCookieGeneratorTest {

    private final ValidCookieGenerator generator = new ValidCookieGenerator();

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

        // We should have good variety for legitimate cookies
        assertTrue(generatedCookies.size() >= 50,
                "Generator should produce varied legitimate cookies, got: " + generatedCookies.size());
    }

    @Test
    void shouldGenerateOnlyLegitimateNames() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test legitimate names only
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for standard legitimate cookie names
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

        // Should NOT generate malicious names
        boolean hasEmptyName = generated.stream().anyMatch(c -> c.name().isEmpty());
        boolean hasSpecialChars = generated.stream().anyMatch(c ->
                c.name().contains("=") || c.name().contains(";") || c.name().contains("\t"));

        assertFalse(hasEmptyName, "Should NOT generate empty cookie names");
        assertFalse(hasSpecialChars, "Should NOT generate cookie names with special characters");
    }

    @Test
    void shouldGenerateOnlyLegitimateValues() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test legitimate values only
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for legitimate cookie values
        boolean hasSessionValue = generated.stream().anyMatch(c -> c.value().contains("session_"));
        boolean hasTrueValue = generated.stream().anyMatch(c -> "true".equals(c.value()));
        boolean hasLangValue = generated.stream().anyMatch(c -> c.value().contains("en_US"));
        boolean hasThemeValue = generated.stream().anyMatch(c -> "dark".equals(c.value()) || "light".equals(c.value()));

        assertTrue(hasSessionValue, "Should generate session-like values");
        assertTrue(hasTrueValue, "Should generate boolean values");
        assertTrue(hasLangValue, "Should generate language values");
        assertTrue(hasThemeValue, "Should generate theme values");

        // Should NOT generate attack values
        boolean hasXssAttack = generated.stream().anyMatch(c -> c.value().contains("<script>"));
        boolean hasSqlInjection = generated.stream().anyMatch(c -> c.value().contains("DROP TABLE"));
        boolean hasPathTraversal = generated.stream().anyMatch(c -> c.value().contains("../"));
        boolean hasNullByte = generated.stream().anyMatch(c -> c.value().contains("\u0000"));

        assertFalse(hasXssAttack, "Should NOT generate XSS attack values");
        assertFalse(hasSqlInjection, "Should NOT generate SQL injection values");
        assertFalse(hasPathTraversal, "Should NOT generate path traversal values");
        assertFalse(hasNullByte, "Should NOT generate null byte values");
    }

    @Test
    void shouldGenerateValidAttributes() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test attributes
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for legitimate cookie attributes
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

        // Should NOT generate malicious attributes
        boolean hasEvilDomain = generated.stream().anyMatch(c -> c.attributes().contains(".evil.com"));
        boolean hasPathTraversal = generated.stream().anyMatch(c -> c.attributes().contains("../"));
        boolean hasHeaderInjection = generated.stream().anyMatch(c -> c.attributes().contains("\r\n"));

        assertFalse(hasEvilDomain, "Should NOT generate malicious domain attributes");
        assertFalse(hasPathTraversal, "Should NOT generate path traversal attributes");
        assertFalse(hasHeaderInjection, "Should NOT generate header injection attributes");
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
    void shouldGenerateFrameworkCompliantPatterns() {
        Set<Cookie> firstRun = new HashSet<>();
        Set<Cookie> secondRun = new HashSet<>();

        // Generate cookies in two runs to test reproducibility
        for (int i = 0; i < 100; i++) {
            firstRun.add(generator.next());
        }

        // Create new generator instance
        ValidCookieGenerator newGenerator = new ValidCookieGenerator();
        for (int i = 0; i < 100; i++) {
            secondRun.add(newGenerator.next());
        }

        // Both runs should have reasonable variety (framework compliance test)
        assertTrue(firstRun.size() >= 20, "First run should have variety");
        assertTrue(secondRun.size() >= 20, "Second run should have variety");

        // Should generate only legitimate patterns consistently
        for (Cookie cookie : firstRun) {
            assertFalse(cookie.value().contains("<script>"), "Should not contain XSS");
            assertFalse(cookie.value().contains("DROP"), "Should not contain SQL injection");
            assertFalse(cookie.name().isEmpty(), "Should not have empty names");
        }

        for (Cookie cookie : secondRun) {
            assertFalse(cookie.value().contains("<script>"), "Should not contain XSS");
            assertFalse(cookie.value().contains("DROP"), "Should not contain SQL injection");
            assertFalse(cookie.name().isEmpty(), "Should not have empty names");
        }
    }
}