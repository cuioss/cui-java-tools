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
 * Test for {@link AttackCookieGenerator}
 * Tests framework-compliant generator for malicious cookie attack patterns.
 */
class AttackCookieGeneratorTest {

    private final AttackCookieGenerator generator = new AttackCookieGenerator();

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
    void shouldGenerateVariedAttackCookies() {
        Set<Cookie> generatedCookies = new HashSet<>();

        // Generate many cookies to test variety
        for (int i = 0; i < 300; i++) {
            generatedCookies.add(generator.next());
        }

        // We should have good variety for attack cookies
        assertTrue(generatedCookies.size() >= 50,
                "Generator should produce varied attack cookies, got: " + generatedCookies.size());
    }

    @Test
    void shouldGenerateAttackNames() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test malicious names
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for malicious cookie name patterns
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
    void shouldGenerateAttackValues() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test attack values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack pattern values
        boolean hasXssAttack = generated.stream().anyMatch(c -> c.value().contains("<script>"));
        boolean hasSqlInjection = generated.stream().anyMatch(c -> c.value().contains("DROP TABLE"));
        boolean hasPathTraversal = generated.stream().anyMatch(c -> c.value().contains("../"));
        boolean hasNullByte = generated.stream().anyMatch(c -> c.value().contains("\u0000"));
        boolean hasJndiAttack = generated.stream().anyMatch(c -> c.value().contains("${jndi:"));

        assertTrue(hasXssAttack, "Should generate XSS attack values");
        assertTrue(hasSqlInjection, "Should generate SQL injection attack values");
        assertTrue(hasPathTraversal, "Should generate path traversal attack values");
        assertTrue(hasNullByte, "Should generate null byte attack values");
        assertTrue(hasJndiAttack, "Should generate JNDI attack values");
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
    void shouldGenerateMaliciousAttributes() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test malicious attributes
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for malicious attribute patterns
        boolean hasEvilDomain = generated.stream().anyMatch(c -> c.attributes().contains(".evil.com"));
        boolean hasPathTraversalInPath = generated.stream().anyMatch(c -> c.attributes().contains("../"));
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
    void shouldGenerateProtocolAttacks() {
        Set<Cookie> generated = new HashSet<>();

        // Generate cookies to test protocol attacks
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for protocol-based attacks
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

            // Test equals and hashCode work (records auto-generate these)
            Cookie duplicate = new Cookie(cookie.name(), cookie.value(), cookie.attributes());
            assertEquals(cookie, duplicate, "Equal cookies should be equal");
            assertEquals(cookie.hashCode(), duplicate.hashCode(), "Equal cookies should have same hash code");
        }
    }

    @Test
    void shouldGenerateFrameworkCompliantAttacks() {
        Set<Cookie> firstRun = new HashSet<>();
        Set<Cookie> secondRun = new HashSet<>();

        // Generate cookies in two runs to test reproducibility
        for (int i = 0; i < 100; i++) {
            firstRun.add(generator.next());
        }

        // Create new generator instance
        AttackCookieGenerator newGenerator = new AttackCookieGenerator();
        for (int i = 0; i < 100; i++) {
            secondRun.add(newGenerator.next());
        }

        // Both runs should have reasonable variety (framework compliance test)
        assertTrue(firstRun.size() >= 20, "First run should have variety");
        assertTrue(secondRun.size() >= 20, "Second run should have variety");

        // Should consistently generate only attack patterns
        boolean firstHasAttacks = firstRun.stream().anyMatch(c ->
                c.value().contains("<script>") || c.value().contains("DROP") ||
                        c.name().isEmpty() || c.name().contains("="));
        boolean secondHasAttacks = secondRun.stream().anyMatch(c ->
                c.value().contains("<script>") || c.value().contains("DROP") ||
                        c.name().isEmpty() || c.name().contains("="));

        assertTrue(firstHasAttacks, "First run should generate attack patterns");
        assertTrue(secondHasAttacks, "Second run should generate attack patterns");
    }
}