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
package de.cuioss.http.security.config;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link SecurityConfiguration}
 */
@EnableGeneratorController
class SecurityConfigurationTest {

    @Test
    void shouldCreateConfigurationWithBuilder() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .allowPathTraversal(false)
                .maxParameterCount(50)
                .requireSecureCookies(true)
                .build();

        assertEquals(2048, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertEquals(50, config.maxParameterCount());
        assertTrue(config.requireSecureCookies());
    }

    @Test
    void shouldCreateStrictConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.strict();

        assertEquals(1024, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertFalse(config.allowDoubleEncoding());
        assertEquals(20, config.maxParameterCount());
        assertTrue(config.requireSecureCookies());
        assertTrue(config.requireHttpOnlyCookies());
        assertFalse(config.allowNullBytes());
        assertFalse(config.allowControlCharacters());
        assertTrue(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @Test
    void shouldCreateLenientConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.lenient();

        assertEquals(8192, config.maxPathLength());
        assertFalse(config.allowPathTraversal()); // Still disabled
        assertTrue(config.allowDoubleEncoding());
        assertEquals(500, config.maxParameterCount());
        assertFalse(config.requireSecureCookies());
        assertFalse(config.requireHttpOnlyCookies());
        assertFalse(config.allowNullBytes()); // Still disabled
        assertTrue(config.allowControlCharacters());
        assertFalse(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @Test
    void shouldCreateDefaultConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.defaults();

        assertEquals(4096, config.maxPathLength());
        assertFalse(config.allowPathTraversal());
        assertFalse(config.allowDoubleEncoding());
        assertEquals(100, config.maxParameterCount());
        assertFalse(config.requireSecureCookies());
        assertFalse(config.requireHttpOnlyCookies());
        assertFalse(config.allowNullBytes());
        assertFalse(config.allowControlCharacters());
        assertFalse(config.failOnSuspiciousPatterns());
        assertTrue(config.logSecurityViolations());
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 5)
    void shouldValidatePositivePathLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxPathLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxPathLength must be positive"));
    }

    static class InvalidPositiveIntegerGenerator implements TypedGenerator<Integer> {
        private final TypedGenerator<Integer> gen = Generators.fixedValues(Integer.class, 0, -1, -100, -999, -1000000);

        @Override
        public Integer next() {
            return gen.next();
        }

        @Override
        public Class<Integer> getType() {
            return Integer.class;
        }
    }

    @Test
    void shouldAllowZeroParameterCount() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterCount(0)
                .build();
        assertEquals(0, config.maxParameterCount());
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = NegativeIntegerGenerator.class, count = 5)
    void shouldValidateNonNegativeParameterCount(Integer negativeValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterCount(negativeValue).build());
        assertTrue(thrown.getMessage().contains("maxParameterCount must be non-negative"));
    }

    static class NegativeIntegerGenerator implements TypedGenerator<Integer> {
        private final TypedGenerator<Integer> gen = Generators.fixedValues(Integer.class, -1, -10, -100, -999, -1000000);

        @Override
        public Integer next() {
            return gen.next();
        }

        @Override
        public Class<Integer> getType() {
            return Integer.class;
        }
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveParameterNameLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterNameLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxParameterNameLength must be positive"));
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveParameterValueLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxParameterValueLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxParameterValueLength must be positive"));
    }

    @Test
    void shouldAllowZeroHeaderCount() {
        SecurityConfiguration.builder().maxHeaderCount(0).build(); // Should work
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = NegativeIntegerGenerator.class, count = 3)
    void shouldValidateNonNegativeHeaderCount(Integer negativeValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderCount(negativeValue).build());
        assertTrue(thrown.getMessage().contains("maxHeaderCount must be non-negative"));
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveHeaderNameLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderNameLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxHeaderNameLength must be positive"));
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveHeaderValueLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxHeaderValueLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxHeaderValueLength must be positive"));
    }

    @Test
    void shouldAllowZeroCookieCount() {
        SecurityConfiguration.builder().maxCookieCount(0).build(); // Should work
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = NegativeIntegerGenerator.class, count = 3)
    void shouldValidateNonNegativeCookieCount(Integer negativeValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieCount(negativeValue).build());
        assertTrue(thrown.getMessage().contains("maxCookieCount must be non-negative"));
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveCookieNameLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieNameLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxCookieNameLength must be positive"));
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidPositiveIntegerGenerator.class, count = 3)
    void shouldValidatePositiveCookieValueLength(Integer invalidValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxCookieValueLength(invalidValue).build());
        assertTrue(thrown.getMessage().contains("maxCookieValueLength must be positive"));
    }

    @Test
    void shouldAllowZeroBodySize() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxBodySize(0)
                .build();
        assertEquals(0, config.maxBodySize());
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = NegativeIntegerGenerator.class, count = 3)
    void shouldValidateNonNegativeBodySize(Integer negativeValue) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                SecurityConfiguration.builder().maxBodySize(negativeValue).build());
        assertTrue(thrown.getMessage().contains("maxBodySize must be non-negative"));
    }

    @Test
    void shouldHandleNullAllowedHeaderNames() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(null)
                .build();

        assertNull(config.allowedHeaderNames());
    }

    @Test
    void shouldMakeImmutableCopiesOfSets() {
        Set<String> mutableHeaders = new HashSet<>();
        mutableHeaders.add("X-Test");

        Set<String> mutableContentTypes = new HashSet<>();
        mutableContentTypes.add("text/test");

        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedHeaderNames(mutableHeaders)
                .blockedContentTypes(mutableContentTypes)
                .build();

        // Modify original sets
        mutableHeaders.add("X-Modified");
        mutableContentTypes.add("text/modified");

        // Configuration should be unaffected
        assertEquals(1, config.blockedHeaderNames().size());
        assertTrue(config.blockedHeaderNames().contains("X-Test"));
        assertFalse(config.blockedHeaderNames().contains("X-Modified"));

        assertEquals(1, config.blockedContentTypes().size());
        assertTrue(config.blockedContentTypes().contains("text/test"));
        assertFalse(config.blockedContentTypes().contains("text/modified"));
    }

    @Test
    void shouldCheckIfHeaderIsAllowed() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(Set.of("X-Allowed", "Authorization"))
                .blockedHeaderNames(Set.of("X-Blocked", "X-Debug"))
                .build();

        assertTrue(config.isHeaderAllowed("X-Allowed"));
        assertTrue(config.isHeaderAllowed("Authorization"));
        assertFalse(config.isHeaderAllowed("X-Blocked"));
        assertFalse(config.isHeaderAllowed("X-Debug"));
        assertFalse(config.isHeaderAllowed("X-Other")); // Not in allow list
        assertFalse(config.isHeaderAllowed(null));
    }

    @Test
    void shouldCheckHeadersWhenOnlyBlockListExists() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedHeaderNames(Set.of("X-Blocked", "X-Debug"))
                .build();

        assertTrue(config.isHeaderAllowed("X-Allowed")); // Not blocked, no allow list
        assertFalse(config.isHeaderAllowed("X-Blocked"));
        assertFalse(config.isHeaderAllowed("X-Debug"));
        assertTrue(config.isHeaderAllowed("Authorization")); // Not blocked
    }

    @Test
    void shouldCheckHeadersCaseInsensitively() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(Set.of("X-ALLOWED"))
                .blockedHeaderNames(Set.of("X-BLOCKED"))
                .caseSensitiveComparison(false)
                .build();

        assertTrue(config.isHeaderAllowed("x-allowed"));
        assertTrue(config.isHeaderAllowed("X-allowed"));
        assertFalse(config.isHeaderAllowed("x-blocked"));
        assertFalse(config.isHeaderAllowed("X-blocked"));
    }

    @Test
    void shouldCheckHeadersCaseSensitively() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedHeaderNames(Set.of("X-Blocked"))
                .caseSensitiveComparison(true)
                .build();

        assertTrue(config.isHeaderAllowed("X-Allowed")); // Not blocked, no allow list
        assertTrue(config.isHeaderAllowed("x-allowed")); // Not blocked, no allow list
        assertFalse(config.isHeaderAllowed("X-Blocked")); // Exact match blocked
        assertTrue(config.isHeaderAllowed("x-blocked")); // Wrong case, so allowed
    }

    @Test
    void shouldCheckIfContentTypeIsAllowed() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedContentTypes(Set.of("application/json", "text/plain"))
                .blockedContentTypes(Set.of("application/x-executable", "text/x-script"))
                .build();

        assertTrue(config.isContentTypeAllowed("application/json"));
        assertTrue(config.isContentTypeAllowed("text/plain"));
        assertFalse(config.isContentTypeAllowed("application/x-executable"));
        assertFalse(config.isContentTypeAllowed("text/x-script"));
        assertFalse(config.isContentTypeAllowed("text/html")); // Not in allow list
        assertFalse(config.isContentTypeAllowed(null));
    }

    @Test
    void shouldCheckContentTypeWhenOnlyBlockListExists() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedContentTypes(Set.of("application/x-executable"))
                .build();

        assertTrue(config.isContentTypeAllowed("application/json")); // Not blocked, no allow list
        assertFalse(config.isContentTypeAllowed("application/x-executable"));
        assertTrue(config.isContentTypeAllowed("text/plain")); // Not blocked
    }

    @Test
    void shouldDetectStrictConfiguration() {
        SecurityConfiguration strict = SecurityConfiguration.strict();
        assertTrue(strict.isStrict());

        SecurityConfiguration lenient = SecurityConfiguration.lenient();
        assertFalse(lenient.isStrict());

        SecurityConfiguration defaults = SecurityConfiguration.defaults();
        assertFalse(defaults.isStrict());
    }

    @Test
    void shouldDetectLenientConfiguration() {
        SecurityConfiguration lenient = SecurityConfiguration.lenient();
        assertTrue(lenient.isLenient());

        SecurityConfiguration strict = SecurityConfiguration.strict();
        assertFalse(strict.isLenient());

        SecurityConfiguration defaults = SecurityConfiguration.defaults();
        assertFalse(defaults.isLenient()); // Default is balanced
    }

    @Test
    void shouldCreateConfigurationWithModifiedPathSecurity() {
        SecurityConfiguration original = SecurityConfiguration.defaults();
        SecurityConfiguration modified = original.withPathSecurity(2048, true);

        assertEquals(2048, modified.maxPathLength());
        assertTrue(modified.allowPathTraversal());

        // Original should be unchanged
        assertEquals(4096, original.maxPathLength());
        assertFalse(original.allowPathTraversal());

        // Other settings should be preserved
        assertEquals(original.maxParameterCount(), modified.maxParameterCount());
        assertEquals(original.logSecurityViolations(), modified.logSecurityViolations());
    }

    @Test
    void shouldCreateConfigurationWithModifiedCookieSecurity() {
        SecurityConfiguration original = SecurityConfiguration.defaults();
        SecurityConfiguration modified = original.withCookieSecurity(true, true);

        assertTrue(modified.requireSecureCookies());
        assertTrue(modified.requireHttpOnlyCookies());

        // Original should be unchanged
        assertFalse(original.requireSecureCookies());
        assertFalse(original.requireHttpOnlyCookies());

        // Other settings should be preserved
        assertEquals(original.maxPathLength(), modified.maxPathLength());
        assertEquals(original.logSecurityViolations(), modified.logSecurityViolations());
    }

    @Test
    void shouldCreateConfigurationWithModifiedLogging() {
        SecurityConfiguration original = SecurityConfiguration.defaults();
        SecurityConfiguration modified = original.withLogging(false);

        assertFalse(modified.logSecurityViolations());

        // Original should be unchanged
        assertTrue(original.logSecurityViolations());

        // Other settings should be preserved
        assertEquals(original.maxPathLength(), modified.maxPathLength());
        assertEquals(original.requireSecureCookies(), modified.requireSecureCookies());
    }

    @Test
    void shouldSupportEquality() {
        SecurityConfiguration config1 = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .allowPathTraversal(false)
                .build();

        SecurityConfiguration config2 = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .allowPathTraversal(false)
                .build();

        SecurityConfiguration config3 = SecurityConfiguration.builder()
                .maxPathLength(1024)
                .allowPathTraversal(false)
                .build();

        assertEquals(config1, config2);
        assertNotEquals(config1, config3);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    void shouldSupportToString() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .allowPathTraversal(false)
                .requireSecureCookies(true)
                .build();

        String string = config.toString();
        assertTrue(string.contains("2048"));
        assertTrue(string.contains("false"));
        assertTrue(string.contains("true"));
    }

    @Test
    void shouldHandleEmptySets() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(Set.of())
                .blockedHeaderNames(Set.of())
                .allowedContentTypes(Set.of())
                .blockedContentTypes(Set.of())
                .build();

        assertTrue(config.allowedHeaderNames().isEmpty());
        assertTrue(config.blockedHeaderNames().isEmpty());
        assertTrue(config.allowedContentTypes().isEmpty());
        assertTrue(config.blockedContentTypes().isEmpty());
    }

    @Test
    void shouldHandleComplexScenarios() {
        // Configuration with mixed allow/block lists
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowedHeaderNames(Set.of("Content-Type", "Authorization", "X-Custom"))
                .blockedHeaderNames(Set.of("X-Debug", "X-Internal"))
                .allowedContentTypes(Set.of("application/json", "text/plain"))
                .blockedContentTypes(Set.of("application/x-executable"))
                .caseSensitiveComparison(false)
                .build();

        // Headers
        assertTrue(config.isHeaderAllowed("content-type")); // Case insensitive
        assertTrue(config.isHeaderAllowed("AUTHORIZATION"));
        assertFalse(config.isHeaderAllowed("x-debug")); // Blocked
        assertFalse(config.isHeaderAllowed("Accept")); // Not in allow list

        // Content types
        assertTrue(config.isContentTypeAllowed("APPLICATION/JSON")); // Case insensitive
        assertFalse(config.isContentTypeAllowed("application/x-executable")); // Blocked
        assertFalse(config.isContentTypeAllowed("text/html")); // Not in allow list
    }

    @Test
    void shouldPreserveImmutabilityOfReturnedSets() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .blockedHeaderNames(Set.of("X-Test"))
                .build();

        assertThrows(UnsupportedOperationException.class, () ->
                config.blockedHeaderNames().add("X-Modified"));
    }
}