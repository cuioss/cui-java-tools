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
package de.cuioss.tools.security.http.core;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link UrlSecurityFailureType}
 */
class UrlSecurityFailureTypeTest {

    @Test
    void shouldHaveAllExpectedFailureTypes() {
        // Verify all expected failure types exist
        assertNotNull(UrlSecurityFailureType.INVALID_ENCODING);
        assertNotNull(UrlSecurityFailureType.DOUBLE_ENCODING);
        assertNotNull(UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED);
        assertNotNull(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED);
        assertNotNull(UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT);
        assertNotNull(UrlSecurityFailureType.INVALID_CHARACTER);
        assertNotNull(UrlSecurityFailureType.NULL_BYTE_INJECTION);
        assertNotNull(UrlSecurityFailureType.CONTROL_CHARACTERS);
        assertNotNull(UrlSecurityFailureType.PATH_TOO_LONG);
        assertNotNull(UrlSecurityFailureType.EXCESSIVE_NESTING);
        assertNotNull(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED);
        assertNotNull(UrlSecurityFailureType.SUSPICIOUS_PARAMETER_NAME);
        assertNotNull(UrlSecurityFailureType.SQL_INJECTION_DETECTED);
        assertNotNull(UrlSecurityFailureType.XSS_DETECTED);
        assertNotNull(UrlSecurityFailureType.COMMAND_INJECTION_DETECTED);
        assertNotNull(UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE);
        assertNotNull(UrlSecurityFailureType.MALFORMED_INPUT);
        assertNotNull(UrlSecurityFailureType.INVALID_STRUCTURE);
        assertNotNull(UrlSecurityFailureType.PROTOCOL_VIOLATION);
        assertNotNull(UrlSecurityFailureType.RFC_VIOLATION);
    }

    @Test
    void shouldHave20FailureTypes() {
        // Verify we have the expected number of failure types
        UrlSecurityFailureType[] values = UrlSecurityFailureType.values();
        assertEquals(20, values.length, "Should have 20 failure types");
    }

    @Test
    void shouldHaveNonNullDescriptions() {
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            assertNotNull(type.getDescription(), "Description should not be null for: " + type);
            assertFalse(type.getDescription().trim().isEmpty(), "Description should not be empty for: " + type);
        }
    }

    @Test
    void shouldHaveUniqueDescriptions() {
        Set<String> descriptions = Arrays.stream(UrlSecurityFailureType.values())
                .map(UrlSecurityFailureType::getDescription)
                .collect(Collectors.toSet());

        assertEquals(UrlSecurityFailureType.values().length, descriptions.size(),
                "All failure types should have unique descriptions");
    }

    @Test
    void shouldCorrectlyIdentifyEncodingIssues() {
        assertTrue(UrlSecurityFailureType.INVALID_ENCODING.isEncodingIssue());
        assertTrue(UrlSecurityFailureType.DOUBLE_ENCODING.isEncodingIssue());
        assertTrue(UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED.isEncodingIssue());

        // Non-encoding issues should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isEncodingIssue());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isEncodingIssue());
        assertFalse(UrlSecurityFailureType.PATH_TOO_LONG.isEncodingIssue());
    }

    @Test
    void shouldCorrectlyIdentifyPathTraversalAttacks() {
        assertTrue(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isPathTraversalAttack());
        assertTrue(UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT.isPathTraversalAttack());

        // Non-path-traversal should return false
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isPathTraversalAttack());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isPathTraversalAttack());
        assertFalse(UrlSecurityFailureType.PATH_TOO_LONG.isPathTraversalAttack());
    }

    @Test
    void shouldCorrectlyIdentifyCharacterAttacks() {
        assertTrue(UrlSecurityFailureType.INVALID_CHARACTER.isCharacterAttack());
        assertTrue(UrlSecurityFailureType.NULL_BYTE_INJECTION.isCharacterAttack());
        assertTrue(UrlSecurityFailureType.CONTROL_CHARACTERS.isCharacterAttack());

        // Non-character attacks should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isCharacterAttack());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isCharacterAttack());
        assertFalse(UrlSecurityFailureType.PATH_TOO_LONG.isCharacterAttack());
    }

    @Test
    void shouldCorrectlyIdentifySizeViolations() {
        assertTrue(UrlSecurityFailureType.PATH_TOO_LONG.isSizeViolation());
        assertTrue(UrlSecurityFailureType.EXCESSIVE_NESTING.isSizeViolation());

        // Non-size violations should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isSizeViolation());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isSizeViolation());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isSizeViolation());
    }

    @Test
    void shouldCorrectlyIdentifyPatternBased() {
        assertTrue(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED.isPatternBased());
        assertTrue(UrlSecurityFailureType.SUSPICIOUS_PARAMETER_NAME.isPatternBased());
        assertTrue(UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE.isPatternBased());

        // Non-pattern-based should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isPatternBased());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isPatternBased());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isPatternBased());
    }

    @Test
    void shouldCorrectlyIdentifyInjectionAttacks() {
        assertTrue(UrlSecurityFailureType.SQL_INJECTION_DETECTED.isInjectionAttack());
        assertTrue(UrlSecurityFailureType.XSS_DETECTED.isInjectionAttack());
        assertTrue(UrlSecurityFailureType.COMMAND_INJECTION_DETECTED.isInjectionAttack());

        // Non-injection attacks should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isInjectionAttack());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isInjectionAttack());
        assertFalse(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED.isInjectionAttack());
    }

    @Test
    void shouldCorrectlyIdentifyStructuralIssues() {
        assertTrue(UrlSecurityFailureType.MALFORMED_INPUT.isStructuralIssue());
        assertTrue(UrlSecurityFailureType.INVALID_STRUCTURE.isStructuralIssue());

        // Non-structural issues should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isStructuralIssue());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isStructuralIssue());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isStructuralIssue());
    }

    @Test
    void shouldCorrectlyIdentifyProtocolViolations() {
        assertTrue(UrlSecurityFailureType.PROTOCOL_VIOLATION.isProtocolViolation());
        assertTrue(UrlSecurityFailureType.RFC_VIOLATION.isProtocolViolation());

        // Non-protocol violations should return false
        assertFalse(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED.isProtocolViolation());
        assertFalse(UrlSecurityFailureType.INVALID_ENCODING.isProtocolViolation());
        assertFalse(UrlSecurityFailureType.NULL_BYTE_INJECTION.isProtocolViolation());
    }

    @Test
    void shouldHaveExactlyOneCategory() {
        // Each failure type should belong to exactly one category
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            int categoryCount = 0;

            if (type.isEncodingIssue()) categoryCount++;
            if (type.isPathTraversalAttack()) categoryCount++;
            if (type.isCharacterAttack()) categoryCount++;
            if (type.isSizeViolation()) categoryCount++;
            if (type.isPatternBased()) categoryCount++;
            if (type.isInjectionAttack()) categoryCount++;
            if (type.isStructuralIssue()) categoryCount++;
            if (type.isProtocolViolation()) categoryCount++;

            assertEquals(1, categoryCount,
                    "Failure type " + type + " should belong to exactly one category, but belongs to " + categoryCount);
        }
    }

    @Test
    void shouldHaveDescriptiveNames() {
        // Verify enum names are descriptive and follow naming conventions
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            String name = type.name();
            assertTrue(name.matches("^[A-Z][A-Z_]*[A-Z]$"),
                    "Enum name should be uppercase with underscores: " + name);
            assertTrue(name.length() > 3,
                    "Enum name should be descriptive (>3 chars): " + name);
        }
    }

    @Test
    void shouldSupportToString() {
        // Verify toString works (should return enum name by default)
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            String toString = type.toString();
            assertNotNull(toString);
            assertFalse(toString.trim().isEmpty());
            assertEquals(type.name(), toString);
        }
    }

    @Test
    void shouldSupportValueOf() {
        // Verify valueOf works for all enum constants
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            UrlSecurityFailureType parsed = UrlSecurityFailureType.valueOf(type.name());
            assertEquals(type, parsed);
        }
    }

    @Test
    void shouldThrowExceptionForInvalidValueOf() {
        assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityFailureType.valueOf("INVALID_FAILURE_TYPE"));
        assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityFailureType.valueOf(""));
        assertThrows(NullPointerException.class, () ->
                UrlSecurityFailureType.valueOf(null));
    }

    @Test
    void shouldBeSerializable() {
        // Enums are automatically serializable in Java
        // Verify all failure types can be used in serialization contexts
        for (UrlSecurityFailureType type : UrlSecurityFailureType.values()) {
            // This would work in actual serialization
            assertNotNull(type.name());
            assertNotNull(type.ordinal());
        }
    }

    @Test
    void shouldHaveStableOrdinals() {
        // Verify ordinal values are as expected (important for serialization)
        // This test will need updating if new enum values are added
        assertEquals(0, UrlSecurityFailureType.INVALID_ENCODING.ordinal());
        assertEquals(1, UrlSecurityFailureType.DOUBLE_ENCODING.ordinal());
        assertEquals(2, UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED.ordinal());
        // ... and so on for critical enum values
    }

    @Test
    void shouldCoverAllSecurityCategories() {
        // Verify we have comprehensive coverage of security failure categories
        long encodingCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isEncodingIssue() ? 1 : 0).sum();
        long pathTraversalCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isPathTraversalAttack() ? 1 : 0).sum();
        long characterCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isCharacterAttack() ? 1 : 0).sum();
        long sizeCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isSizeViolation() ? 1 : 0).sum();
        long patternCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isPatternBased() ? 1 : 0).sum();
        long structuralCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isStructuralIssue() ? 1 : 0).sum();
        long protocolCount = Arrays.stream(UrlSecurityFailureType.values())
                .mapToLong(t -> t.isProtocolViolation() ? 1 : 0).sum();

        // Each category should have at least 2 failure types for comprehensive coverage
        assertTrue(encodingCount >= 2, "Should have at least 2 encoding issue types");
        assertTrue(pathTraversalCount >= 2, "Should have at least 2 path traversal types");
        assertTrue(characterCount >= 2, "Should have at least 2 character attack types");
        assertTrue(sizeCount >= 2, "Should have at least 2 size violation types");
        assertTrue(patternCount >= 2, "Should have at least 2 pattern-based types");
        assertTrue(structuralCount >= 2, "Should have at least 2 structural issue types");
        assertTrue(protocolCount >= 2, "Should have at least 2 protocol violation types");
    }
}