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
package de.cuioss.http.security.core;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ValidationType}
 */
class ValidationTypeTest {

    @Test
    void shouldHaveAllExpectedValidationTypes() {
        // Verify all expected validation types exist
        assertNotNull(ValidationType.URL_PATH);
        assertNotNull(ValidationType.PARAMETER_NAME);
        assertNotNull(ValidationType.PARAMETER_VALUE);
        assertNotNull(ValidationType.HEADER_NAME);
        assertNotNull(ValidationType.HEADER_VALUE);
        assertNotNull(ValidationType.COOKIE_NAME);
        assertNotNull(ValidationType.COOKIE_VALUE);
        assertNotNull(ValidationType.BODY);
    }

    @Test
    void shouldHave8ValidationTypes() {
        // Verify we have the expected number of validation types
        ValidationType[] values = ValidationType.values();
        assertEquals(8, values.length, "Should have 8 validation types");
    }

    @Test
    void shouldCorrectlyIdentifyDecodingRequirement() {
        // Types that require decoding
        assertTrue(ValidationType.URL_PATH.requiresDecoding());
        assertTrue(ValidationType.PARAMETER_NAME.requiresDecoding());
        assertTrue(ValidationType.PARAMETER_VALUE.requiresDecoding());

        // Types that don't require decoding
        assertFalse(ValidationType.HEADER_NAME.requiresDecoding());
        assertFalse(ValidationType.HEADER_VALUE.requiresDecoding());
        assertFalse(ValidationType.COOKIE_NAME.requiresDecoding());
        assertFalse(ValidationType.COOKIE_VALUE.requiresDecoding());
        assertFalse(ValidationType.BODY.requiresDecoding());
    }

    @Test
    void shouldCorrectlyIdentifyKeyComponents() {
        // Types that are key components
        assertTrue(ValidationType.PARAMETER_NAME.isKey());
        assertTrue(ValidationType.HEADER_NAME.isKey());
        assertTrue(ValidationType.COOKIE_NAME.isKey());

        // Types that are not key components
        assertFalse(ValidationType.URL_PATH.isKey());
        assertFalse(ValidationType.PARAMETER_VALUE.isKey());
        assertFalse(ValidationType.HEADER_VALUE.isKey());
        assertFalse(ValidationType.COOKIE_VALUE.isKey());
        assertFalse(ValidationType.BODY.isKey());
    }

    @Test
    void shouldCorrectlyIdentifyValueComponents() {
        // Types that are value components
        assertTrue(ValidationType.PARAMETER_VALUE.isValue());
        assertTrue(ValidationType.HEADER_VALUE.isValue());
        assertTrue(ValidationType.COOKIE_VALUE.isValue());

        // Types that are not value components
        assertFalse(ValidationType.URL_PATH.isValue());
        assertFalse(ValidationType.PARAMETER_NAME.isValue());
        assertFalse(ValidationType.HEADER_NAME.isValue());
        assertFalse(ValidationType.COOKIE_NAME.isValue());
        assertFalse(ValidationType.BODY.isValue());
    }

    @Test
    void shouldCorrectlyIdentifyBodyComponents() {
        // Only BODY should be a body component
        assertTrue(ValidationType.BODY.isBody());

        // All other types should not be body components
        assertFalse(ValidationType.URL_PATH.isBody());
        assertFalse(ValidationType.PARAMETER_NAME.isBody());
        assertFalse(ValidationType.PARAMETER_VALUE.isBody());
        assertFalse(ValidationType.HEADER_NAME.isBody());
        assertFalse(ValidationType.HEADER_VALUE.isBody());
        assertFalse(ValidationType.COOKIE_NAME.isBody());
        assertFalse(ValidationType.COOKIE_VALUE.isBody());
    }

    @Test
    void shouldCorrectlyIdentifyPathComponents() {
        // Only URL_PATH should be a path component
        assertTrue(ValidationType.URL_PATH.isPath());

        // All other types should not be path components
        assertFalse(ValidationType.PARAMETER_NAME.isPath());
        assertFalse(ValidationType.PARAMETER_VALUE.isPath());
        assertFalse(ValidationType.HEADER_NAME.isPath());
        assertFalse(ValidationType.HEADER_VALUE.isPath());
        assertFalse(ValidationType.COOKIE_NAME.isPath());
        assertFalse(ValidationType.COOKIE_VALUE.isPath());
        assertFalse(ValidationType.BODY.isPath());
    }

    @Test
    void shouldCorrectlyIdentifyHeaderComponents() {
        // Header types should be identified as header components
        assertTrue(ValidationType.HEADER_NAME.isHeader());
        assertTrue(ValidationType.HEADER_VALUE.isHeader());

        // Non-header types should not be header components
        assertFalse(ValidationType.URL_PATH.isHeader());
        assertFalse(ValidationType.PARAMETER_NAME.isHeader());
        assertFalse(ValidationType.PARAMETER_VALUE.isHeader());
        assertFalse(ValidationType.COOKIE_NAME.isHeader());
        assertFalse(ValidationType.COOKIE_VALUE.isHeader());
        assertFalse(ValidationType.BODY.isHeader());
    }

    @Test
    void shouldCorrectlyIdentifyCookieComponents() {
        // Cookie types should be identified as cookie components
        assertTrue(ValidationType.COOKIE_NAME.isCookie());
        assertTrue(ValidationType.COOKIE_VALUE.isCookie());

        // Non-cookie types should not be cookie components
        assertFalse(ValidationType.URL_PATH.isCookie());
        assertFalse(ValidationType.PARAMETER_NAME.isCookie());
        assertFalse(ValidationType.PARAMETER_VALUE.isCookie());
        assertFalse(ValidationType.HEADER_NAME.isCookie());
        assertFalse(ValidationType.HEADER_VALUE.isCookie());
        assertFalse(ValidationType.BODY.isCookie());
    }

    @Test
    void shouldCorrectlyIdentifyParameterComponents() {
        // Parameter types should be identified as parameter components
        assertTrue(ValidationType.PARAMETER_NAME.isParameter());
        assertTrue(ValidationType.PARAMETER_VALUE.isParameter());

        // Non-parameter types should not be parameter components
        assertFalse(ValidationType.URL_PATH.isParameter());
        assertFalse(ValidationType.HEADER_NAME.isParameter());
        assertFalse(ValidationType.HEADER_VALUE.isParameter());
        assertFalse(ValidationType.COOKIE_NAME.isParameter());
        assertFalse(ValidationType.COOKIE_VALUE.isParameter());
        assertFalse(ValidationType.BODY.isParameter());
    }

    @Test
    void shouldHaveUniqueClassifications() {
        // Verify that the type classifications don't overlap inappropriately
        for (ValidationType type : ValidationType.values()) {
            // A type should not be both key and value
            assertFalse(type.isKey() && type.isValue(),
                    type + " should not be both key and value");

            // Body should be distinct from other categories
            if (type.isBody()) {
                assertFalse(type.isKey() || type.isValue() || type.isPath() ||
                        type.isHeader() || type.isCookie() || type.isParameter(),
                        type + " should not be body and another category");
            }

            // Path should be distinct from key/value pairs
            if (type.isPath()) {
                assertFalse(type.isKey() || type.isValue(),
                        type + " should not be path and key/value");
            }
        }
    }

    @Test
    void shouldCoverAllTypesInCategories() {
        // Every type should belong to at least one logical category
        for (ValidationType type : ValidationType.values()) {
            boolean hasCategory = type.isKey() || type.isValue() || type.isBody() || type.isPath();
            assertTrue(hasCategory, type + " should belong to at least one category");
        }
    }

    @Test
    void shouldHaveDescriptiveNames() {
        // Verify enum names are descriptive and follow naming conventions
        for (ValidationType type : ValidationType.values()) {
            String name = type.name();
            assertTrue(name.matches("^[A-Z][A-Z_]*[A-Z]$|^[A-Z]+$"),
                    "Enum name should be uppercase with underscores: " + name);
            assertTrue(name.length() > 3,
                    "Enum name should be descriptive (>3 chars): " + name);
        }
    }

    @Test
    void shouldSupportToString() {
        // Verify toString works (should return enum name by default)
        for (ValidationType type : ValidationType.values()) {
            String toString = type.toString();
            assertNotNull(toString);
            assertFalse(toString.trim().isEmpty());
            assertEquals(type.name(), toString);
        }
    }

    @Test
    void shouldSupportValueOf() {
        // Verify valueOf works for all enum constants
        for (ValidationType type : ValidationType.values()) {
            ValidationType parsed = ValidationType.valueOf(type.name());
            assertEquals(type, parsed);
        }
    }

    @Test
    void shouldThrowExceptionForInvalidValueOf() {
        assertThrows(IllegalArgumentException.class, () ->
                ValidationType.valueOf("INVALID_TYPE"));
        assertThrows(IllegalArgumentException.class, () ->
                ValidationType.valueOf(""));
        assertThrows(NullPointerException.class, () ->
                ValidationType.valueOf(null));
    }

    @Test
    void shouldHaveStableOrdinals() {
        // Verify ordinal values are as expected (important for serialization)
        assertEquals(0, ValidationType.URL_PATH.ordinal());
        assertEquals(1, ValidationType.PARAMETER_NAME.ordinal());
        assertEquals(2, ValidationType.PARAMETER_VALUE.ordinal());
        assertEquals(3, ValidationType.HEADER_NAME.ordinal());
        assertEquals(4, ValidationType.HEADER_VALUE.ordinal());
        assertEquals(5, ValidationType.COOKIE_NAME.ordinal());
        assertEquals(6, ValidationType.COOKIE_VALUE.ordinal());
        assertEquals(7, ValidationType.BODY.ordinal());
    }

    @Test
    void shouldBeSerializable() {
        // Enums are automatically serializable in Java
        // Verify all validation types can be used in serialization contexts
        for (ValidationType type : ValidationType.values()) {
            assertNotNull(type.name());
            assertTrue(type.ordinal() >= 0);
        }
    }

    @Test
    void shouldHaveLogicalGroupings() {
        // Verify logical groupings make sense
        Set<ValidationType> keyTypes = Arrays.stream(ValidationType.values())
                .filter(ValidationType::isKey)
                .collect(Collectors.toSet());
        Set<ValidationType> valueTypes = Arrays.stream(ValidationType.values())
                .filter(ValidationType::isValue)
                .collect(Collectors.toSet());

        assertEquals(3, keyTypes.size(), "Should have exactly 3 key types");
        assertEquals(3, valueTypes.size(), "Should have exactly 3 value types");

        // Key and value types should be disjoint
        assertTrue(keyTypes.stream().noneMatch(ValidationType::isValue),
                "Key types should not overlap with value types");
        assertTrue(valueTypes.stream().noneMatch(ValidationType::isKey),
                "Value types should not overlap with key types");
    }

    @Test
    void shouldHaveCorrectDecodingLogic() {
        // URL-related components should require decoding
        long decodingTypes = Arrays.stream(ValidationType.values())
                .filter(ValidationType::requiresDecoding)
                .count();

        assertEquals(3, decodingTypes, "Should have exactly 3 types requiring decoding");

        // Verify the specific types that require decoding
        assertTrue(ValidationType.URL_PATH.requiresDecoding());
        assertTrue(ValidationType.PARAMETER_NAME.requiresDecoding());
        assertTrue(ValidationType.PARAMETER_VALUE.requiresDecoding());
    }
}