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

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.http.security.data.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ValidCookieGenerator}
 * Tests framework-compliant generator for legitimate cookie patterns.
 */
@EnableGeneratorController
class ValidCookieGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidCookieGenerator.class, count = 100)
    @DisplayName("Generator should produce valid cookies")
    void shouldGenerateValidOutput(Cookie generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertNotNull(generatedValue.name(), "Cookie name should not be null");
        assertNotNull(generatedValue.value(), "Cookie value should not be null");
        assertNotNull(generatedValue.attributes(), "Cookie attributes should not be null");

        // Validate name is not empty for valid cookies
        assertFalse(generatedValue.name().isEmpty(), "Cookie name should not be empty");

        // Validate cookie structure
        String toString = generatedValue.toString();
        assertTrue(toString.contains("Cookie"), "toString should contain record name");

        // Test equals and hashCode work (records auto-generate these)
        Cookie duplicate = new Cookie(generatedValue.name(), generatedValue.value(), generatedValue.attributes());
        assertEquals(generatedValue, duplicate, "Equal cookies should be equal");
        assertEquals(generatedValue.hashCode(), duplicate.hashCode(), "Equal cookies should have same hash code");
    }
}