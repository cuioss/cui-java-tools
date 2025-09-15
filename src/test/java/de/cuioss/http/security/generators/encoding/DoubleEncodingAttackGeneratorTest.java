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
package de.cuioss.http.security.generators.encoding;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link DoubleEncodingAttackGenerator}
 */
@EnableGeneratorController
class DoubleEncodingAttackGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = DoubleEncodingAttackGenerator.class, count = 100)
    @DisplayName("Generator should produce valid double encoding attack patterns")
    void shouldGenerateValidOutput(String generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertFalse(generatedValue.isEmpty(), "Generated value should not be empty");

        // Every pattern should contain double encoding indicators
        boolean hasDoubleEncoding = generatedValue.contains("%252") ||  // Standard double encoding
                generatedValue.contains("%%3") ||                           // CVE-style double encoding
                generatedValue.contains("%25252") ||                        // Triple encoding
                generatedValue.contains("%255");                            // Double encoding of backslash
        assertTrue(hasDoubleEncoding,
                "Pattern should contain double encoding: " + generatedValue);

        // Generated patterns should be reasonable length
        assertTrue(generatedValue.length() < 500, "Pattern should not be excessively long: " + generatedValue);
    }
}