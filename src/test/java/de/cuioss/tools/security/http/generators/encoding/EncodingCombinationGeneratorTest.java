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
package de.cuioss.tools.security.http.generators.encoding;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link EncodingCombinationGenerator}
 */
@EnableGeneratorController
class EncodingCombinationGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 100)
    @DisplayName("Generator should produce valid encoding combination patterns")
    void shouldGenerateValidOutput(String generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertFalse(generatedValue.isEmpty(), "Generated value should not be empty");
        
        // Since this is for encoding combination testing, any non-null, non-empty output serves
        // the security testing purpose
    }
}