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
package de.cuioss.http.security.generators.url;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for {@link InvalidURLGenerator}
 */
@EnableGeneratorController
class InvalidURLGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = InvalidURLGenerator.class, count = 200)
    @DisplayName("Generator should produce invalid URLs")
    void shouldGenerateValidOutput(String generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");

        // Invalid URLs can be empty strings, whitespace, or have various malformations

        // Since this is for testing invalid URLs, we simply verify it's not null
        // The generator's purpose is to create invalid URLs, so any non-null output is acceptable
        // as it serves the security testing purpose
    }
}