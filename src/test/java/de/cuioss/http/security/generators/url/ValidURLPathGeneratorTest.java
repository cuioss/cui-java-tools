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

import static org.junit.jupiter.api.Assertions.*;

/**
 * QI-5: Basic generator test for ValidURLPathGenerator.
 *
 * <p>
 * Simple validation to ensure the generator works without exceptions and produces
 * non-null, non-empty output. Following cui-test-generator lightweight testing pattern.
 * </p>
 *
 * @author QI-5 Generator Coverage Initiative
 */
@EnableGeneratorController
class ValidURLPathGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLPathGenerator.class, count = 10)
    @DisplayName("Generator should produce valid non-null URL paths")
    void shouldGenerateValidOutput(String generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertFalse(generatedValue.isEmpty(), "Generator should produce non-empty URL paths");
        assertTrue(generatedValue.length() > 1, "URL paths should be meaningful (more than 1 character)");
    }
}