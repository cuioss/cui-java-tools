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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.data.URLParameter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * QI-5: Basic generator test for ValidURLParameterGenerator.
 * 
 * <p>
 * Simple validation to ensure the generator works without exceptions and produces 
 * non-null, non-empty output. Following cui-test-generator lightweight testing pattern.
 * </p>
 *
 * @author QI-5 Generator Coverage Initiative
 */
@EnableGeneratorController
class ValidURLParameterGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLParameterGenerator.class, count = 10)
    @DisplayName("Generator should produce valid non-null URL parameters")
    void shouldGenerateValidOutput(URLParameter generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertNotNull(generatedValue.name(), "URL parameter name should not be null");
        assertFalse(generatedValue.name().isEmpty(), "URL parameter name should not be empty");
        assertTrue(generatedValue.name().length() > 1, "URL parameter names should be meaningful (more than 1 character)");
    }
}