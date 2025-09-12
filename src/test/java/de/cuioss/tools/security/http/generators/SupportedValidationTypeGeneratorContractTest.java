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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.core.ValidationType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for SupportedValidationTypeGenerator.
 * 
 * <p>Validates that SupportedValidationTypeGenerator produces only the 
 * supported validation types as documented in its implementation.</p>
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("SupportedValidationTypeGenerator Tests")
class SupportedValidationTypeGeneratorContractTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = SupportedValidationTypeGenerator.class, count = 100)
    @DisplayName("Generator should produce valid non-null validation types")
    void shouldGenerateValidOutput(ValidationType generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");

        // Verify it's one of the supported types
        Set<ValidationType> supportedTypes = EnumSet.of(
                ValidationType.URL_PATH,
                ValidationType.PARAMETER_VALUE,
                ValidationType.HEADER_NAME,
                ValidationType.HEADER_VALUE,
                ValidationType.BODY
        );

        assertTrue(supportedTypes.contains(generatedValue),
                "Generated type must be one of the supported types. Got: " + generatedValue);
    }

    @Test
    @DisplayName("Should generate all supported validation types")
    void shouldGenerateAllSupportedTypes() {
        SupportedValidationTypeGenerator generator = new SupportedValidationTypeGenerator();

        Set<ValidationType> expectedTypes = EnumSet.of(
                ValidationType.URL_PATH,
                ValidationType.PARAMETER_VALUE,
                ValidationType.HEADER_NAME,
                ValidationType.HEADER_VALUE,
                ValidationType.BODY
        );

        Set<ValidationType> generatedTypes = EnumSet.noneOf(ValidationType.class);

        // Generate enough values to likely cover all types
        for (int i = 0; i < 1000; i++) {
            ValidationType result = generator.next();
            assertNotNull(result, "Generator should never return null");
            generatedTypes.add(result);
        }

        // Verify we generated all expected types
        assertEquals(expectedTypes, generatedTypes,
                "Generator should eventually produce all supported types");
    }

    @Test
    @DisplayName("Should return correct type")
    void shouldReturnCorrectType() {
        SupportedValidationTypeGenerator generator = new SupportedValidationTypeGenerator();
        assertEquals(ValidationType.class, generator.getType(),
                "Generator should return ValidationType.class");
    }

    @Test
    @DisplayName("Should provide reasonable distribution")
    void shouldProvideReasonableDistribution() {
        SupportedValidationTypeGenerator generator = new SupportedValidationTypeGenerator();

        // Use a map to count occurrences safely
        int urlPathCount = 0;
        int parameterValueCount = 0;
        int headerNameCount = 0;
        int headerValueCount = 0;
        int bodyCount = 0;

        int total = 1000;

        for (int i = 0; i < total; i++) {
            ValidationType type = generator.next();
            switch (type) {
                case URL_PATH -> urlPathCount++;
                case PARAMETER_VALUE -> parameterValueCount++;
                case HEADER_NAME -> headerNameCount++;
                case HEADER_VALUE -> headerValueCount++;
                case BODY -> bodyCount++;
                default -> fail("Unexpected type: " + type);
            }
        }

        // Check that no single type dominates (< 60%)
        assertTrue(urlPathCount < 600, "URL_PATH appeared " + urlPathCount + " times (< 600 expected)");
        assertTrue(parameterValueCount < 600, "PARAMETER_VALUE appeared " + parameterValueCount + " times (< 600 expected)");
        assertTrue(headerNameCount < 600, "HEADER_NAME appeared " + headerNameCount + " times (< 600 expected)");
        assertTrue(headerValueCount < 600, "HEADER_VALUE appeared " + headerValueCount + " times (< 600 expected)");
        assertTrue(bodyCount < 600, "BODY appeared " + bodyCount + " times (< 600 expected)");
    }
}