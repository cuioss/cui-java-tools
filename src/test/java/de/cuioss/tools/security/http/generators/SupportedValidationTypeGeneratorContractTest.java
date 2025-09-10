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

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.security.http.core.ValidationType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Contract validation tests for SupportedValidationTypeGenerator.
 * 
 * <p>QI-4: Demonstrates proper contract validation for all generators.</p>
 * 
 * <p>This class extends GeneratorContractTestBase to validate that
 * SupportedValidationTypeGenerator meets all standard generator contracts.
 * It also includes specific validation tests for the enum generation behavior.</p>
 * 
 * <p>This serves as a reference implementation for how all generator tests
 * should be structured to ensure contract compliance.</p>
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("SupportedValidationTypeGenerator Contract Validation")
class SupportedValidationTypeGeneratorContractTest extends GeneratorContractTestBase<ValidationType> {

    @Override
    protected TypedGenerator<ValidationType> createGenerator() {
        return new SupportedValidationTypeGenerator();
    }

    @Override
    protected Class<ValidationType> getExpectedType() {
        return ValidationType.class;
    }

    /**
     * Generator-specific test: Should only generate supported validation types.
     * 
     * <p>Tests that the generator only produces the subset of ValidationType
     * enum values that are supported by the PipelineFactory, as documented
     * in the generator's purpose.</p>
     */
    @Test
    @DisplayName("Should only generate supported validation types")
    void shouldOnlyGenerateSupportedTypes() {
        TypedGenerator<ValidationType> generator = createGenerator();

        // Define the expected supported types based on generator implementation
        Set<ValidationType> expectedSupportedTypes = EnumSet.of(
                ValidationType.URL_PATH,
                ValidationType.PARAMETER_VALUE,
                ValidationType.HEADER_NAME,
                ValidationType.HEADER_VALUE,
                ValidationType.BODY
        );

        Set<ValidationType> generatedTypes = EnumSet.noneOf(ValidationType.class);

        // Generate many values to ensure we cover all possible outputs
        for (int i = 0; i < 1000; i++) {
            ValidationType result = generator.next();
            generatedTypes.add(result);
        }

        // Verify all generated types are in the expected supported set
        assertTrue(expectedSupportedTypes.containsAll(generatedTypes),
                "Generator produced unsupported types. Expected: " + expectedSupportedTypes +
                        ", but generated: " + generatedTypes);

        // Verify we generated all expected types (high probability with 1000 iterations)
        assertEquals(expectedSupportedTypes, generatedTypes,
                "Generator should eventually produce all supported types. " +
                        "Expected: " + expectedSupportedTypes + ", but only generated: " + generatedTypes);
    }

    /**
     * Generator-specific test: Should provide balanced distribution.
     * 
     * <p>Tests that the generator provides reasonably balanced distribution
     * of the supported validation types, rather than heavily favoring one type.</p>
     * 
     * <p>Note: This is a quality test. Perfect distribution is not required,
     * but extreme bias toward one type may indicate implementation issues.</p>
     */
    @Test
    @DisplayName("Should provide reasonably balanced type distribution")
    void shouldProvideBalancedDistribution() {
        TypedGenerator<ValidationType> generator = createGenerator();

        int[] typeCounts = new int[6]; // ValidationType has 5 supported values (1-5)
        
        int totalGenerations = 1000;
        for (int i = 0; i < totalGenerations; i++) {
            ValidationType result = generator.next();

            // Map enum to index for counting
            switch (result) {
                case URL_PATH -> typeCounts[1]++;
                case PARAMETER_VALUE -> typeCounts[2]++;
                case HEADER_NAME -> typeCounts[3]++;
                case HEADER_VALUE -> typeCounts[4]++;
                case BODY -> typeCounts[5]++;
                default -> fail("Unexpected validation type: " + result);
            }
        }

        // Check that no single type dominates (shouldn't be > 60% of total)
        int maxCount = 0;
        for (int i = 1; i <= 5; i++) {
            maxCount = Math.max(maxCount, typeCounts[i]);
        }

        double maxPercentage = (double) maxCount / totalGenerations;
        assertTrue(maxPercentage < 0.6,
                """
                        Type distribution appears unbalanced. \
                        Most frequent type appeared %.1f%% of the time (expected < 60%%). \
                        Counts: URL_PATH=%d, PARAMETER_VALUE=%d, HEADER_NAME=%d, HEADER_VALUE=%d, BODY=%d""".formatted(
                        maxPercentage * 100,
                        typeCounts[1], typeCounts[2], typeCounts[3], typeCounts[4], typeCounts[5]));
    }

    /**
     * Demonstration test: Show sample generator output.
     * 
     * <p>This test demonstrates the generator output and can be useful for
     * debugging and understanding generator behavior. It's not a validation
     * test but provides visibility into what the generator produces.</p>
     */
    @Test
    @DisplayName("Generator output sample demonstration")
    void demonstrateGeneratorOutput() {
        List<ValidationType> samples = getSampleOutputs(10);

        // This test always passes - it's for demonstration/debugging
        assertEquals(10, samples.size(), "Should generate requested number of samples");

        // Print samples for manual inspection during development
        /*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*/System.out.println("SupportedValidationTypeGenerator sample outputs:");
        for (int i = 0; i < samples.size(); i++) {
            /*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*//*~~(Use CuiLogger)~~>*/System.out.printf("  [%d]: %s%n", i + 1, samples.get(i));
        }
    }
}