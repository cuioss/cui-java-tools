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

import de.cuioss.tools.security.http.data.URLParameter;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link URLParameterGenerator}
 */
class URLParameterGeneratorTest {

    private final URLParameterGenerator generator = new URLParameterGenerator();

    @Test
    void shouldReturnURLParameterType() {
        assertEquals(URLParameter.class, generator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        for (int i = 0; i < 100; i++) {
            URLParameter param = generator.next();
            assertNotNull(param, "Generated URLParameter should not be null");
            assertNotNull(param.name(), "Parameter name should not be null");
            assertNotNull(param.value(), "Parameter value should not be null");
        }
    }

    @Test
    void shouldGenerateVariedParameters() {
        Set<URLParameter> generatedParams = new HashSet<>();

        // Generate many parameters to test variety
        for (int i = 0; i < 300; i++) {
            generatedParams.add(generator.next());
        }

        // We should have good variety
        assertTrue(generatedParams.size() >= 50,
                "Generator should produce varied URL parameters, got: " + generatedParams.size());
    }

    @Test
    void shouldGenerateSafeParameters() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test safe combinations
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for safe parameter names and values
        boolean hasPageParam = generated.stream().anyMatch(p -> "page".equals(p.name()));
        boolean hasSortParam = generated.stream().anyMatch(p -> "sort".equals(p.name()));
        boolean hasSearchParam = generated.stream().anyMatch(p -> "search".equals(p.name()));
        boolean hasTrueValue = generated.stream().anyMatch(p -> "true".equals(p.value()));
        boolean hasJsonValue = generated.stream().anyMatch(p -> "json".equals(p.value()));

        assertTrue(hasPageParam, "Should generate page parameters");
        assertTrue(hasSortParam, "Should generate sort parameters");
        assertTrue(hasSearchParam, "Should generate search parameters");
        assertTrue(hasTrueValue, "Should generate true values");
        assertTrue(hasJsonValue, "Should generate json values");
    }

    @Test
    void shouldGenerateAttackValues() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test attack values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for attack pattern values
        boolean hasPathTraversal = generated.stream().anyMatch(p -> p.value().contains("../etc/passwd"));
        boolean hasXssAttack = generated.stream().anyMatch(p -> p.value().contains("<script>"));
        boolean hasSqlInjection = generated.stream().anyMatch(p -> p.value().contains("DROP TABLE"));
        boolean hasNullByte = generated.stream().anyMatch(p -> p.value().contains("\u0000"));
        boolean hasJndiAttack = generated.stream().anyMatch(p -> p.value().contains("${jndi:"));

        assertTrue(hasPathTraversal, "Should generate path traversal attack values");
        assertTrue(hasXssAttack, "Should generate XSS attack values");
        assertTrue(hasSqlInjection, "Should generate SQL injection attack values");
        assertTrue(hasNullByte, "Should generate null byte attack values");
        assertTrue(hasJndiAttack, "Should generate JNDI attack values");
    }

    @Test
    void shouldGenerateSpecialParameterNames() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test special names
        for (int i = 0; i < 300; i++) {
            generated.add(generator.next());
        }

        // Check for special parameter name patterns
        boolean hasEmptyName = generated.stream().anyMatch(p -> p.name().isEmpty());
        boolean hasWhitespaceName = generated.stream().anyMatch(p -> p.name().trim().isEmpty() && !p.name().isEmpty());
        boolean hasSpacesInName = generated.stream().anyMatch(p -> p.name().contains("param with spaces"));
        boolean hasEncodedName = generated.stream().anyMatch(p -> p.name().contains("%20"));
        boolean hasBracketsInName = generated.stream().anyMatch(p -> p.name().contains("[bracket]"));

        assertTrue(hasEmptyName, "Should generate empty parameter names");
        assertTrue(hasWhitespaceName, "Should generate whitespace parameter names");
        assertTrue(hasSpacesInName, "Should generate parameter names with spaces");
        assertTrue(hasEncodedName, "Should generate encoded parameter names");
        assertTrue(hasBracketsInName, "Should generate parameter names with brackets");
    }

    @Test
    void shouldGenerateSpecialCharactersInNames() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test special characters in names
        for (int i = 0; i < 300; i++) {
            generated.add(generator.next());
        }

        // Check for special characters in parameter names
        boolean hasBracesInName = generated.stream().anyMatch(p -> p.name().contains("{brace}"));
        boolean hasPipeInName = generated.stream().anyMatch(p -> p.name().contains("|pipe"));
        boolean hasEqualsInName = generated.stream().anyMatch(p -> p.name().contains("=equals"));
        boolean hasAmpersandInName = generated.stream().anyMatch(p -> p.name().contains("&ampersand"));
        boolean hasHashInName = generated.stream().anyMatch(p -> p.name().contains("#hash"));

        assertTrue(hasBracesInName, "Should generate parameter names with braces");
        assertTrue(hasPipeInName, "Should generate parameter names with pipes");
        assertTrue(hasEqualsInName, "Should generate parameter names with equals");
        assertTrue(hasAmpersandInName, "Should generate parameter names with ampersands");
        assertTrue(hasHashInName, "Should generate parameter names with hash symbols");
    }

    @Test
    void shouldGenerateUrlProblemCharacters() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test URL problem characters
        for (int i = 0; i < 300; i++) {
            generated.add(generator.next());
        }

        // Check for URL problematic characters
        boolean hasQuestionInName = generated.stream().anyMatch(p -> p.name().contains("?question"));
        boolean hasSlashInName = generated.stream().anyMatch(p -> p.name().contains("/slash"));
        boolean hasBackslashInName = generated.stream().anyMatch(p -> p.name().contains("\\backslash"));

        assertTrue(hasQuestionInName, "Should generate parameter names with question marks");
        assertTrue(hasSlashInName, "Should generate parameter names with slashes");
        assertTrue(hasBackslashInName, "Should generate parameter names with backslashes");
    }

    @Test
    void shouldGenerateLongParameterNames() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test long names
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for very long parameter names
        boolean hasLongName = generated.stream().anyMatch(p -> p.name().length() > 100);

        assertTrue(hasLongName, "Should generate very long parameter names");
    }

    @Test
    void shouldGenerateLongValues() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test long values
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for very long parameter values
        boolean hasLongValue = generated.stream().anyMatch(p -> p.value().length() > 500);

        assertTrue(hasLongValue, "Should generate very long parameter values");
    }

    @Test
    void shouldGenerateSecurityTestPatterns() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate parameters to test security patterns
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for security test patterns
        boolean hasJavaScriptProtocol = generated.stream().anyMatch(p -> p.value().contains("javascript:"));
        boolean hasFileProtocol = generated.stream().anyMatch(p -> p.value().contains("file:///"));

        assertTrue(hasJavaScriptProtocol, "Should generate JavaScript protocol attack values");
        assertTrue(hasFileProtocol, "Should generate file protocol attack values");
    }

    @Test
    void shouldGenerateDifferentParameterTypes() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate a large set to test different types
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have both normal and special parameter combinations
        boolean hasNormalNames = generated.stream().anyMatch(p ->
                "page".equals(p.name()) || "search".equals(p.name()) || "sort".equals(p.name()));
        boolean hasSafeValues = generated.stream().anyMatch(p ->
                "1".equals(p.value()) || "true".equals(p.value()) || "asc".equals(p.value()));
        boolean hasAttackValues = generated.stream().anyMatch(p ->
                p.value().contains("<script>") || p.value().contains("../") || p.value().contains("DROP"));
        boolean hasSpecialNames = generated.stream().anyMatch(p ->
                p.name().contains("spaces") || p.name().contains("[") || p.name().contains("{"));

        assertTrue(hasNormalNames, "Should generate normal parameter names");
        assertTrue(hasSafeValues, "Should generate safe parameter values");
        assertTrue(hasAttackValues, "Should generate attack parameter values");
        assertTrue(hasSpecialNames, "Should generate special parameter names");
    }

    @Test
    void shouldGenerateValidRecordStructure() {
        // Test that all generated parameters have valid record structure
        for (int i = 0; i < 100; i++) {
            URLParameter param = generator.next();

            // Test record methods work correctly
            assertNotNull(param.name(), "Parameter name should not be null");
            assertNotNull(param.value(), "Parameter value should not be null");

            // Test toString method works (records auto-generate this)
            String toString = param.toString();
            assertTrue(toString.contains("URLParameter"), "toString should contain record name");
            assertTrue(toString.contains(param.name()), "toString should contain parameter name");
            assertTrue(toString.contains(param.value()), "toString should contain parameter value");

            // Test equals and hashCode work (records auto-generate these)
            URLParameter duplicate = new URLParameter(param.name(), param.value());
            assertEquals(param, duplicate, "Equal parameters should be equal");
            assertEquals(param.hashCode(), duplicate.hashCode(), "Equal parameters should have same hash code");
        }
    }

    @Test
    void shouldGenerateReasonableVariety() {
        Set<URLParameter> generated = new HashSet<>();

        // Generate a large set to test overall variety
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have parameters from different categories
        boolean hasStandardNames = generated.stream().anyMatch(p -> p.name().matches("page|size|sort|filter"));
        boolean hasSpecialNames = generated.stream().anyMatch(p -> p.name().matches(".*[\\[\\]{}|=&#?/\\\\].*"));
        boolean hasSafeValues = generated.stream().anyMatch(p -> p.value().matches("\\d+|true|false|asc|desc|json|xml"));
        boolean hasAttackValues = generated.stream().anyMatch(p -> p.value().contains("<") || p.value().contains(".."));

        assertTrue(hasStandardNames, "Should generate standard parameter names");
        assertTrue(hasSpecialNames, "Should generate special character parameter names");
        assertTrue(hasSafeValues, "Should generate safe parameter values");
        assertTrue(hasAttackValues, "Should generate attack parameter values");

        // Should generate reasonable variety
        assertTrue(generated.size() >= 100, "Should generate reasonable variety of URL parameters");
    }
}