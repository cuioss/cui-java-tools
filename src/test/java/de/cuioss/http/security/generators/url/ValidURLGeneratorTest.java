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
 * Test for {@link ValidURLGenerator}
 */
@EnableGeneratorController
class ValidURLGeneratorTest {

    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLGenerator.class, count = 100)
    @DisplayName("Generator should produce valid URLs")
    void shouldGenerateValidOutput(String generatedValue) {
        assertNotNull(generatedValue, "Generator must not produce null values");
        assertFalse(generatedValue.isEmpty(), "Generated value should not be empty");

        // Should start with / (valid URL path)
        assertTrue(generatedValue.startsWith("/"), "Valid URLs should start with /");

        // Should not exceed maximum length
        assertTrue(generatedValue.length() <= 2048,
                "Generated path should not exceed max length: " + generatedValue.length());

        // Should not contain attack patterns (valid URLs are secure)
        assertFalse(generatedValue.contains("../"), "Valid URLs should not contain path traversal");
        assertFalse(generatedValue.contains("..\\"), "Valid URLs should not contain Windows path traversal");
        assertFalse(generatedValue.contains("\u0000"), "Valid URLs should not contain null bytes");
        assertFalse(generatedValue.contains("<script"), "Valid URLs should not contain script tags");
        assertFalse(generatedValue.contains("javascript:"), "Valid URLs should not contain javascript protocol");

        // Should be well-formed if it has parameters
        if (generatedValue.contains("?")) {
            String[] parts = generatedValue.split("\\?", 2);
            assertEquals(2, parts.length, "URL with parameters should have proper format");
            String params = parts[1];
            assertTrue(params.matches("[a-zA-Z0-9=&._%+-]+"),
                    "URL parameters should contain valid characters");
        }

        // Should have valid structure characteristics
        boolean hasValidCharacteristic =
                generatedValue.contains("/api/") ||             // API paths
                        generatedValue.contains("/static/") ||          // Static resources
                        generatedValue.contains("/index.html") ||       // Index pages
                        generatedValue.contains("/docs/") ||            // Documentation
                        generatedValue.contains("/search?") ||          // Search functionality
                        generatedValue.contains("/products/") ||        // Product paths
                        generatedValue.contains("/admin/") ||           // Admin paths
                        generatedValue.contains("?page=") ||            // Pagination
                        generatedValue.contains("&sort=");              // Sorting

        assertTrue(hasValidCharacteristic,
                "Pattern should have valid URL characteristics");
    }
}