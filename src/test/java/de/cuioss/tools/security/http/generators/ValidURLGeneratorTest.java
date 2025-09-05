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

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ValidURLGenerator}
 */
class ValidURLGeneratorTest {

    private final ValidURLGenerator generator = new ValidURLGenerator();

    @Test
    void shouldReturnStringType() {
        assertEquals(String.class, generator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        for (int i = 0; i < 100; i++) {
            assertNotNull(generator.next(), "Generated value should not be null");
        }
    }

    @Test
    void shouldGenerateVariedPatterns() {
        Set<String> generatedValues = new HashSet<>();

        // Generate many values to test variety
        for (int i = 0; i < 200; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (base paths + parameter combinations)
        assertTrue(generatedValues.size() >= 10,
                "Generator should produce varied valid URL patterns, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateValidBasePaths() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test base paths
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check for expected base path patterns
        boolean hasApiPath = generated.stream().anyMatch(s -> s.contains("/api/v1/users"));
        boolean hasStaticPath = generated.stream().anyMatch(s -> s.contains("/static/css/style.css"));
        boolean hasIndexPath = generated.stream().anyMatch(s -> s.contains("/index.html"));
        boolean hasDocsPath = generated.stream().anyMatch(s -> s.contains("/docs/guide.pdf"));

        assertTrue(hasApiPath, "Should generate API path patterns");
        assertTrue(hasStaticPath, "Should generate static resource patterns");
        assertTrue(hasIndexPath, "Should generate index page patterns");
        assertTrue(hasDocsPath, "Should generate documentation patterns");
    }

    @Test
    void shouldGenerateSearchPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test search functionality
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check for search patterns
        boolean hasSearchPath = generated.stream().anyMatch(s -> s.contains("/search?q=test&limit=10"));

        assertTrue(hasSearchPath, "Should generate search query patterns");
    }

    @Test
    void shouldGenerateProductPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test product functionality
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check for product patterns
        boolean hasProductPath = generated.stream().anyMatch(s -> s.contains("/products/123/reviews"));

        assertTrue(hasProductPath, "Should generate product review patterns");
    }

    @Test
    void shouldGenerateAdminPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test admin functionality
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check for admin patterns
        boolean hasAdminPath = generated.stream().anyMatch(s -> s.contains("/admin/dashboard"));

        assertTrue(hasAdminPath, "Should generate admin dashboard patterns");
    }

    @Test
    void shouldGenerateParameterizedPaths() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test parameterized paths
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for parameterized patterns
        boolean hasPageParam = generated.stream().anyMatch(s -> s.contains("?page="));
        boolean hasSortParam = generated.stream().anyMatch(s -> s.contains("&sort="));
        boolean hasAscSort = generated.stream().anyMatch(s -> s.contains("sort=asc"));
        boolean hasDescSort = generated.stream().anyMatch(s -> s.contains("sort=desc"));

        assertTrue(hasPageParam, "Should generate paths with page parameters");
        assertTrue(hasSortParam, "Should generate paths with sort parameters");
        assertTrue(hasAscSort, "Should generate ascending sort parameters");
        assertTrue(hasDescSort, "Should generate descending sort parameters");
    }

    @Test
    void shouldGenerateNonParameterizedPaths() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test non-parameterized paths
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check that some paths don't have additional parameters beyond base path
        // Note: Some base paths like /search?q=test&limit=10 already have parameters
        boolean hasNonParameterized = generated.stream().anyMatch(s ->
                !s.contains("?page=") && !s.contains("&sort="));

        assertTrue(hasNonParameterized, "Should generate some paths without additional parameters");
    }

    @Test
    void shouldRespectLengthConstraints() {
        // Test that all generated paths respect the length limit
        for (int i = 0; i < 200; i++) {
            String generated = generator.next();
            assertTrue(generated.length() <= 2048,
                    "Generated path should not exceed max length: " + generated.length());
        }
    }

    @Test
    void shouldGenerateValidPageNumbers() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test page number range
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Extract and check page numbers from parameterized paths
        boolean hasValidPageNumbers = generated.stream()
                .filter(s -> s.contains("?page="))
                .anyMatch(s -> {
                    String pageParam = s.substring(s.indexOf("?page=") + 6);
                    if (pageParam.contains("&")) {
                        pageParam = pageParam.substring(0, pageParam.indexOf("&"));
                    }
                    try {
                        int pageNum = Integer.parseInt(pageParam);
                        return pageNum >= 1 && pageNum <= 100;
                    } catch (NumberFormatException e) {
                        return false;
                    }
                });

        assertTrue(hasValidPageNumbers, "Should generate valid page number ranges (1-100)");
    }

    @Test
    void shouldGenerateWellFormedURLs() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test URL structure
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check that all generated URLs are well-formed
        boolean allWellFormed = generated.stream().allMatch(url -> {
            // Basic URL structure validation
            if (!url.startsWith("/")) {
                return false;
            }
            // If it has parameters, should have proper format
            if (url.contains("?")) {
                String[] parts = url.split("\\?", 2);
                if (parts.length != 2) {
                    return false;
                }
                // Check parameter format (allow alphanumeric, equals, ampersand, and common URL chars)
                String params = parts[1];
                return params.matches("[a-zA-Z0-9=&._%+-]+");
            }
            return true;
        });

        assertTrue(allWellFormed, "All generated URLs should be well-formed");
    }

    @Test
    void shouldNotContainSecurityRisks() {
        // Test that valid URLs don't contain common attack patterns
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();

            // Should not contain path traversal patterns
            assertFalse(generated.contains("../"), "Valid URLs should not contain path traversal: " + generated);
            assertFalse(generated.contains("..\\"), "Valid URLs should not contain Windows path traversal: " + generated);

            // Should not contain null bytes
            assertFalse(generated.contains("\u0000"), "Valid URLs should not contain null bytes: " + generated);

            // Should not contain script injection patterns
            assertFalse(generated.contains("<script"), "Valid URLs should not contain script tags: " + generated);
            assertFalse(generated.contains("javascript:"), "Valid URLs should not contain javascript protocol: " + generated);
        }
    }

    @Test
    void shouldGenerateConsistentPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate a large set to test consistency
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have both additional parameterized and non-additional parameterized URLs
        // Note: Some base paths already have parameters, so we check for additional params
        long additionalParamCount = generated.stream()
                .filter(s -> s.contains("?page=") || s.contains("&sort=")).count();
        long nonAdditionalParamCount = generated.size() - additionalParamCount;

        assertTrue(additionalParamCount > 0, "Should generate some URLs with additional parameters");
        assertTrue(nonAdditionalParamCount > 0, "Should generate some URLs without additional parameters");

        // Test that we get reasonable variety in the generated set
        assertTrue(generated.size() >= 10, "Should generate reasonable variety of URLs");

        // Test that all URLs are within length limits
        boolean allWithinLimits = generated.stream().allMatch(s -> s.length() <= 2048);
        assertTrue(allWithinLimits, "All generated URLs should be within length limits");
    }
}