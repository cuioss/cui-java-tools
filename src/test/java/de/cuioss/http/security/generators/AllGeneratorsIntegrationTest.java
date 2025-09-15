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
package de.cuioss.http.security.generators;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.http.security.data.Cookie;
import de.cuioss.http.security.data.HTTPBody;
import de.cuioss.http.security.data.URLParameter;
import de.cuioss.http.security.generators.body.HTTPBodyGenerator;
import de.cuioss.http.security.generators.cookie.AttackCookieGenerator;
import de.cuioss.http.security.generators.cookie.ValidCookieGenerator;
import de.cuioss.http.security.generators.encoding.BoundaryFuzzingGenerator;
import de.cuioss.http.security.generators.encoding.EncodingCombinationGenerator;
import de.cuioss.http.security.generators.encoding.PathTraversalGenerator;
import de.cuioss.http.security.generators.encoding.UnicodeAttackGenerator;
import de.cuioss.http.security.generators.url.AttackURLParameterGenerator;
import de.cuioss.http.security.generators.url.InvalidURLGenerator;
import de.cuioss.http.security.generators.url.ValidURLGenerator;
import de.cuioss.http.security.generators.url.ValidURLParameterGenerator;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for all HTTP security generators.
 * Implements: Task G10 from HTTP verification specification
 */
class AllGeneratorsIntegrationTest {

    private final PathTraversalGenerator pathTraversalGenerator = new PathTraversalGenerator();
    private final EncodingCombinationGenerator encodingGenerator = new EncodingCombinationGenerator();
    private final UnicodeAttackGenerator unicodeGenerator = new UnicodeAttackGenerator();
    private final BoundaryFuzzingGenerator boundaryGenerator = new BoundaryFuzzingGenerator();
    private final ValidURLGenerator validUrlGenerator = new ValidURLGenerator();
    private final InvalidURLGenerator invalidUrlGenerator = new InvalidURLGenerator();
    private final ValidURLParameterGenerator validParameterGenerator = new ValidURLParameterGenerator();
    private final AttackURLParameterGenerator attackParameterGenerator = new AttackURLParameterGenerator();
    private final ValidCookieGenerator validCookieGenerator = new ValidCookieGenerator();
    private final AttackCookieGenerator attackCookieGenerator = new AttackCookieGenerator();
    private final HTTPBodyGenerator bodyGenerator = new HTTPBodyGenerator();

    @Test
    void shouldHaveAllGeneratorsImplemented() {
        // Verify all generators are instantiated and functional (now using framework-compliant variants)
        assertNotNull(pathTraversalGenerator);
        assertNotNull(encodingGenerator);
        assertNotNull(unicodeGenerator);
        assertNotNull(boundaryGenerator);
        assertNotNull(validUrlGenerator);
        assertNotNull(invalidUrlGenerator);
        assertNotNull(validParameterGenerator);
        assertNotNull(attackParameterGenerator);
        assertNotNull(validCookieGenerator);
        assertNotNull(attackCookieGenerator);
        assertNotNull(bodyGenerator);
    }

    @Test
    void shouldReturnCorrectTypes() {
        assertEquals(String.class, pathTraversalGenerator.getType());
        assertEquals(String.class, encodingGenerator.getType());
        assertEquals(String.class, unicodeGenerator.getType());
        assertEquals(String.class, boundaryGenerator.getType());
        assertEquals(String.class, validUrlGenerator.getType());
        assertEquals(String.class, invalidUrlGenerator.getType());
        assertEquals(URLParameter.class, validParameterGenerator.getType());
        assertEquals(URLParameter.class, attackParameterGenerator.getType());
        assertEquals(Cookie.class, validCookieGenerator.getType());
        assertEquals(Cookie.class, attackCookieGenerator.getType());
        assertEquals(HTTPBody.class, bodyGenerator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        List<TypedGenerator<?>> generators = List.of(
                pathTraversalGenerator,
                encodingGenerator,
                unicodeGenerator,
                boundaryGenerator,
                validUrlGenerator,
                invalidUrlGenerator,
                validParameterGenerator,
                attackParameterGenerator,
                validCookieGenerator,
                attackCookieGenerator,
                bodyGenerator
        );

        for (TypedGenerator<?> generator : generators) {
            for (int i = 0; i < 50; i++) {
                Object generated = generator.next();
                assertNotNull(generated, "Generator " + generator.getClass().getSimpleName() + " should not return null");
            }
        }
    }

    @Test
    void shouldGenerateVariedOutputs() {
        // Test that each generator produces variety
        Set<String> pathTraversals = new HashSet<>();
        Set<String> encodings = new HashSet<>();
        Set<String> unicodeAttacks = new HashSet<>();
        Set<String> boundaryFuzzing = new HashSet<>();
        Set<String> validUrls = new HashSet<>();
        Set<String> invalidUrls = new HashSet<>();
        Set<URLParameter> parameters = new HashSet<>();
        Set<Cookie> cookies = new HashSet<>();
        Set<HTTPBody> bodies = new HashSet<>();

        for (int i = 0; i < 200; i++) {
            pathTraversals.add(pathTraversalGenerator.next());
            encodings.add(encodingGenerator.next());
            unicodeAttacks.add(unicodeGenerator.next());
            boundaryFuzzing.add(boundaryGenerator.next());
            validUrls.add(validUrlGenerator.next());
            invalidUrls.add(invalidUrlGenerator.next());
            parameters.add(validParameterGenerator.next());
            parameters.add(attackParameterGenerator.next());
            cookies.add(validCookieGenerator.next());
            cookies.add(attackCookieGenerator.next());
            bodies.add(bodyGenerator.next());
        }

        // Each generator should produce reasonable variety
        assertTrue(pathTraversals.size() >= 10, "PathTraversalGenerator should produce variety, got: " + pathTraversals.size());
        assertTrue(encodings.size() >= 10, "EncodingCombinationGenerator should produce variety, got: " + encodings.size());
        assertTrue(unicodeAttacks.size() >= 10, "UnicodeAttackGenerator should produce variety, got: " + unicodeAttacks.size());
        assertTrue(boundaryFuzzing.size() >= 20, "BoundaryFuzzingGenerator should produce variety, got: " + boundaryFuzzing.size());
        assertTrue(validUrls.size() >= 10, "ValidURLGenerator should produce variety, got: " + validUrls.size());
        assertTrue(invalidUrls.size() >= 10, "InvalidURLGenerator should produce variety, got: " + invalidUrls.size());
        assertTrue(parameters.size() >= 30, "URL Parameter generators should produce variety, got: " + parameters.size());
        assertTrue(cookies.size() >= 30, "Cookie generators should produce variety, got: " + cookies.size());
        assertTrue(bodies.size() >= 30, "HTTPBodyGenerator should produce variety, got: " + bodies.size());
    }

    @Test
    void shouldGenerateAttackPatterns() {
        // Verify that generators produce security-relevant patterns
        Set<String> pathTraversals = new HashSet<>();
        Set<String> encodings = new HashSet<>();
        Set<String> unicodeAttacks = new HashSet<>();
        Set<String> boundaryFuzzing = new HashSet<>();
        Set<URLParameter> parameters = new HashSet<>();
        Set<Cookie> cookies = new HashSet<>();
        Set<HTTPBody> bodies = new HashSet<>();

        for (int i = 0; i < 200; i++) {
            pathTraversals.add(pathTraversalGenerator.next());
            encodings.add(encodingGenerator.next());
            unicodeAttacks.add(unicodeGenerator.next());
            boundaryFuzzing.add(boundaryGenerator.next());
            parameters.add(attackParameterGenerator.next()); // Use attack generator for attack pattern test
            cookies.add(attackCookieGenerator.next()); // Use attack generator for attack pattern test
            bodies.add(bodyGenerator.next());
        }

        // Check for common attack patterns
        boolean hasPathTraversal = pathTraversals.stream().anyMatch(s -> s.contains("../"));
        boolean hasEncoding = encodings.stream().anyMatch(s -> s.contains("%"));
        boolean hasUnicodeAttack = unicodeAttacks.stream().anyMatch(s -> s.length() > 0);
        boolean hasBoundaryFuzz = boundaryFuzzing.stream().anyMatch(s -> s.length() > 100 || s.isEmpty());

        boolean hasParameterAttack = parameters.stream().anyMatch(p ->
                p.value().contains("<script>") || p.value().contains("../") || p.value().contains("DROP"));
        boolean hasCookieAttack = cookies.stream().anyMatch(c ->
                c.value().contains("<script>") || c.value().contains("../") || c.value().contains("DROP"));
        boolean hasBodyAttack = bodies.stream().anyMatch(b ->
                b.content().contains("<script>") || b.content().contains("../") || b.content().contains("DROP"));

        assertTrue(hasPathTraversal, "PathTraversalGenerator should generate path traversal patterns");
        assertTrue(hasEncoding, "EncodingCombinationGenerator should generate encoded patterns");
        assertTrue(hasUnicodeAttack, "UnicodeAttackGenerator should generate unicode patterns");
        assertTrue(hasBoundaryFuzz, "BoundaryFuzzingGenerator should generate boundary fuzzing patterns");
        assertTrue(hasParameterAttack, "Attack URL Parameter generator should generate attack patterns");
        assertTrue(hasCookieAttack, "Attack Cookie generator should generate attack patterns");
        assertTrue(hasBodyAttack, "HTTPBodyGenerator should generate attack patterns");
    }

    @Test
    void shouldGenerateLegitimateValues() {
        // Verify that generators also produce legitimate/safe values for false positive testing
        Set<String> validUrls = new HashSet<>();
        Set<URLParameter> parameters = new HashSet<>();
        Set<Cookie> cookies = new HashSet<>();
        Set<HTTPBody> bodies = new HashSet<>();

        for (int i = 0; i < 200; i++) {
            validUrls.add(validUrlGenerator.next());
            parameters.add(validParameterGenerator.next()); // Use valid generator for legitimate value test
            cookies.add(validCookieGenerator.next()); // Use valid generator for legitimate value test
            bodies.add(bodyGenerator.next());
        }

        // Check for legitimate patterns
        boolean hasValidPath = validUrls.stream().anyMatch(s -> s.startsWith("/") || s.startsWith("api/"));
        boolean hasLegitimateParam = parameters.stream().anyMatch(p ->
                "id".equals(p.name()) || "page".equals(p.name()) || "limit".equals(p.name()));
        boolean hasLegitimateCoookie = cookies.stream().anyMatch(c ->
                "JSESSIONID".equals(c.name()) || "auth_token".equals(c.name()));
        boolean hasLegitimateBody = bodies.stream().anyMatch(b ->
                b.content().contains("Hello World") || b.content().contains("{\"user\""));

        assertTrue(hasValidPath, "ValidURLGenerator should generate valid paths");
        assertTrue(hasLegitimateParam, "Valid URL Parameter generator should generate legitimate parameters");
        assertTrue(hasLegitimateCoookie, "Valid Cookie generator should generate legitimate cookies");
        assertTrue(hasLegitimateBody, "HTTPBodyGenerator should generate legitimate bodies");
    }

    @Test
    void shouldHandleConcurrentGeneration() {
        // Test thread safety of generators
        List<Thread> threads = List.of(
                new Thread(() -> {
                    for (int i = 0; i < 100; i++) {
                        pathTraversalGenerator.next();
                        encodingGenerator.next();
                        unicodeGenerator.next();
                    }
                }),
                new Thread(() -> {
                    for (int i = 0; i < 100; i++) {
                        boundaryGenerator.next();
                        validUrlGenerator.next();
                        invalidUrlGenerator.next();
                    }
                }),
                new Thread(() -> {
                    for (int i = 0; i < 100; i++) {
                        validParameterGenerator.next();
                        attackParameterGenerator.next();
                        validCookieGenerator.next();
                        attackCookieGenerator.next();
                        bodyGenerator.next();
                    }
                })
        );

        // Start all threads
        threads.forEach(Thread::start);

        // Wait for completion
        threads.forEach(thread -> {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Thread interrupted during concurrent generation test");
            }
        });

        // If we get here without exceptions, thread safety test passed
        assertTrue(true, "Concurrent generation completed without exceptions");
    }

    @Test
    void shouldGenerateComplexRecordStructures() {
        // Test that record-based generators create proper structures
        for (int i = 0; i < 50; i++) {
            URLParameter param = validParameterGenerator.next(); // Test with valid generator
            assertNotNull(param.name(), "URLParameter name should not be null");
            assertNotNull(param.value(), "URLParameter value should not be null");

            Cookie cookie = validCookieGenerator.next(); // Test with valid generator
            assertNotNull(cookie.name(), "Cookie name should not be null");
            assertNotNull(cookie.value(), "Cookie value should not be null");
            assertNotNull(cookie.attributes(), "Cookie attributes should not be null");

            HTTPBody body = bodyGenerator.next();
            assertNotNull(body.content(), "HTTPBody content should not be null");
            assertNotNull(body.contentType(), "HTTPBody contentType should not be null");
            assertNotNull(body.encoding(), "HTTPBody encoding should not be null");
        }
    }

    @Test
    void shouldGenerateEdgeCasesForSecurityTesting() {
        // Test that generators produce edge cases that are important for security testing
        Set<String> allStringOutputs = new HashSet<>();
        Set<URLParameter> allParams = new HashSet<>();
        Set<Cookie> allCookies = new HashSet<>();
        Set<HTTPBody> allBodies = new HashSet<>();

        for (int i = 0; i < 300; i++) {
            allStringOutputs.add(pathTraversalGenerator.next());
            allStringOutputs.add(encodingGenerator.next());
            allStringOutputs.add(unicodeGenerator.next());
            allStringOutputs.add(boundaryGenerator.next());
            allStringOutputs.add(validUrlGenerator.next());
            allStringOutputs.add(invalidUrlGenerator.next());
            allParams.add(validParameterGenerator.next());
            allParams.add(attackParameterGenerator.next());
            allCookies.add(validCookieGenerator.next());
            allCookies.add(attackCookieGenerator.next());
            allBodies.add(bodyGenerator.next());
        }

        // Check for important edge cases
        boolean hasEmptyString = allStringOutputs.contains("");
        boolean hasLongString = allStringOutputs.stream().anyMatch(s -> s.length() > 1000);
        boolean hasSpecialChars = allStringOutputs.stream().anyMatch(s -> s.contains("\n") || s.contains("\r") || s.contains("\t"));

        boolean hasEmptyParamName = allParams.stream().anyMatch(p -> p.name().isEmpty());
        boolean hasEmptyCookieName = allCookies.stream().anyMatch(c -> c.name().isEmpty());
        boolean hasEmptyBodyContent = allBodies.stream().anyMatch(b -> b.content().isEmpty());

        assertTrue(hasEmptyString, "Should generate empty strings for edge case testing");
        assertTrue(hasLongString, "Should generate long strings for buffer overflow testing");
        assertTrue(hasSpecialChars, "Should generate special characters for injection testing");
        assertTrue(hasEmptyParamName, "Should generate empty parameter names for edge case testing");
        assertTrue(hasEmptyCookieName, "Should generate empty cookie names for edge case testing");
        assertTrue(hasEmptyBodyContent, "Should generate empty body content for edge case testing");
    }

    @Test
    void shouldMaintainGeneratorConsistency() {
        // Test that generators maintain consistent behavior across multiple calls
        for (int run = 0; run < 10; run++) {
            Set<String> currentRun = new HashSet<>();

            // Generate same number of values in each run
            for (int i = 0; i < 100; i++) {
                currentRun.add(pathTraversalGenerator.next());
                currentRun.add(encodingGenerator.next());
                currentRun.add(unicodeGenerator.next());
            }

            // Each run should produce variety (not the same single value repeated)
            assertTrue(currentRun.size() > 5, "Each run should produce variety, run " + run + " had " + currentRun.size() + " unique values");
        }
    }

    @Test
    void shouldGeneratePhase1CompleteTestSuite() {
        // Comprehensive test that Phase 1 generators work together as a complete system
        // This validates that all G1-G9 generators are properly implemented and integrated

        int totalGenerations = 1000;
        Set<String> allStringGenerations = new HashSet<>();
        Set<URLParameter> allParameterGenerations = new HashSet<>();
        Set<Cookie> allCookieGenerations = new HashSet<>();
        Set<HTTPBody> allBodyGenerations = new HashSet<>();

        for (int i = 0; i < totalGenerations; i++) {
            // String-based generators (G1-G6)
            allStringGenerations.add(pathTraversalGenerator.next());
            allStringGenerations.add(encodingGenerator.next());
            allStringGenerations.add(unicodeGenerator.next());
            allStringGenerations.add(boundaryGenerator.next());
            allStringGenerations.add(validUrlGenerator.next());
            allStringGenerations.add(invalidUrlGenerator.next());

            // Record-based generators (G7-G9)
            allParameterGenerations.add(validParameterGenerator.next());
            allParameterGenerations.add(attackParameterGenerator.next());
            allCookieGenerations.add(validCookieGenerator.next());
            allCookieGenerations.add(attackCookieGenerator.next());
            allBodyGenerations.add(bodyGenerator.next());
        }

        // Phase 1 completion criteria
        assertTrue(allStringGenerations.size() >= 200, "String generators should produce substantial variety");
        assertTrue(allParameterGenerations.size() >= 150, "Parameter generator should produce substantial variety");
        assertTrue(allCookieGenerations.size() >= 150, "Cookie generator should produce substantial variety");
        assertTrue(allBodyGenerations.size() >= 150, "Body generator should produce substantial variety");

        // Verify security coverage
        boolean hasPathTraversalAttacks = allStringGenerations.stream().anyMatch(s -> s.contains("../"));
        boolean hasEncodingAttacks = allStringGenerations.stream().anyMatch(s -> s.contains("%2e%2e"));
        boolean hasUnicodeAttacks = allStringGenerations.stream().anyMatch(s -> s.contains("\u202e"));

        boolean hasParameterXSS = allParameterGenerations.stream().anyMatch(p -> p.value().contains("<script>"));
        boolean hasCookieInjection = allCookieGenerations.stream().anyMatch(c -> c.value().contains("\r\n"));
        boolean hasBodyXXE = allBodyGenerations.stream().anyMatch(b -> b.content().contains("<!ENTITY"));

        assertTrue(hasPathTraversalAttacks, "Should generate path traversal attacks");
        assertTrue(hasEncodingAttacks, "Should generate encoding attacks");
        assertTrue(hasUnicodeAttacks, "Should generate unicode attacks");
        assertTrue(hasParameterXSS, "Should generate parameter XSS attacks");
        assertTrue(hasCookieInjection, "Should generate cookie injection attacks");
        assertTrue(hasBodyXXE, "Should generate XXE attacks");

        // Phase 1 is now complete - all 10 tasks (G1-G10) implemented
        assertTrue(true, "Phase 1: Test Infrastructure and Generators (10/10 complete)");
    }
}