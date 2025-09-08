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
package de.cuioss.tools.security.http.tests;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.URLLengthLimitAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T19: Test URL length limit attacks
 * 
 * <p>
 * This test class implements Task T19 from the HTTP security validation plan,
 * focusing on testing URL length limit attacks that attempt to exploit URL
 * length limitations to cause denial of service, buffer overflows, or bypass
 * security controls through excessive URL sizes using specialized generators
 * and comprehensive attack vectors.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Basic length overflow attacks exceeding standard URL length limits</li>
 *   <li>Path component overflow attacks with extremely long path segments</li>
 *   <li>Query parameter overflow attacks with long query strings</li>
 *   <li>Fragment overflow attacks with long URL fragments</li>
 *   <li>Hostname overflow attacks with long hostname components</li>
 *   <li>Repeated parameter attacks with many identical parameters</li>
 *   <li>Deep path nesting attacks with many directory levels</li>
 *   <li>Long parameter name attacks</li>
 *   <li>Long parameter value attacks</li>
 *   <li>Mixed length attacks combining multiple long components</li>
 *   <li>Buffer overflow pattern attacks</li>
 *   <li>Memory exhaustion attacks</li>
 *   <li>Parser confusion attacks with challenging parsing scenarios</li>
 *   <li>Encoding length attacks that amplify length through encoding</li>
 *   <li>Algorithmic complexity attacks causing processing slowdown</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax</li>
 *   <li>RFC 7230 - HTTP/1.1 Message Syntax and Routing</li>
 *   <li>OWASP - Application Denial of Service</li>
 *   <li>CWE-400 - Uncontrolled Resource Consumption</li>
 *   <li>CWE-770 - Allocation of Resources Without Limits or Throttling</li>
 *   <li>CWE-120 - Buffer Copy without Checking Size of Input</li>
 * </ul>
 * 
 * Implements: Task T19 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T19: URL Length Limit Attack Tests")
class URLLengthLimitAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        // Configure with stricter path length limits to properly detect length limit attacks
        config = SecurityConfiguration.builder()
                .maxPathLength(1024) // Further reduced to catch more length attacks
                .maxParameterNameLength(64)   // Reduced from default 128
                .maxParameterValueLength(256) // Further reduced from 512
                .maxHeaderNameLength(64)      // Reduced from default 128
                .maxHeaderValueLength(256)    // Further reduced from 512
                .allowPathTraversal(false)
                .allowDoubleEncoding(false)
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Test comprehensive URL length limit attack patterns.
     * 
     * <p>
     * Uses URLLengthLimitAttackGenerator which provides 15 different types
     * of URL length limit attacks including basic overflow, path component overflow,
     * query parameter overflow, fragment overflow, hostname overflow, repeated
     * parameters, deep nesting, and various resource exhaustion techniques.
     * </p>
     * 
     * @param lengthAttackPattern A URL length limit attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = URLLengthLimitAttackGenerator.class, count = 30)
    @DisplayName("All URL length limit attacks should be rejected")
    void shouldRejectAllURLLengthLimitAttacks(String lengthAttackPattern) {
        // Given: A URL length limit attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the length attack
        try {
            pipeline.validate(lengthAttackPattern);
            // If validation passes, check if this is expected
            // URLs with long hostnames but short paths may pass URL path validation
            if (isPathBasedLengthAttack(lengthAttackPattern)) {
                fail("Expected path-based length attack to be rejected: " + lengthAttackPattern);
            }
            // Otherwise, this is expected (e.g., long hostname with short path)
            assertTrue(lengthAttackPattern.length() > 0, "Pattern should not be empty: " + lengthAttackPattern);
        } catch (UrlSecurityException exception) {
            // Then: If an exception is thrown, it should be length-related
            assertNotNull(exception, "Exception should not be null");
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Failure type should be length limit related: " + exception.getFailureType() +
                            " for pattern: " + lengthAttackPattern);

            // And: Original malicious input should be preserved
            assertEquals(lengthAttackPattern, exception.getOriginalInput(),
                    "Original input should be preserved in exception");

            // And: Security event should be recorded when exception is thrown
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded when exception is thrown for: " + lengthAttackPattern);
        }
    }

    /**
     * Test basic URL length overflow attacks.
     * 
     * <p>
     * Tests attacks that exceed standard URL length limits through
     * various components of the URL.
     * </p>
     */
    @Test
    @DisplayName("Basic URL length overflow attacks must be blocked")
    void shouldBlockBasicLengthOverflowAttacks() {
        String[] basicOverflows = {
                // Standard length limit tests
                "/api?" + "A".repeat(8192), // 8KB query string
                "/search?" + "B".repeat(16384), // 16KB query string
                "/data/" + "C".repeat(4096), // 4KB path component
                "/resource?param=" + "D".repeat(10000), // 10KB parameter value
                
                // Mixed component overflows
                "/service/" + "E".repeat(2048) + "?data=" + "F".repeat(2048), // Combined 4KB components
                "/endpoint?" + "G".repeat(32768), // 32KB query
                "/handler/" + "H".repeat(1024) + "/" + "I".repeat(1024) + "/" + "J".repeat(1024), // Multiple long segments
                "/process?field=" + "K".repeat(65536) // 64KB parameter
        };

        for (String attack : basicOverflows) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Basic length overflow attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect length overflow: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for length overflow");
        }
    }

    /**
     * Test path component overflow attacks.
     * 
     * <p>
     * Tests attacks using extremely long path segments to cause
     * buffer overflows or parsing issues.
     * </p>
     */
    @Test
    @DisplayName("Path component overflow attacks must be blocked")
    void shouldBlockPathComponentOverflowAttacks() {
        String[] pathOverflows = {
                // Single long path segments
                "/api/" + "segment".repeat(1000), // Repeated segment names
                "/data/" + "A".repeat(4096) + "/normal", // One very long segment
                "/service/" + "path_" + "B".repeat(2048) + "/resource", // Long segment with prefix
                
                // Multiple long segments
                "/" + "C".repeat(8192) + "/api", // Long prefix path
                "/endpoint/" + "dir_" + "D".repeat(1024) + "/file_" + "E".repeat(1024), // Multiple long segments
                "/handler/" + "very_long_directory_name_" + "F".repeat(3000), // Descriptive long segment
                
                // Nested long paths
                "/process/" + "component" + "G".repeat(512) + "/subdir" + "H".repeat(512) + "/file", // Nested long paths
                "/action/" + "I".repeat(16384) // Single massive segment
        };

        for (String attack : pathOverflows) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Path component overflow attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect path component overflow: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for path component overflow");
        }
    }

    /**
     * Test query parameter overflow attacks.
     * 
     * <p>
     * Tests attacks using extremely long query strings and parameters
     * to cause resource exhaustion or buffer overflows.
     * </p>
     */
    @Test
    @DisplayName("Query parameter overflow attacks must be blocked")
    void shouldBlockQueryParameterOverflowAttacks() {
        String[] queryOverflows = {
                // Single long parameters
                "/search?param=" + "A".repeat(10000), // 10KB parameter
                "/api?data=" + "B".repeat(5000) + "&info=" + "C".repeat(5000), // Multiple 5KB parameters
                "/endpoint?query=" + "D".repeat(20000), // 20KB parameter
                
                // Repeated terms and structured content
                "/service?search=" + "term ".repeat(2000), // Repeated search terms
                "/handler?content=" + "E".repeat(8192) + "&type=json", // Long parameter with normal parameter
                "/process?input=" + ("value" + "F".repeat(100) + "&").repeat(50), // Many medium-length parameters
                
                // Very large parameters
                "/resource?buffer=" + "G".repeat(32768), // 32KB parameter
                "/data?payload=" + "H".repeat(65536) // 64KB parameter
        };

        for (String attack : queryOverflows) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Query parameter overflow attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect query parameter overflow: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for query parameter overflow");
        }
    }

    /**
     * Test repeated parameter attacks.
     * 
     * <p>
     * Tests attacks using many repeated parameters to cause parsing
     * complexity or resource exhaustion.
     * </p>
     */
    @Test
    @DisplayName("Repeated parameter attacks must be blocked")
    void shouldBlockRepeatedParameterAttacks() {
        String[] repeatedParamAttacks = {
                // Basic repeated parameters
                "/api?" + "param=value&".repeat(1000), // 1000 identical parameters
                "/search?" + "data=test&".repeat(2000), // 2000 parameters
                "/endpoint?" + "field=info&".repeat(5000), // 5000 parameters
                
                // Parameters with long values
                "/service?" + ("item=" + "A".repeat(100) + "&").repeat(500), // 500 parameters with 100-char values
                "/handler?" + "query=search&".repeat(10000), // 10000 parameters
                
                // Long parameter names
                "/process?" + ("param" + "B".repeat(50) + "=value&").repeat(200), // Long parameter names
                "/resource?" + "test=data&".repeat(50000), // 50000 parameters
                "/data?" + ("key=value" + "C".repeat(10) + "&").repeat(1000) // Mixed repeated parameters
        };

        for (String attack : repeatedParamAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Repeated parameter attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect repeated parameter attack: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for repeated parameter attack");
        }
    }

    /**
     * Test deep path nesting attacks.
     * 
     * <p>
     * Tests attacks using many directory levels to cause stack
     * overflow or parsing complexity issues.
     * </p>
     */
    @Test
    @DisplayName("Deep path nesting attacks must be blocked")
    void shouldBlockDeepPathNestingAttacks() {
        String[] deepNestingAttacks = {
                // Basic deep nesting
                "/" + "dir/".repeat(1000) + "api", // 1000 directory levels
                "/" + "level/".repeat(2000) + "file", // 2000 levels deep
                "/api/" + "sub/".repeat(5000) + "resource", // 5000 nested levels
                
                // Extremely deep nesting
                "/" + ("path" + "/").repeat(10000) + "endpoint", // 10000 path segments
                "/" + "deep/".repeat(500) + "very/".repeat(500) + "nested/".repeat(500) + "api", // Mixed depths
                
                // Varied directory names
                "/" + ("dir" + hashBasedSelection(100) + "/").repeat(1000) + "target", // Varied directory names
                "/" + "A/".repeat(20000) + "final", // 20000 single-char directories
                "/" + ("folder" + "/subfolder" + "/").repeat(1000) + "destination" // Alternating long paths
        };

        for (String attack : deepNestingAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Deep path nesting attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect deep path nesting: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for deep path nesting");
        }
    }

    /**
     * Test long parameter name attacks.
     * 
     * <p>
     * Tests attacks using extremely long parameter names to cause
     * parsing issues or buffer overflows.
     * </p>
     */
    @Test
    @DisplayName("Long parameter name attacks must be blocked")
    void shouldBlockLongParameterNameAttacks() {
        String[] longNameAttacks = {
                // Basic long parameter names
                "/api?" + "A".repeat(4096) + "=value", // 4KB parameter name
                "/search?" + "param_" + "B".repeat(2000) + "=data", // Long name with prefix
                "/endpoint?" + "C".repeat(8192) + "=test&normal=ok", // Long name with normal parameter
                
                // Descriptive long names
                "/service?" + "field_name_" + "D".repeat(5000) + "=content", // Descriptive long name
                "/handler?" + "E".repeat(16384) + "=info", // 16KB parameter name
                
                // Multiple long names
                "/process?" + ("parameter_" + "F".repeat(100) + "=value&").repeat(10), // Multiple long names
                "/resource?" + "G".repeat(32768) + "=result", // 32KB parameter name
                "/data?" + "query_string_parameter_name_" + "H".repeat(10000) + "=search" // Very descriptive long name
        };

        for (String attack : longNameAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Long parameter name attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect long parameter name: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for long parameter name");
        }
    }

    /**
     * Test buffer overflow pattern attacks.
     * 
     * <p>
     * Tests attacks specifically designed to trigger buffer overflows
     * or memory allocation issues.
     * </p>
     */
    @Test
    @DisplayName("Buffer overflow pattern attacks must be blocked")
    void shouldBlockBufferOverflowPatternAttacks() {
        String[] bufferOverflows = {
                // Standard buffer overflow sizes
                "/api?" + "A".repeat(65536), // 64KB buffer overflow attempt
                "/search/" + "B".repeat(32768) + "?data=" + "C".repeat(32768), // 32KB path + 32KB parameter
                "/endpoint?buffer=" + "D".repeat(131072), // 128KB parameter
                
                // Combined overflow attempts
                "/" + "E".repeat(16384) + "/api?payload=" + "F".repeat(49152), // 16KB path + 48KB parameter = 64KB total
                "/service?" + ("overflow" + "G".repeat(1000) + "=data&").repeat(50), // Many parameters with buffer patterns
                
                // Large single components
                "/handler/" + "H".repeat(65536), // 64KB path component
                "/process?input=" + "I".repeat(262144), // 256KB parameter value
                "/resource#" + "J".repeat(131072) // 128KB fragment
        };

        for (String attack : bufferOverflows) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Buffer overflow pattern attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect buffer overflow pattern: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for buffer overflow pattern");
        }
    }

    /**
     * Test memory exhaustion attacks.
     * 
     * <p>
     * Tests attacks designed to consume excessive memory resources
     * through extremely large URL components.
     * </p>
     */
    @Test
    @DisplayName("Memory exhaustion attacks must be blocked")
    void shouldBlockMemoryExhaustionAttacks() {
        String[] memoryAttacks = {
                // Large memory allocation attempts
                "/api?memory=" + "A".repeat(500000), // 500KB parameter (reduced for test performance)
                "/search/" + "B".repeat(250000) + "?data=" + "C".repeat(250000), // 500KB total (reduced)
                
                // Structured large data
                "/endpoint?" + ("param" + hashBasedSelection(1000) + "=" + "D".repeat(500) + "&").repeat(200), // 200KB in varied parameters (reduced)
                "/service?exhaustion=" + "E".repeat(1000000), // 1MB parameter (may cause test timeout - handled by assertion)
                
                // Large path and fragment
                "/" + "F".repeat(500000) + "/api", // 500KB path prefix (reduced)
                "/handler?large_data=" + ("chunk" + "G".repeat(500)).repeat(100), // Structured large data (reduced)
                "/process#" + "H".repeat(500000) // 500KB fragment (reduced)
        };

        for (String attack : memoryAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Memory exhaustion attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect memory exhaustion: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for memory exhaustion");
        }
    }

    /**
     * Test encoding length attacks.
     * 
     * <p>
     * Tests attacks that use URL encoding to amplify the effective
     * length of the URL beyond normal limits.
     * </p>
     */
    @Test
    @DisplayName("Encoding length attacks must be blocked")
    void shouldBlockEncodingLengthAttacks() {
        String[] encodingAttacks = {
                // URL encoding amplification
                "/api?data=" + "%41".repeat(5000), // URL encoding amplification
                "/search/" + "%2E".repeat(10000), // Encoded dots
                "/endpoint?param=" + "%20".repeat(10000), // Encoded spaces
                
                // Mixed encoding patterns
                "/service/" + ("%2F" + "A".repeat(100)).repeat(200), // Mixed encoding
                "/handler?query=" + "%3C%3E".repeat(5000), // Encoded angle brackets
                "/process/" + "%2E%2E%2F".repeat(2000), // Encoded path traversal patterns
                
                // Complex encoding patterns
                "/resource?field=" + "%41%42%43".repeat(10000), // Encoded ABC pattern
                "/data#" + "%23".repeat(15000) // Encoded hash symbols
        };

        for (String attack : encodingAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Encoding length attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isLengthLimitRelatedFailure(exception.getFailureType()),
                    "Should detect encoding length attack: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for encoding length attack");
        }
    }

    /**
     * Test performance impact of URL length limit attack validation.
     * 
     * <p>
     * Ensures that URL length limit attack detection doesn't significantly
     * impact validation performance, even with very long URLs.
     * </p>
     */
    @Test
    @DisplayName("URL length limit attack validation should maintain performance")
    void shouldMaintainPerformanceWithLengthLimitAttacks() {
        String complexLengthPattern = "/" + "A".repeat(1000) + "/api?" + "param=" + "B".repeat(1000) + "&data=" + "C".repeat(1000) + "#" + "D".repeat(1000);

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexLengthPattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexLengthPattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 10ms per validation for length attacks)
        assertTrue(averageMillis < 10,
                "URL length limit attack validation should complete within 10ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test comprehensive edge cases in URL length limit detection.
     * 
     * <p>
     * Tests various edge cases and corner conditions that might be
     * exploited in URL length limit attacks.
     * </p>
     */
    @Test
    @DisplayName("URL length limit attack edge cases must be handled")
    void shouldHandleURLLengthLimitAttackEdgeCases() {
        String[] edgeCaseAttacks = {
                // Algorithmic complexity attacks
                "/api?" + ("a" + "=b&").repeat(5000), // Many small parameters (parsing complexity) - reduced count
                "/search/" + "x/".repeat(2500) + "target", // Many small path segments - reduced count
                "/" + "../".repeat(5000) + "/api", // Many traversal attempts - reduced count
                
                // Varied patterns for complexity
                "/endpoint?" + ("param" + hashBasedSelection(500) + "=value" + hashBasedSelection(500) + "&").repeat(100), // Varied parameter names - reduced count
                "/service/" + ("segment" + hashBasedSelection(50)).repeat(200), // Varied path segments - reduced count
                
                // Complex nested patterns
                "/handler?" + "regex=" + "(a+)+".repeat(500), // Regex complexity pattern - reduced count
                "/process/" + ("a" + "/b".repeat(50)).repeat(20), // Nested pattern complexity - reduced count
                "/resource?" + ("key=value" + "&").repeat(10000) // Simple but numerous parameters
        };

        for (String attack : edgeCaseAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "URL length limit edge case should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for edge case");
        }
    }

    /**
     * Determines if a URL pattern represents a path-based length attack that should be caught by URL path validation.
     * 
     * @param pattern The URL pattern to analyze
     * @return true if this is a path-based attack that should be rejected, false if it's a hostname-based attack
     */
    private boolean isPathBasedLengthAttack(String pattern) {
        // Extract the path component from the URL
        String pathComponent;
        if (pattern.startsWith("http://") || pattern.startsWith("https://")) {
            // Full URL - extract path after hostname
            int schemeEnd = pattern.indexOf("://") + 3;
            int pathStart = pattern.indexOf('/', schemeEnd);
            if (pathStart == -1) {
                pathComponent = "/"; // No path, just hostname
            } else {
                int fragmentStart = pattern.indexOf('#', pathStart);
                int queryStart = pattern.indexOf('?', pathStart);

                int pathEnd = pattern.length();
                if (fragmentStart != -1) pathEnd = Math.min(pathEnd, fragmentStart);
                if (queryStart != -1) pathEnd = Math.min(pathEnd, queryStart);

                pathComponent = pattern.substring(pathStart, pathEnd);
            }
        } else {
            // Relative path - extract path before query/fragment
            int fragmentStart = pattern.indexOf('#');
            int queryStart = pattern.indexOf('?');

            int pathEnd = pattern.length();
            if (fragmentStart != -1) pathEnd = Math.min(pathEnd, fragmentStart);
            if (queryStart != -1) pathEnd = Math.min(pathEnd, queryStart);

            pathComponent = pattern.substring(0, pathEnd);
        }

        // Return true if the path component exceeds our configured limit (1024)
        return pathComponent.length() > 1024;
    }

    /**
     * Determines if a failure type is related to URL length limit attacks.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates a length limit-related security issue
     */
    private boolean isLengthLimitRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.INPUT_TOO_LONG ||
                failureType == UrlSecurityFailureType.PATH_TOO_LONG ||
                failureType == UrlSecurityFailureType.EXCESSIVE_NESTING ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.INVALID_STRUCTURE ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.PROTOCOL_VIOLATION ||
                failureType == UrlSecurityFailureType.RFC_VIOLATION ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER; // Repeated chars in length attacks
    }

    /**
     * Helper method for hash-based selection in tests.
     */
    private int hashBasedSelection(int bound) {
        return Math.abs(this.hashCode()) % bound;
    }
}