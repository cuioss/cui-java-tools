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

import java.util.Arrays;
import java.util.List;

/**
 * Generator for URL length limit attack patterns.
 * 
 * <p>
 * This generator creates comprehensive URL length limit attack vectors that
 * attempt to exploit URL length limitations to cause denial of service,
 * buffer overflows, or bypass security controls. The generator covers various
 * URL length attack techniques used by attackers to exploit web applications
 * through excessive URL sizes.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li><strong>Basic Length Overflow</strong> - URLs exceeding standard length limits</li>
 *   <li><strong>Path Component Overflow</strong> - Extremely long path segments</li>
 *   <li><strong>Query Parameter Overflow</strong> - Long query strings and parameters</li>
 *   <li><strong>Fragment Overflow</strong> - Long URL fragments</li>
 *   <li><strong>Hostname Overflow</strong> - Long hostname components</li>
 *   <li><strong>Repeated Parameter Attack</strong> - Many identical parameters</li>
 *   <li><strong>Deep Path Nesting</strong> - Many nested directory levels</li>
 *   <li><strong>Long Parameter Names</strong> - Extremely long parameter names</li>
 *   <li><strong>Long Parameter Values</strong> - Extremely long parameter values</li>
 *   <li><strong>Mixed Length Attacks</strong> - Combination of long components</li>
 *   <li><strong>Buffer Overflow Patterns</strong> - Patterns designed to cause overflows</li>
 *   <li><strong>Memory Exhaustion</strong> - URLs designed to consume memory</li>
 *   <li><strong>Parser Confusion</strong> - Long URLs with parsing challenges</li>
 *   <li><strong>Encoding Length Attacks</strong> - Length amplification via encoding</li>
 *   <li><strong>Algorithmic Complexity</strong> - URLs causing processing slowdown</li>
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
 * <h3>Usage Example</h3>
 * <pre>
 * &#64;ParameterizedTest
 * &#64;TypeGeneratorSource(value = URLLengthLimitAttackGenerator.class, count = 100)
 * void shouldRejectURLLengthLimitAttacks(String lengthAttack) {
 *     assertThrows(UrlSecurityException.class, 
 *         () -> pipeline.validate(lengthAttack));
 * }
 * </pre>
 * 
 * Implements: Task T19 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class URLLengthLimitAttackGenerator implements TypedGenerator<String> {

    private static final List<String> BASE_PATTERNS = Arrays.asList(
            "/api",
            "/search",
            "/data",
            "/resource",
            "/service",
            "/endpoint",
            "/handler",
            "/process",
            "/action",
            "/request"
    );

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(15);

    @Override
    public String next() {
        String basePattern = BASE_PATTERNS.get(hashBasedSelection(BASE_PATTERNS.size()));

        return switch (attackTypeSelector.nextAttackType()) {
            case 0 -> createBasicLengthOverflow(basePattern);
            case 1 -> createPathComponentOverflow(basePattern);
            case 2 -> createQueryParameterOverflow(basePattern);
            case 3 -> createFragmentOverflow(basePattern);
            case 4 -> createHostnameOverflow(basePattern);
            case 5 -> createRepeatedParameterAttack(basePattern);
            case 6 -> createDeepPathNesting(basePattern);
            case 7 -> createLongParameterNames(basePattern);
            case 8 -> createLongParameterValues(basePattern);
            case 9 -> createMixedLengthAttacks(basePattern);
            case 10 -> createBufferOverflowPatterns(basePattern);
            case 11 -> createMemoryExhaustionAttack(basePattern);
            case 12 -> createParserConfusion(basePattern);
            case 13 -> createEncodingLengthAttacks(basePattern);
            case 14 -> createAlgorithmicComplexity(basePattern);
            default -> createBasicLengthOverflow(basePattern);
        };
    }

    /**
     * Creates basic URL length overflow attacks exceeding standard limits.
     */
    private String createBasicLengthOverflow(String pattern) {
        // Standard URL length limits: IE (2083), Chrome (2MB), but servers typically limit to 8KB
        String[] lengthOverflows = {
                pattern + "?" + "A".repeat(8192), // 8KB limit test
                pattern + "?" + "B".repeat(16384), // 16KB limit test
                pattern + "/" + "C".repeat(4096), // Long path
                pattern + "?" + "param=" + "D".repeat(10000), // Long parameter value
                pattern + "/" + "E".repeat(2048) + "?data=" + "F".repeat(2048), // Mixed long components
                pattern + "?" + "G".repeat(32768), // 32KB attack
                pattern + "/" + "H".repeat(1024) + "/" + "I".repeat(1024) + "/" + "J".repeat(1024), // Multiple long segments
                pattern + "?" + "field=" + "K".repeat(65536) // 64KB parameter
        };
        return lengthOverflows[hashBasedSelection(lengthOverflows.length)];
    }

    /**
     * Creates path component overflow attacks with extremely long path segments.
     */
    private String createPathComponentOverflow(String pattern) {
        String[] pathOverflows = {
                pattern + "/" + "segment".repeat(1000), // Repeated segment names
                pattern + "/" + "A".repeat(4096) + "/normal", // One very long segment
                pattern + "/" + "path_" + "B".repeat(2048) + "/data", // Long segment with prefix
                "/" + "C".repeat(8192) + pattern, // Long prefix path
                pattern + "/" + "dir_" + "D".repeat(1024) + "/file_" + "E".repeat(1024), // Multiple long segments
                pattern + "/" + "very_long_directory_name_" + "F".repeat(3000), // Descriptive long segment
                pattern + "/" + "component" + "G".repeat(512) + "/subdir" + "H".repeat(512) + "/file", // Nested long paths
                pattern + "/" + "I".repeat(16384) // Single massive segment
        };
        return pathOverflows[hashBasedSelection(pathOverflows.length)];
    }

    /**
     * Creates query parameter overflow attacks with long query strings.
     */
    private String createQueryParameterOverflow(String pattern) {
        String[] queryOverflows = {
                pattern + "?" + "param=" + "A".repeat(10000), // Single long parameter
                pattern + "?" + "data=" + "B".repeat(5000) + "&info=" + "C".repeat(5000), // Multiple long parameters
                pattern + "?" + "query=" + "D".repeat(20000), // Very long single parameter
                pattern + "?" + "search=" + "term ".repeat(2000), // Repeated terms
                pattern + "?" + "content=" + "E".repeat(8192) + "&type=json", // Long parameter with normal parameter
                pattern + "?" + "input=" + ("value" + "F".repeat(100) + "&").repeat(50), // Many medium-length parameters
                pattern + "?" + "buffer=" + "G".repeat(32768), // 32KB parameter value
                pattern + "?" + "payload=" + "H".repeat(65536) // 64KB parameter value
        };
        return queryOverflows[hashBasedSelection(queryOverflows.length)];
    }

    /**
     * Creates fragment overflow attacks with long URL fragments.
     */
    private String createFragmentOverflow(String pattern) {
        String[] fragmentOverflows = {
                pattern + "#" + "A".repeat(4096), // Long fragment
                pattern + "?param=value#" + "B".repeat(8192), // Long fragment with query
                pattern + "/path#" + "section" + "C".repeat(2000), // Long named fragment
                pattern + "#" + "anchor_" + "D".repeat(5000), // Long fragment with prefix
                pattern + "?data=test#" + "E".repeat(16384), // Very long fragment
                pattern + "#" + ("part" + "F".repeat(50) + "_").repeat(100), // Repeated fragment parts
                pattern + "#" + "G".repeat(32768), // 32KB fragment
                pattern + "/resource?id=123#" + "content_" + "H".repeat(10000) // Mixed with long fragment
        };
        return fragmentOverflows[hashBasedSelection(fragmentOverflows.length)];
    }

    /**
     * Creates hostname overflow attacks with long hostname components.
     */
    private String createHostnameOverflow(String pattern) {
        String[] hostnameOverflows = {
                "http://" + "A".repeat(253) + ".com" + pattern, // Max hostname length
                "https://" + "B".repeat(63) + "." + "C".repeat(63) + ".com" + pattern, // Max label length
                "http://" + "subdomain".repeat(30) + ".example.com" + pattern, // Many subdomains
                "https://" + "D".repeat(1000) + ".evil.com" + pattern, // Excessive hostname
                "http://" + ("sub" + "E".repeat(20) + ".").repeat(10) + "domain.com" + pattern, // Nested long subdomains
                "https://" + "F".repeat(512) + ".attacker.org" + pattern, // Very long subdomain
                "http://" + "G".repeat(2048) + ".malicious.net" + pattern, // Extremely long hostname part
                "https://" + ("long" + "H".repeat(50)).repeat(5) + ".test.com" + pattern // Multiple long parts
        };
        return hostnameOverflows[hashBasedSelection(hostnameOverflows.length)];
    }

    /**
     * Creates repeated parameter attacks with many identical parameters.
     */
    private String createRepeatedParameterAttack(String pattern) {
        String[] repeatedParams = {
                pattern + "?" + "param=value&".repeat(1000), // 1000 identical parameters
                pattern + "?" + "data=test&".repeat(2000), // 2000 parameters
                pattern + "?" + "field=info&".repeat(5000), // 5000 parameters
                pattern + "?" + ("item=" + "A".repeat(100) + "&").repeat(500), // 500 parameters with long values
                pattern + "?" + "query=search&".repeat(10000), // 10000 parameters
                pattern + "?" + ("param" + "B".repeat(50) + "=value&").repeat(200), // Long parameter names
                pattern + "?" + "test=data&".repeat(50000), // 50000 parameters
                pattern + "?" + ("key=value" + "C".repeat(10) + "&").repeat(1000) // Mixed repeated parameters
        };
        return repeatedParams[hashBasedSelection(repeatedParams.length)];
    }

    /**
     * Creates deep path nesting attacks with many directory levels.
     */
    private String createDeepPathNesting(String pattern) {
        String[] deepPaths = {
                "/" + "dir/".repeat(1000) + pattern.substring(1), // 1000 directory levels
                "/" + "level/".repeat(2000) + "file", // 2000 levels deep
                pattern + "/" + "sub/".repeat(5000) + "resource", // 5000 nested levels
                "/" + ("path" + "/").repeat(10000) + "endpoint", // 10000 path segments
                "/" + "deep/".repeat(500) + "very/".repeat(500) + "nested/".repeat(500) + pattern.substring(1), // Mixed depths
                "/" + ("dir" + hashBasedSelection(100) + "/").repeat(1000) + "target", // Varied directory names
                "/" + "A/".repeat(20000) + "final", // 20000 single-char directories
                "/" + ("folder" + "/subfolder" + "/").repeat(1000) + "destination" // Alternating long paths
        };
        return deepPaths[hashBasedSelection(deepPaths.length)];
    }

    /**
     * Creates attacks with extremely long parameter names.
     */
    private String createLongParameterNames(String pattern) {
        String[] longNames = {
                pattern + "?" + "A".repeat(4096) + "=value", // 4KB parameter name
                pattern + "?" + "param_" + "B".repeat(2000) + "=data", // Long name with prefix
                pattern + "?" + "C".repeat(8192) + "=test&normal=ok", // Long name with normal parameter
                pattern + "?" + "field_name_" + "D".repeat(5000) + "=content", // Descriptive long name
                pattern + "?" + "E".repeat(16384) + "=info", // 16KB parameter name
                pattern + "?" + ("parameter_" + "F".repeat(100) + "=value&").repeat(10), // Multiple long names
                pattern + "?" + "G".repeat(32768) + "=result", // 32KB parameter name
                pattern + "?" + "query_string_parameter_name_" + "H".repeat(10000) + "=search" // Very descriptive long name
        };
        return longNames[hashBasedSelection(longNames.length)];
    }

    /**
     * Creates attacks with extremely long parameter values.
     */
    private String createLongParameterValues(String pattern) {
        String[] longValues = {
                pattern + "?data=" + "A".repeat(10000), // 10KB parameter value
                pattern + "?content=" + "B".repeat(20000), // 20KB parameter value
                pattern + "?payload=" + "C".repeat(50000), // 50KB parameter value
                pattern + "?info=" + "D".repeat(100000), // 100KB parameter value
                pattern + "?search=" + ("query " + "E".repeat(500) + " ").repeat(100), // Repeated long terms
                pattern + "?input=" + "F".repeat(200000), // 200KB parameter value
                pattern + "?field=" + "value_" + "G".repeat(80000), // Long value with prefix
                pattern + "?buffer=" + "H".repeat(500000) // 500KB parameter value
        };
        return longValues[hashBasedSelection(longValues.length)];
    }

    /**
     * Creates mixed length attacks combining multiple long components.
     */
    private String createMixedLengthAttacks(String pattern) {
        String[] mixedAttacks = {
                "/" + "A".repeat(1000) + pattern + "?" + "param=" + "B".repeat(1000) + "#" + "C".repeat(1000), // Long path, query, fragment
                pattern + "/" + "D".repeat(2000) + "?" + "E".repeat(1000) + "=value", // Long path segment and parameter name
                "/" + "path/".repeat(500) + pattern.substring(1) + "?" + "data=" + "F".repeat(5000), // Deep path with long parameter
                pattern + "/" + "G".repeat(1500) + "/" + "H".repeat(1500) + "?" + "query=" + "I".repeat(3000), // Multiple long components
                "/" + "J".repeat(4000) + "?" + ("param" + "K".repeat(200) + "=" + "L".repeat(200) + "&").repeat(10), // Very long path with multiple long parameters
                pattern + "/" + "segment_" + "M".repeat(2500) + "?" + "field_" + "N".repeat(1000) + "=" + "O".repeat(2000) + "#anchor_" + "P".repeat(1000), // All components long
                "/" + "dir/".repeat(1000) + "resource" + "?" + "buffer=" + "Q".repeat(10000), // Deep nesting with long parameter
                "https://" + "R".repeat(200) + ".example.com" + pattern + "/" + "S".repeat(1000) + "?" + "data=" + "T".repeat(2000) // Long hostname, path, and parameter
        };
        return mixedAttacks[hashBasedSelection(mixedAttacks.length)];
    }

    /**
     * Creates buffer overflow patterns designed to trigger memory issues.
     */
    private String createBufferOverflowPatterns(String pattern) {
        String[] bufferOverflows = {
                pattern + "?" + "A".repeat(65536), // 64KB buffer overflow attempt
                pattern + "/" + "B".repeat(32768) + "?" + "data=" + "C".repeat(32768), // 32KB path + 32KB parameter
                pattern + "?" + "buffer=" + "D".repeat(131072), // 128KB parameter
                "/" + "E".repeat(16384) + pattern + "?" + "payload=" + "F".repeat(49152), // 16KB path + 48KB parameter = 64KB total
                pattern + "?" + ("overflow" + "G".repeat(1000) + "=data&").repeat(50), // Many parameters with buffer patterns
                pattern + "/" + "H".repeat(65536), // 64KB path component
                pattern + "?" + "input=" + "I".repeat(262144), // 256KB parameter value
                pattern + "#" + "J".repeat(131072) // 128KB fragment
        };
        return bufferOverflows[hashBasedSelection(bufferOverflows.length)];
    }

    /**
     * Creates memory exhaustion attacks designed to consume server memory.
     */
    private String createMemoryExhaustionAttack(String pattern) {
        String[] memoryAttacks = {
                pattern + "?" + "memory=" + "A".repeat(1000000), // 1MB parameter
                pattern + "/" + "B".repeat(500000) + "?" + "data=" + "C".repeat(500000), // 1MB total
                pattern + "?" + ("param" + hashBasedSelection(10000) + "=" + "D".repeat(1000) + "&").repeat(500), // 500KB in varied parameters
                pattern + "?" + "exhaustion=" + "E".repeat(2000000), // 2MB parameter
                "/" + "F".repeat(1000000) + pattern, // 1MB path prefix
                pattern + "?" + "large_data=" + ("chunk" + "G".repeat(1000)).repeat(200), // Structured large data
                pattern + "#" + "H".repeat(1000000), // 1MB fragment
                pattern + "?" + "payload=" + "I".repeat(5000000) // 5MB parameter
        };
        return memoryAttacks[hashBasedSelection(memoryAttacks.length)];
    }

    /**
     * Creates parser confusion attacks with challenging parsing scenarios.
     */
    private String createParserConfusion(String pattern) {
        String[] parserConfusions = {
                pattern + "?" + "A".repeat(10000) + "=" + "B".repeat(10000) + "&" + "C".repeat(5000) + "=" + "D".repeat(5000), // Multiple long parameters
                pattern + "/" + ("segment" + "E".repeat(500) + "/").repeat(20) + "?" + "query=" + "F".repeat(10000), // Mixed long segments and parameters
                "/" + "G".repeat(8000) + "/" + "H".repeat(8000) + pattern + "?" + "data=" + "I".repeat(8000), // Long prefix and suffix
                pattern + "?" + ("key" + "J".repeat(200) + "=value" + "K".repeat(200) + "&").repeat(100), // Many medium-long parameters
                pattern + "/" + "L".repeat(16000) + "#" + "M".repeat(16000), // Long path and fragment
                pattern + "?" + "complex=" + ("part" + "N".repeat(100) + "_").repeat(500), // Structured long parameter
                "/" + ("dir" + "O".repeat(50) + "/").repeat(200) + pattern + "?" + ("param" + "P".repeat(50) + "=val&").repeat(200), // Many structured components
                pattern + "?" + "test=" + "Q".repeat(20000) + "&verify=" + "R".repeat(20000) + "#section=" + "S".repeat(20000) // All components very long
        };
        return parserConfusions[hashBasedSelection(parserConfusions.length)];
    }

    /**
     * Creates encoding length attacks that amplify length through encoding.
     */
    private String createEncodingLengthAttacks(String pattern) {
        String[] encodingAttacks = {
                pattern + "?" + "data=" + "%41".repeat(5000), // URL encoding amplification
                pattern + "/" + "%2E".repeat(10000), // Encoded dots
                pattern + "?" + "param=" + "%20".repeat(10000), // Encoded spaces
                pattern + "/" + ("%2F" + "A".repeat(100)).repeat(200), // Mixed encoding
                pattern + "?" + "query=" + "%3C%3E".repeat(5000), // Encoded angle brackets
                pattern + "/" + "%2E%2E%2F".repeat(2000), // Encoded path traversal patterns
                pattern + "?" + "field=" + "%41%42%43".repeat(10000), // Encoded ABC pattern
                pattern + "#" + "%23".repeat(15000) // Encoded hash symbols
        };
        return encodingAttacks[hashBasedSelection(encodingAttacks.length)];
    }

    /**
     * Creates algorithmic complexity attacks causing processing slowdown.
     */
    private String createAlgorithmicComplexity(String pattern) {
        String[] complexityAttacks = {
                pattern + "?" + ("a" + "=b&").repeat(10000), // Many small parameters (parsing complexity)
                pattern + "/" + "x/".repeat(5000) + "target", // Many small path segments
                "/" + "../".repeat(10000) + pattern, // Many traversal attempts
                pattern + "?" + ("param" + hashBasedSelection(1000) + "=value" + hashBasedSelection(1000) + "&").repeat(1000), // Varied parameter names
                pattern + "/" + ("segment" + hashBasedSelection(100)).repeat(1000), // Varied path segments
                pattern + "?" + "regex=" + "(a+)+".repeat(1000), // Regex complexity pattern
                pattern + "/" + ("a" + "/b".repeat(100)).repeat(100), // Nested pattern complexity
                pattern + "?" + ("key=value" + "&").repeat(20000) // Simple but numerous parameters
        };
        return complexityAttacks[hashBasedSelection(complexityAttacks.length)];
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }

    /**
     * Creates hash-based selection for deterministic but varied attack patterns.
     */
    private int hashBasedSelection(int bound) {
        return Math.abs((int) (this.hashCode() + System.nanoTime())) % bound;
    }

    /**
     * Helper class to cycle through attack types systematically.
     */
    private static class AttackTypeSelector {
        private final int maxTypes;
        private int currentType = 0;

        AttackTypeSelector(int maxTypes) {
            this.maxTypes = maxTypes;
        }

        int nextAttackType() {
            int type = currentType;
            currentType = (currentType + 1) % maxTypes;
            return type;
        }
    }
}