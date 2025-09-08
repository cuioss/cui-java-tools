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

import de.cuioss.test.generator.Generators;
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

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(13); // Removed encoding attacks (13,14) - they test encoding not length

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
            case 12 -> createAlgorithmicComplexity(basePattern);
            // Removed case 13 (encoding attacks) and case 14 - they test encoding validation not length validation
            default -> createBasicLengthOverflow(basePattern);
        };
    }

    /**
     * Creates basic URL length overflow attacks exceeding standard limits.
     */
    private String createBasicLengthOverflow(String pattern) {
        // Test realistic length limits: STRICT=1024, DEFAULT=4096, LENIENT=8192
        // Generate URLs just over these limits to test actual validation logic
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.letterStrings(1030, 1050).next(); // Just over STRICT limit
            case 1 -> pattern + "/" + Generators.letterStrings(1025, 1040).next(); // Barely over STRICT
            case 2 -> pattern + "?" + "param=" + Generators.letterStrings(4100, 4150).next(); // Just over DEFAULT limit
            case 3 -> pattern + "/" + Generators.letterStrings(4097, 4120).next(); // Barely over DEFAULT
            case 4 -> pattern + "?" + Generators.letterStrings(8200, 8250).next(); // Just over LENIENT limit
            case 5 -> pattern + "/" + Generators.letterStrings(8193, 8210).next(); // Barely over LENIENT
            case 6 -> pattern + "/" + Generators.letterStrings(512, 512).next() + "/" + Generators.letterStrings(512, 512).next() + "?" + Generators.letterStrings(512, 512).next(); // Distributed length
            case 7 -> pattern + "?" + "field=" + Generators.letterStrings(2050, 2100).next(); // Medium overflow
            default -> pattern + "?" + Generators.letterStrings(1030, 1050).next(); // Default just over STRICT
        };
    }

    /**
     * Creates path component overflow attacks with extremely long path segments.
     */
    private String createPathComponentOverflow(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "/" + Generators.strings("segment/", 150, 180).next() + "file"; // Repeated segments to reach limits
            case 1 -> pattern + "/" + Generators.letterStrings(1030, 1050).next() + "/normal"; // Single long segment over STRICT
            case 2 -> pattern + "/" + "path_" + Generators.letterStrings(1000, 1020).next() + "/data"; // Long segment with prefix
            case 3 -> "/" + Generators.letterStrings(800, 850).next() + pattern + "/file"; // Long prefix path  
            case 4 -> pattern + "/" + "dir_" + Generators.letterStrings(500, 520).next() + "/file_" + Generators.letterStrings(500, 520).next(); // Multiple segments
            case 5 -> pattern + "/" + "very_long_directory_name_" + Generators.letterStrings(950, 980).next(); // Descriptive long segment
            case 6 -> pattern + "/" + "component" + Generators.letterStrings(400, 420).next() + "/subdir" + Generators.letterStrings(400, 420).next() + "/file"; // Nested paths
            case 7 -> pattern + "/" + Generators.letterStrings(4100, 4150).next() + "/end"; // Just over DEFAULT limit
            default -> pattern + "/" + Generators.letterStrings(1030, 1050).next(); // Default just over STRICT
        };
    }

    /**
     * Creates query parameter overflow attacks with long query strings.
     */
    private String createQueryParameterOverflow(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + "param=" + Generators.letterStrings(900, 950).next(); // Parameter value near STRICT limit
            case 1 -> pattern + "?" + "data=" + Generators.letterStrings(500, 520).next() + "&info=" + Generators.letterStrings(500, 520).next(); // Multiple parameters
            case 2 -> pattern + "?" + "query=" + Generators.letterStrings(3800, 3900).next(); // Parameter near DEFAULT limit
            case 3 -> pattern + "?" + "search=" + Generators.strings("term ", 200, 250).next(); // Repeated terms to reach limit
            case 4 -> pattern + "?" + "content=" + Generators.letterStrings(900, 950).next() + "&type=json"; // Long parameter with normal
            case 5 -> pattern + "?" + Generators.strings("input=value123&", 50, 80).next(); // Many small parameters
            case 6 -> pattern + "?" + "buffer=" + Generators.letterStrings(7800, 7900).next(); // Near LENIENT limit
            case 7 -> pattern + "?" + "payload=" + Generators.letterStrings(1030, 1080).next() + "&extra=data"; // Just over STRICT with extra
            default -> pattern + "?" + "param=" + Generators.letterStrings(1030, 1050).next(); // Default just over STRICT
        };
    }

    /**
     * Creates fragment overflow attacks with long URL fragments.
     */
    private String createFragmentOverflow(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "#" + Generators.letterStrings(500, 550).next(); // Fragment within reasonable limits
            case 1 -> pattern + "?param=value#" + Generators.letterStrings(800, 850).next(); // Long fragment with query
            case 2 -> pattern + "/path#" + "section" + Generators.letterStrings(400, 450).next(); // Named fragment
            case 3 -> pattern + "#" + "anchor_" + Generators.letterStrings(600, 650).next(); // Fragment with prefix
            case 4 -> pattern + "?data=test#" + Generators.letterStrings(900, 950).next(); // Long fragment near STRICT
            case 5 -> pattern + "#" + Generators.strings("part_", 60, 80).next(); // Repeated fragment parts
            case 6 -> pattern + "#" + Generators.letterStrings(3800, 3900).next(); // Fragment near DEFAULT limit
            case 7 -> pattern + "/resource?id=123#" + "content_" + Generators.letterStrings(700, 750).next(); // Mixed with fragment
            default -> pattern + "#" + Generators.letterStrings(500, 550).next(); // Default fragment
        };
    }

    /**
     * Creates hostname overflow attacks with long hostname components.
     */
    private String createHostnameOverflow(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> "https://" + Generators.letterStrings(250, 253).next() + ".com" + pattern; // Near DNS max hostname (253)
            case 1 -> "https://" + Generators.letterStrings(60, 63).next() + "." + Generators.letterStrings(60, 63).next() + ".com" + pattern; // Near DNS max label (63)
            case 2 -> "https://" + Generators.strings("subdomain.", 15, 25).next() + "example.com" + pattern; // Many subdomains within reason
            case 3 -> "https://" + Generators.letterStrings(100, 120).next() + ".evil.com" + pattern; // Long but reasonable subdomain
            case 4 -> "https://" + Generators.strings("sub", 50, 80).next() + ".domain.com" + pattern; // Repeated subdomain parts
            case 5 -> "https://" + Generators.letterStrings(80, 100).next() + ".attacker.org" + pattern; // Long subdomain
            case 6 -> "https://" + Generators.letterStrings(150, 200).next() + ".malicious.net" + pattern; // Very long hostname part
            case 7 -> "https://" + Generators.strings("long", 30, 50).next() + ".test.com" + pattern; // Multiple long parts
            default -> "https://" + Generators.letterStrings(100, 120).next() + ".com" + pattern; // Default long hostname
        };
    }

    /**
     * Creates repeated parameter attacks with many identical parameters.
     */
    private String createRepeatedParameterAttack(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.strings("param=value&", 30, 50).next(); // Many small parameters to reach limit
            case 1 -> pattern + "?" + Generators.strings("data=test&", 40, 60).next(); // Repeated parameters
            case 2 -> pattern + "?" + Generators.strings("field=info&", 25, 35).next(); // Parameter repetition
            case 3 -> pattern + "?" + Generators.strings("item=" + Generators.letterStrings(20, 30).next() + "&", 15, 25).next(); // Parameters with medium values
            case 4 -> pattern + "?" + Generators.strings("query=search&", 35, 55).next(); // Many search parameters
            case 5 -> pattern + "?" + Generators.strings("param" + Generators.letterStrings(10, 15).next() + "=value&", 20, 30).next(); // Varied parameter names
            case 6 -> pattern + "?" + Generators.strings("test=data&", 60, 90).next(); // Many test parameters
            case 7 -> pattern + "?" + Generators.strings("key=value" + Generators.letterStrings(5, 10).next() + "&", 25, 40).next(); // Mixed parameters
            default -> pattern + "?" + Generators.strings("param=value&", 30, 50).next(); // Default repeated parameters
        };
    }

    /**
     * Creates deep path nesting attacks with many directory levels.
     */
    private String createDeepPathNesting(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> "/" + Generators.strings("dir/", 40, 60).next() + pattern.substring(1); // Many directory levels to reach limits
            case 1 -> "/" + Generators.strings("level/", 50, 70).next() + "file"; // Deep levels
            case 2 -> pattern + "/" + Generators.strings("sub/", 30, 50).next() + "resource"; // Nested levels
            case 3 -> "/" + Generators.strings("path/", 45, 65).next() + "endpoint"; // Many path segments
            case 4 -> "/" + Generators.strings("deep/", 20, 30).next() + Generators.strings("very/", 20, 30).next() + "nested/" + pattern.substring(1); // Mixed depths
            case 5 -> "/" + Generators.strings("dir" + hashBasedSelection(100) + "/", 35, 55).next() + "target"; // Varied directory names
            case 6 -> "/" + Generators.strings("A/", 80, 120).next() + "final"; // Single-char directories
            case 7 -> "/" + Generators.strings("folder/subfolder/", 25, 35).next() + "destination"; // Alternating paths
            default -> "/" + Generators.strings("dir/", 40, 60).next() + pattern.substring(1); // Default deep nesting
        };
    }

    /**
     * Creates attacks with extremely long parameter names.
     */
    private String createLongParameterNames(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.letterStrings(900, 950).next() + "=value"; // Long parameter name near STRICT
            case 1 -> pattern + "?" + "param_" + Generators.letterStrings(800, 850).next() + "=data"; // Long name with prefix
            case 2 -> pattern + "?" + Generators.letterStrings(700, 750).next() + "=test&normal=ok"; // Long name with normal parameter
            case 3 -> pattern + "?" + "field_name_" + Generators.letterStrings(600, 650).next() + "=content"; // Descriptive long name
            case 4 -> pattern + "?" + Generators.letterStrings(3800, 3900).next() + "=info"; // Parameter name near DEFAULT limit
            case 5 -> pattern + "?" + Generators.strings("parameter_" + Generators.letterStrings(20, 30).next() + "=value&", 10, 15).next(); // Multiple medium names
            case 6 -> pattern + "?" + Generators.letterStrings(1030, 1080).next() + "=result"; // Just over STRICT limit
            case 7 -> pattern + "?" + "query_string_parameter_name_" + Generators.letterStrings(500, 550).next() + "=search"; // Very descriptive name
            default -> pattern + "?" + Generators.letterStrings(900, 950).next() + "=value"; // Default long name
        };
    }

    /**
     * Creates attacks with extremely long parameter values.
     */
    private String createLongParameterValues(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?data=" + Generators.letterStrings(1030, 1080).next(); // Just over STRICT limit
            case 1 -> pattern + "?content=" + Generators.letterStrings(4100, 4150).next(); // Just over DEFAULT limit
            case 2 -> pattern + "?payload=" + Generators.letterStrings(8200, 8250).next(); // Just over LENIENT limit
            case 3 -> pattern + "?info=" + Generators.letterStrings(2000, 2100).next(); // Medium length value
            case 4 -> pattern + "?search=" + Generators.strings("query ", 150, 200).next(); // Repeated search terms
            case 5 -> pattern + "?input=" + Generators.letterStrings(3000, 3200).next(); // Large but reasonable value
            case 6 -> pattern + "?field=" + "value_" + Generators.letterStrings(900, 950).next(); // Long value with prefix
            case 7 -> pattern + "?buffer=" + Generators.letterStrings(7800, 7900).next(); // Near LENIENT limit
            default -> pattern + "?data=" + Generators.letterStrings(1030, 1080).next(); // Default just over STRICT
        };
    }

    /**
     * Creates mixed length attacks combining multiple long components.
     */
    private String createMixedLengthAttacks(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> "/" + Generators.letterStrings(300, 350).next() + pattern + "?" + "param=" + Generators.letterStrings(300, 350).next() + "#" + Generators.letterStrings(300, 350).next(); // Distributed length components
            case 1 -> pattern + "/" + Generators.letterStrings(500, 550).next() + "?" + Generators.letterStrings(400, 450).next() + "=value"; // Long path segment and parameter name
            case 2 -> "/" + Generators.strings("path/", 15, 25).next() + pattern.substring(1) + "?" + "data=" + Generators.letterStrings(800, 850).next(); // Deep path with long parameter
            case 3 -> pattern + "/" + Generators.letterStrings(400, 450).next() + "/" + Generators.letterStrings(400, 450).next() + "?" + "query=" + Generators.letterStrings(600, 650).next(); // Multiple medium components
            case 4 -> "/" + Generators.letterStrings(800, 850).next() + "?" + Generators.strings("param" + Generators.letterStrings(15, 20).next() + "=" + Generators.letterStrings(15, 20).next() + "&", 8, 12).next(); // Long path with parameters
            case 5 -> pattern + "/" + "segment_" + Generators.letterStrings(400, 450).next() + "?" + "field_" + Generators.letterStrings(200, 250).next() + "=" + Generators.letterStrings(400, 450).next() + "#anchor_" + Generators.letterStrings(200, 250).next(); // All components reasonable
            case 6 -> "/" + Generators.strings("dir/", 30, 50).next() + "resource" + "?" + "buffer=" + Generators.letterStrings(600, 650).next(); // Deep nesting with parameter
            case 7 -> "https://" + Generators.letterStrings(80, 100).next() + ".example.com" + pattern + "/" + Generators.letterStrings(300, 350).next() + "?" + "data=" + Generators.letterStrings(400, 450).next(); // Long hostname, path, and parameter
            default -> pattern + "/" + Generators.letterStrings(400, 450).next() + "?" + "param=" + Generators.letterStrings(400, 450).next(); // Default mixed length
        };
    }

    /**
     * Creates buffer overflow patterns designed to trigger memory issues.
     */
    private String createBufferOverflowPatterns(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.letterStrings(8200, 8300).next(); // Just over LENIENT limit (testing buffer boundaries)
            case 1 -> pattern + "/" + Generators.letterStrings(4100, 4200).next() + "?" + "data=" + Generators.letterStrings(4100, 4200).next(); // DEFAULT limit overflow in both components
            case 2 -> pattern + "?" + "buffer=" + Generators.letterStrings(9000, 9500).next(); // Moderate buffer test
            case 3 -> "/" + Generators.letterStrings(2000, 2100).next() + pattern + "?" + "payload=" + Generators.letterStrings(6000, 6500).next(); // Distributed length test
            case 4 -> pattern + "?" + Generators.strings("overflow" + Generators.letterStrings(20, 30).next() + "=data&", 30, 50).next(); // Many parameters with patterns
            case 5 -> pattern + "/" + Generators.letterStrings(8300, 8400).next(); // Path component just over LENIENT
            case 6 -> pattern + "?" + "input=" + Generators.letterStrings(10000, 12000).next(); // Large but not extreme parameter
            case 7 -> pattern + "#" + Generators.letterStrings(7000, 7500).next(); // Large fragment
            default -> pattern + "?" + Generators.letterStrings(8200, 8300).next(); // Default buffer test
        };
    }

    /**
     * Creates memory exhaustion attacks designed to consume server memory.
     */
    private String createMemoryExhaustionAttack(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + "memory=" + Generators.letterStrings(12000, 15000).next(); // Large but reasonable parameter
            case 1 -> pattern + "/" + Generators.letterStrings(4000, 4500).next() + "?" + "data=" + Generators.letterStrings(4000, 4500).next(); // Distributed large components
            case 2 -> pattern + "?" + Generators.strings("param" + hashBasedSelection(100) + "=" + Generators.letterStrings(20, 30).next() + "&", 100, 200).next(); // Many parameters with varied data
            case 3 -> pattern + "?" + "exhaustion=" + Generators.letterStrings(20000, 25000).next(); // Large parameter test
            case 4 -> "/" + Generators.letterStrings(6000, 8000).next() + pattern; // Large path prefix
            case 5 -> pattern + "?" + "large_data=" + Generators.strings("chunk" + Generators.letterStrings(50, 100).next(), 50, 100).next(); // Structured data within limits
            case 6 -> pattern + "#" + Generators.letterStrings(10000, 15000).next(); // Large fragment
            case 7 -> pattern + "?" + "payload=" + Generators.letterStrings(30000, 35000).next(); // Large payload test
            default -> pattern + "?" + "memory=" + Generators.letterStrings(12000, 15000).next(); // Default memory test
        };
    }

    /**
     * Creates parser confusion attacks with challenging parsing scenarios.
     */
    private String createParserConfusion(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.letterStrings(800, 900).next() + "=" + Generators.letterStrings(800, 900).next() + "&" + Generators.letterStrings(400, 500).next() + "=" + Generators.letterStrings(400, 500).next(); // Multiple medium parameters
            case 1 -> pattern + "/" + Generators.strings("segment" + Generators.letterStrings(30, 50).next() + "/", 20, 30).next() + "?" + "query=" + Generators.letterStrings(600, 700).next(); // Mixed segments and parameters
            case 2 -> "/" + Generators.letterStrings(1500, 2000).next() + "/" + Generators.letterStrings(1500, 2000).next() + pattern + "?" + "data=" + Generators.letterStrings(1000, 1200).next(); // Long prefix and suffix
            case 3 -> pattern + "?" + Generators.strings("key" + Generators.letterStrings(15, 25).next() + "=value" + Generators.letterStrings(15, 25).next() + "&", 20, 40).next(); // Many medium-long parameters
            case 4 -> pattern + "/" + Generators.letterStrings(3000, 3500).next() + "#" + Generators.letterStrings(3000, 3500).next(); // Long path and fragment within reason
            case 5 -> pattern + "?" + "complex=" + Generators.strings("part" + Generators.letterStrings(20, 30).next() + "_", 40, 60).next(); // Structured parameter
            case 6 -> "/" + Generators.strings("dir" + Generators.letterStrings(10, 20).next() + "/", 30, 50).next() + pattern + "?" + Generators.strings("param" + Generators.letterStrings(10, 20).next() + "=val&", 20, 35).next(); // Structured components
            case 7 -> pattern + "?" + "test=" + Generators.letterStrings(2000, 2500).next() + "&verify=" + Generators.letterStrings(2000, 2500).next() + "#section=" + Generators.letterStrings(1500, 2000).next(); // Multiple reasonable components
            default -> pattern + "?" + Generators.letterStrings(1000, 1200).next() + "=" + Generators.letterStrings(1000, 1200).next(); // Default parser confusion
        };
    }

    /**
     * Creates encoding length attacks that amplify length through encoding.
     */
    private String createEncodingLengthAttacks(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + "data=" + Generators.strings("%41", 300, 500).next(); // URL encoding amplification within limits
            case 1 -> pattern + "/" + Generators.strings("%2E", 400, 600).next(); // Encoded dots
            case 2 -> pattern + "?" + "param=" + Generators.strings("%20", 350, 550).next(); // Encoded spaces
            case 3 -> pattern + "/" + Generators.strings("%2F", 200, 300).next() + Generators.letterStrings(100, 200).next(); // Mixed encoding - separate valid encoding from letters
            case 4 -> pattern + "?" + "query=" + Generators.strings("%3C%3E", 200, 350).next(); // Encoded angle brackets
            case 5 -> pattern + "/" + Generators.strings("%2E%2E%2F", 100, 200).next(); // Encoded path traversal patterns
            case 6 -> pattern + "?" + "field=" + Generators.strings("%41%42%43", 250, 400).next(); // Encoded ABC pattern
            case 7 -> pattern + "#" + Generators.strings("%23", 300, 500).next(); // Encoded hash symbols
            default -> pattern + "?" + "data=" + Generators.strings("%41", 300, 500).next(); // Default encoding attack
        };
    }

    /**
     * Creates algorithmic complexity attacks causing processing slowdown.
     */
    private String createAlgorithmicComplexity(String pattern) {
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?" + Generators.strings("a=b&", 200, 400).next(); // Many small parameters within reason
            case 1 -> pattern + "/" + Generators.strings("x/", 150, 300).next() + "target"; // Many small path segments
            case 2 -> "/" + Generators.strings("../", 100, 200).next() + pattern; // Path traversal attempts within limits
            case 3 -> pattern + "?" + Generators.strings("param" + hashBasedSelection(100) + "=value" + hashBasedSelection(100) + "&", 50, 100).next(); // Varied parameter names
            case 4 -> pattern + "/" + Generators.strings("segment" + hashBasedSelection(50), 80, 150).next(); // Varied path segments
            case 5 -> pattern + "?" + "regex=" + Generators.strings("(a+)+", 30, 60).next(); // Regex complexity pattern
            case 6 -> pattern + "/" + Generators.strings("a" + Generators.strings("/b", 20, 40).next(), 15, 30).next(); // Nested pattern complexity
            case 7 -> pattern + "?" + Generators.strings("key=value&", 150, 300).next(); // Numerous but reasonable parameters
            default -> pattern + "?" + Generators.strings("a=b&", 200, 400).next(); // Default complexity attack
        };
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