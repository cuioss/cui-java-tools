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
 * Test for {@link InvalidURLGenerator}
 */
class InvalidURLGeneratorTest {

    private final InvalidURLGenerator generator = new InvalidURLGenerator();

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
        for (int i = 0; i < 300; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (many different malformed patterns)
        assertTrue(generatedValues.size() >= 25,
                "Generator should produce varied malformed URL patterns, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateProtocolIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test protocol issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for protocol-related malformations
        boolean hasMalformedProtocol = generated.stream().anyMatch(s -> s.contains("htp://"));
        boolean hasMissingProtocol = generated.stream().anyMatch(s -> s.startsWith("://"));
        boolean hasSingleSlash = generated.stream().anyMatch(s -> s.contains("http:/example"));
        boolean hasTripleSlash = generated.stream().anyMatch(s -> s.contains("http:///"));

        assertTrue(hasMalformedProtocol, "Should generate malformed protocol patterns");
        assertTrue(hasMissingProtocol, "Should generate missing protocol patterns");
        assertTrue(hasSingleSlash, "Should generate single slash protocol patterns");
        assertTrue(hasTripleSlash, "Should generate triple slash protocol patterns");
    }

    @Test
    void shouldGenerateHostIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test host issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for host-related malformations
        boolean hasEmptyHost = generated.stream().anyMatch(s -> "http://".equals(s));
        boolean hasSpaceInHost = generated.stream().anyMatch(s -> s.contains("exam ple.com"));
        boolean hasDoubleDots = generated.stream().anyMatch(s -> s.contains("example..com"));
        boolean hasLeadingDot = generated.stream().anyMatch(s -> s.contains("//.example.com"));

        assertTrue(hasEmptyHost, "Should generate empty host patterns");
        assertTrue(hasSpaceInHost, "Should generate space in hostname patterns");
        assertTrue(hasDoubleDots, "Should generate double dots in hostname patterns");
        assertTrue(hasLeadingDot, "Should generate leading dot in hostname patterns");
    }

    @Test
    void shouldGeneratePathIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test path issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for path-related malformations
        boolean hasDoubleSlashes = generated.stream().anyMatch(s -> s.contains("//path"));

        assertTrue(hasDoubleSlashes, "Should generate double slash path patterns");
    }

    @Test
    void shouldGenerateQueryParameterIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test query parameter issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for query parameter malformations
        boolean hasEmptyQuery = generated.stream().anyMatch(s -> s.endsWith("?"));
        boolean hasMissingParamName = generated.stream().anyMatch(s -> s.contains("?=value"));
        boolean hasMissingParamValue = generated.stream().anyMatch(s -> s.contains("param=") && !s.contains("param=val"));
        boolean hasTrailingAmpersand = generated.stream().anyMatch(s -> s.contains("&") && s.endsWith("&"));

        assertTrue(hasEmptyQuery, "Should generate empty query patterns");
        assertTrue(hasMissingParamName, "Should generate missing parameter name patterns");
        assertTrue(hasMissingParamValue, "Should generate missing parameter value patterns");
        assertTrue(hasTrailingAmpersand, "Should generate trailing ampersand patterns");
    }

    @Test
    void shouldGenerateFragmentIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test fragment issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for fragment-related malformations
        boolean hasEmptyFragment = generated.stream().anyMatch(s -> s.endsWith("#"));
        boolean hasDoubleHash = generated.stream().anyMatch(s -> s.contains("##"));

        assertTrue(hasEmptyFragment, "Should generate empty fragment patterns");
        assertTrue(hasDoubleHash, "Should generate double hash patterns");
    }

    @Test
    void shouldGeneratePortIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test port issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for port-related malformations
        boolean hasEmptyPort = generated.stream().anyMatch(s -> s.contains("://"));
        boolean hasInvalidPort = generated.stream().anyMatch(s -> s.contains(":99999/"));
        boolean hasNonNumericPort = generated.stream().anyMatch(s -> s.contains(":abc/"));
        boolean hasNegativePort = generated.stream().anyMatch(s -> s.contains(":-80/"));

        assertTrue(hasEmptyPort, "Should generate empty port patterns");
        assertTrue(hasInvalidPort, "Should generate invalid port number patterns");
        assertTrue(hasNonNumericPort, "Should generate non-numeric port patterns");
        assertTrue(hasNegativePort, "Should generate negative port patterns");
    }

    @Test
    void shouldGenerateSpecialCharacterIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test special character issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for special character malformations
        boolean hasUncodedSpaces = generated.stream().anyMatch(s -> s.contains("path with spaces"));
        boolean hasUncodedBrackets = generated.stream().anyMatch(s -> s.contains("[bracket]"));
        boolean hasUncodedBraces = generated.stream().anyMatch(s -> s.contains("{brace}"));
        boolean hasUncodedPipe = generated.stream().anyMatch(s -> s.contains("path|pipe"));
        boolean hasBackslashes = generated.stream().anyMatch(s -> s.contains("\\"));

        assertTrue(hasUncodedSpaces, "Should generate unencoded space patterns");
        assertTrue(hasUncodedBrackets, "Should generate unencoded bracket patterns");
        assertTrue(hasUncodedBraces, "Should generate unencoded brace patterns");
        assertTrue(hasUncodedPipe, "Should generate unencoded pipe patterns");
        assertTrue(hasBackslashes, "Should generate backslash patterns");
    }

    @Test
    void shouldGenerateEncodingIssues() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test encoding issues
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for encoding malformations
        boolean hasIncompleteEncoding = generated.stream().anyMatch(s -> s.contains("path%") && !s.contains("path%2"));
        boolean hasInvalidHex = generated.stream().anyMatch(s -> s.contains("%ZZ") || s.contains("%GG"));

        assertTrue(hasIncompleteEncoding, "Should generate incomplete percent encoding patterns");
        assertTrue(hasInvalidHex, "Should generate invalid hex encoding patterns");
    }

    @Test
    void shouldGenerateLengthIssues() {
        // Test that some generated URLs are extremely long
        boolean hasLongUrl = false;

        for (int i = 0; i < 100; i++) {
            String generated = generator.next();
            if (generated.length() > 5000) {
                hasLongUrl = true;
                break;
            }
        }

        assertTrue(hasLongUrl, "Should generate some extremely long URL patterns");
    }

    @Test
    void shouldGenerateNonUrlFormats() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test non-URL formats
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for non-URL patterns
        boolean hasEmptyString = generated.stream().anyMatch(String::isEmpty);
        boolean hasWhitespaceOnly = generated.stream().anyMatch(s -> s.trim().isEmpty() && !s.isEmpty());
        boolean hasNonUrlText = generated.stream().anyMatch(s -> "not-a-url-at-all".equals(s));

        assertTrue(hasEmptyString, "Should generate empty string patterns");
        assertTrue(hasWhitespaceOnly, "Should generate whitespace-only patterns");
        assertTrue(hasNonUrlText, "Should generate non-URL text patterns");
    }

    @Test
    void shouldGenerateSecurityRiskyPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test security-risky formats
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for potentially dangerous patterns
        boolean hasJavaScriptProtocol = generated.stream().anyMatch(s -> s.startsWith("javascript:"));
        boolean hasDataUrl = generated.stream().anyMatch(s -> s.startsWith("data:"));
        boolean hasFileProtocol = generated.stream().anyMatch(s -> s.startsWith("file://"));
        boolean hasFtpProtocol = generated.stream().anyMatch(s -> s.startsWith("ftp://"));

        assertTrue(hasJavaScriptProtocol, "Should generate JavaScript protocol patterns");
        assertTrue(hasDataUrl, "Should generate data URL patterns");
        assertTrue(hasFileProtocol, "Should generate file protocol patterns");
        assertTrue(hasFtpProtocol, "Should generate FTP protocol patterns");
    }

    @Test
    void shouldGenerateCombinedMalformations() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test combined malformations
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for combined malformation patterns
        boolean hasCombinedIssues = generated.stream().anyMatch(s ->
                s.contains("..") && s.contains("//") && s.contains("??"));
        boolean hasAdditionalMalformation = generated.stream().anyMatch(s ->
                s.contains("%invalid%encoding"));

        assertTrue(hasCombinedIssues, "Should generate patterns with multiple combined issues");
        assertTrue(hasAdditionalMalformation, "Should generate patterns with additional malformations");
    }

    @Test
    void shouldGenerateReasonableVariety() {
        Set<String> generated = new HashSet<>();

        // Generate a large set to test overall variety
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have patterns from different categories
        boolean hasProtocolIssues = generated.stream().anyMatch(s -> s.startsWith("htp://") || s.startsWith("://"));
        boolean hasHostIssues = generated.stream().anyMatch(s -> s.contains("..com") || s.contains("exam ple"));
        boolean hasEncodingIssues = generated.stream().anyMatch(s -> s.contains("path%") || s.contains("%ZZ"));
        boolean hasSpecialChars = generated.stream().anyMatch(s -> s.matches(".*[\\[\\]{}|\\\\].*"));

        assertTrue(hasProtocolIssues, "Should generate protocol issue patterns");
        assertTrue(hasHostIssues, "Should generate host issue patterns");
        assertTrue(hasEncodingIssues, "Should generate encoding issue patterns");
        assertTrue(hasSpecialChars, "Should generate special character issue patterns");

        // Should generate reasonable variety
        assertTrue(generated.size() >= 30, "Should generate reasonable variety of malformed URLs");
    }
}