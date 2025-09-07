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

/**
 * Generates HTML entity encoding attack patterns for security testing.
 * 
 * <p>
 * This generator creates attack patterns that use HTML entity encoding
 * to bypass security controls that might not properly decode HTML entities
 * before validation. HTML entity encoding can be used to obfuscate malicious
 * payloads and evade pattern-based detection.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>Named HTML entities (&lt;, &gt;, &quot;, &amp;, &#x27;)</li>
 *   <li>Decimal numeric entities (&#46; for '.', &#47; for '/')</li>
 *   <li>Hexadecimal numeric entities (&#x2E; for '.', &#x2F; for '/')</li>
 *   <li>Mixed case variants (&#X2E; vs &#x2e;)</li>
 *   <li>Leading zeros in numeric entities (&#00046; for '.')</li>
 *   <li>Malformed entities for robustness testing</li>
 *   <li>Nested entity encoding (&amp;lt; for &lt;)</li>
 *   <li>Path traversal patterns with HTML entity encoding</li>
 *   <li>XSS payloads with HTML entity obfuscation</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-79: Cross-site Scripting (XSS)</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>HTML5 Character Reference Standards</li>
 *   <li>W3C HTML Entity Specification</li>
 * </ul>
 * 
 * Implements: Generator for Task T7 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class HtmlEntityEncodingAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> basePatternGen = Generators.fixedValues(
            "../",
            "..\\",
            "../../",
            "../../../",
            "<script>",
            "</script>",
            "<img src=x>",
            "javascript:",
            "data:",
            "on",  // For event handlers like onclick
            "\"",
            "'",
            "&",
            "<",
            ">",
            "/",
            "\\",
            "."
    );

    private final TypedGenerator<String> encodingTypeGen = Generators.fixedValues(
            "named_entities",           // Standard named HTML entities
            "decimal_numeric",          // Decimal numeric entities  
            "hex_numeric",              // Hexadecimal numeric entities
            "hex_mixed_case",           // Mixed case hex entities
            "leading_zeros",            // Numeric entities with leading zeros
            "malformed_entities",       // Malformed entities for robustness
            "nested_entities",          // Nested entity encoding
            "path_traversal_entities",  // Path traversal with entities
            "xss_entities"              // XSS payloads with entity encoding
    );

    @Override
    public String next() {
        String basePattern = basePatternGen.next();
        String encodingType = encodingTypeGen.next();

        return switch (encodingType) {
            case "named_entities" -> applyNamedEntities(basePattern);
            case "decimal_numeric" -> applyDecimalNumericEntities(basePattern);
            case "hex_numeric" -> applyHexNumericEntities(basePattern);
            case "hex_mixed_case" -> applyMixedCaseHexEntities(basePattern);
            case "leading_zeros" -> applyLeadingZeroEntities(basePattern);
            case "malformed_entities" -> applyMalformedEntities(basePattern);
            case "nested_entities" -> applyNestedEntities(basePattern);
            case "path_traversal_entities" -> createPathTraversalWithEntities();
            case "xss_entities" -> createXssWithEntities();
            default -> basePattern;
        };
    }

    /**
     * Apply standard named HTML entities.
     */
    private String applyNamedEntities(String pattern) {
        return pattern.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("&", "&amp;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * Apply decimal numeric HTML entities.
     */
    private String applyDecimalNumericEntities(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> result.append("&#46;");
                case '/' -> result.append("&#47;");
                case '\\' -> result.append("&#92;");
                case '<' -> result.append("&#60;");
                case '>' -> result.append("&#62;");
                case '"' -> result.append("&#34;");
                case '\'' -> result.append("&#39;");
                case '&' -> result.append("&#38;");
                case ':' -> result.append("&#58;");
                case '=' -> result.append("&#61;");
                case '(' -> result.append("&#40;");
                case ')' -> result.append("&#41;");
                default -> result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Apply hexadecimal numeric HTML entities.
     */
    private String applyHexNumericEntities(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> result.append("&#x2E;");
                case '/' -> result.append("&#x2F;");
                case '\\' -> result.append("&#x5C;");
                case '<' -> result.append("&#x3C;");
                case '>' -> result.append("&#x3E;");
                case '"' -> result.append("&#x22;");
                case '\'' -> result.append("&#x27;");
                case '&' -> result.append("&#x26;");
                case ':' -> result.append("&#x3A;");
                case '=' -> result.append("&#x3D;");
                case '(' -> result.append("&#x28;");
                case ')' -> result.append("&#x29;");
                default -> result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Apply mixed case hexadecimal entities.
     */
    private String applyMixedCaseHexEntities(String pattern) {
        StringBuilder result = new StringBuilder();
        boolean upperCase = false;
        for (char c : pattern.toCharArray()) {
            String hex = switch (c) {
                case '.' -> upperCase ? "&#X2E;" : "&#x2e;";
                case '/' -> upperCase ? "&#X2F;" : "&#x2f;";
                case '\\' -> upperCase ? "&#X5C;" : "&#x5c;";
                case '<' -> upperCase ? "&#X3C;" : "&#x3c;";
                case '>' -> upperCase ? "&#X3E;" : "&#x3e;";
                default -> String.valueOf(c);
            };
            result.append(hex);
            upperCase = !upperCase; // Toggle case for variety
        }
        return result.toString();
    }

    /**
     * Apply numeric entities with leading zeros.
     */
    private String applyLeadingZeroEntities(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> result.append("&#00046;");
                case '/' -> result.append("&#00047;");
                case '\\' -> result.append("&#00092;");
                case '<' -> result.append("&#00060;");
                case '>' -> result.append("&#00062;");
                case '"' -> result.append("&#00034;");
                case '\'' -> result.append("&#00039;");
                default -> result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Apply malformed entities for robustness testing.
     */
    private String applyMalformedEntities(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> result.append("&#46"); // Missing semicolon
                case '/' -> result.append("&#x2F"); // Missing semicolon
                case '<' -> result.append("&#x3C;extra"); // Extra content
                case '>' -> result.append("&#999;"); // Invalid numeric value
                case '"' -> result.append("&#x;"); // Missing hex digits
                case '&' -> result.append("&invalid;"); // Invalid entity name
                default -> result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Apply nested entity encoding.
     */
    private String applyNestedEntities(String pattern) {
        // First pass: encode & as &amp;
        String firstPass = pattern.replace("&", "&amp;");
        // Second pass: encode < and > as entities, creating nested encoding
        return firstPass.replace("<", "&amp;lt;").replace(">", "&amp;gt;");
    }

    /**
     * Create path traversal attacks with HTML entities.
     */
    private String createPathTraversalWithEntities() {
        String[] pathTraversalPatterns = {
                "&#46;&#46;&#47;",                    // ../
                "&#x2E;&#x2E;&#x2F;",                // ../
                "&#46;&#46;&#92;",                   // ..\
                "&#46;&#46;&#47;&#46;&#46;&#47;",    // ../../
                "&#x2E;&#x2E;&#x5C;",                // ..\
                "&amp;#46;&amp;#46;&amp;#47;",      // Nested encoding
                "&#00046;&#00046;&#00047;",          // With leading zeros
        };
        return pathTraversalPatterns[pathTraversalPatterns.length % pathTraversalPatterns.length];
    }

    /**
     * Create XSS attacks with HTML entity encoding.
     */
    private String createXssWithEntities() {
        String[] xssPatterns = {
                "&lt;script&gt;alert&#40;1&#41;&lt;&#47;script&gt;",
                "&lt;img src&#61;x onerror&#61;alert&#40;1&#41;&gt;",
                "javascript&#58;alert&#40;1&#41;",
                "&lt;svg onload&#61;alert&#40;1&#41;&gt;",
                "&quot;&gt;&lt;script&gt;alert&#40;document.cookie&#41;&lt;&#47;script&gt;",
                "&lt;iframe src&#61;javascript&#58;alert&#40;1&#41;&gt;",
                "&#39;&gt;&lt;script&gt;alert&#40;String.fromCharCode&#40;88,83,83&#41;&#41;&lt;&#47;script&gt;",
                "&lt;body onload&#61;&quot;alert&#40;&#39;XSS&#39;&#41;&quot;&gt;"
        };
        return xssPatterns[xssPatterns.length % xssPatterns.length];
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}