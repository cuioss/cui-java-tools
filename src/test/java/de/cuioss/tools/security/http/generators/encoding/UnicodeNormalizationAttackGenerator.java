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
package de.cuioss.tools.security.http.generators.encoding;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

import java.text.Normalizer;

/**
 * Generates Unicode normalization attack patterns for security testing.
 * 
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 * 
 * <p>
 * This generator creates attack patterns that exploit Unicode normalization
 * vulnerabilities where different Unicode sequences can normalize to the same
 * characters, potentially bypassing security controls that don't account for
 * normalization. These attacks can be used to evade detection of malicious
 * patterns by using Unicode combining characters, lookalikes, or different
 * encodings that normalize to dangerous characters.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>Decomposed Unicode characters (NFD normalization attacks)</li>
 *   <li>Composed Unicode characters (NFC normalization issues)</li>
 *   <li>Compatibility normalization (NFKC/NFKD attacks)</li>
 *   <li>Unicode combining character sequences</li>
 *   <li>Homograph attacks using Unicode lookalikes</li>
 *   <li>Overlong UTF-8 sequences that normalize differently</li>
 *   <li>Mixed script attacks using different Unicode blocks</li>
 *   <li>Zero-width character injection</li>
 *   <li>Bidirectional text override attacks</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-176: Improper Handling of Unicode Encoding</li>
 *   <li>CWE-838: Inappropriate Encoding for Output Context</li>
 *   <li>Unicode Technical Standard #39 (Unicode Security Mechanisms)</li>
 *   <li>RFC 3454 - Preparation of Internationalized Strings</li>
 *   <li>Unicode Normalization Forms (UAX #15)</li>
 * </ul>
 * 
 * Implements: Generator for Task T8 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class UnicodeNormalizationAttackGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> basePatternTypeGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> depthGen = Generators.integers(2, 6);
    private final TypedGenerator<Integer> scriptElementGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> protocolGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> funcGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> attackTypeGen = Generators.integers(1, 9);

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int attackType = attackTypeGen.next();

        return switch (attackType) {
            case 1 -> createDecomposedNormalizationAttack(basePattern);
            case 2 -> createComposedNormalizationAttack(basePattern);
            case 3 -> createCompatibilityNormalizationAttack(basePattern);
            case 4 -> createCombiningCharacterAttack(basePattern);
            case 5 -> createHomographAttack(basePattern);
            case 6 -> createOverlongSequenceAttack(basePattern);
            case 7 -> createMixedScriptAttack(basePattern);
            case 8 -> createZeroWidthInjectionAttack(basePattern);
            case 9 -> createBidirectionalOverrideAttack(basePattern);
            default -> createComposedNormalizationAttack(basePattern);
        };
    }

    private String generateBasePattern() {
        return switch (basePatternTypeGen.next()) {
            case 1 -> generateTraversalPattern();
            case 2 -> generateScriptPattern();
            case 3 -> generateProtocolPattern();
            case 4 -> generateFunctionPattern();
            case 5 -> generateBackslashTraversalPattern();
            default -> "../";
        };
    }

    private String generateTraversalPattern() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("../");
        }
        return pattern.toString();
    }

    private String generateScriptPattern() {
        String element = switch (scriptElementGen.next()) {
            case 1 -> "script";
            case 2 -> "img";
            case 3 -> "iframe";
            case 4 -> "object";
            default -> "script";
        };
        return "<" + element + ">";
    }

    private String generateProtocolPattern() {
        String protocol = switch (protocolGen.next()) {
            case 1 -> "javascript";
            case 2 -> "data";
            case 3 -> "vbscript";
            case 4 -> "file";
            default -> "javascript";
        };
        // Ensure dangerous protocol patterns that will trigger security validation
        return protocol + "://malicious.example.com/";
    }

    private String generateFunctionPattern() {
        String func = switch (funcGen.next()) {
            case 1 -> "eval";
            case 2 -> "alert";
            case 3 -> "confirm";
            case 4 -> "setTimeout";
            default -> "eval";
        };
        // Create more aggressive function injection patterns
        return func + "(document.cookie)";
    }

    private String generateBackslashTraversalPattern() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("..\\");
        }
        return pattern.toString();
    }

    /**
     * Create attacks using Unicode decomposed normalization (NFD).
     */
    private String createDecomposedNormalizationAttack(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> {
                    // Use combining characters to create a decomposed dot
                    result.append('\u002E').append('\u0300'); // . + combining grave accent
                }
                case '/' -> {
                    // Decomposed solidus with combining character
                    result.append('\u002F').append('\u0301'); // / + combining acute accent
                }
                case '<' -> {
                    // Decomposed less-than with combining
                    result.append('\u003C').append('\u0302'); // < + combining circumflex
                }
                case '>' -> {
                    // Decomposed greater-than with combining
                    result.append('\u003E').append('\u0303'); // > + combining tilde
                }
                case '=' -> {
                    // Decomposed equals with combining
                    result.append('\u003D').append('\u0304'); // = + combining macron
                }
                default -> result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Create attacks exploiting composed normalization (NFC) issues.
     */
    private String createComposedNormalizationAttack(String pattern) {
        // Use precomposed characters that might normalize differently
        String result = pattern.replace(".", "\u1E00") // A with ring below (looks similar to dot in some fonts)
                .replace("/", "\u2044")       // Fraction slash (different from regular solidus)
                .replace("\\", "\u29F5")      // Reverse solidus operator
                .replace(":", "\uFF1A")       // Fullwidth colon
                .replace("=", "\uFF1D");      // Fullwidth equals sign
        
        // Ensure we always create an attack pattern by adding Unicode lookalikes if no substitutions were made
        if (result.equals(pattern)) {
            result = "\u2044" + pattern + "\uFF1A"; // Add fraction slash and fullwidth colon as attack markers
        }
        return result;
    }

    /**
     * Create attacks using compatibility normalization (NFKC/NFKD).
     */
    private String createCompatibilityNormalizationAttack(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> result.append('\uFF0E'); // Fullwidth full stop
                case '/' -> result.append('\uFF0F'); // Fullwidth solidus
                case '\\' -> result.append('\uFF3C'); // Fullwidth reverse solidus
                case '<' -> result.append('\uFF1C'); // Fullwidth less-than sign
                case '>' -> result.append('\uFF1E'); // Fullwidth greater-than sign
                case ':' -> result.append('\uFF1A'); // Fullwidth colon
                case '=' -> result.append('\uFF1D'); // Fullwidth equals sign
                case 'a' -> result.append('\uFF41'); // Fullwidth latin small letter a
                case 's' -> result.append('\uFF53'); // Fullwidth latin small letter s
                case 'd' -> result.append('\uFF44'); // Fullwidth latin small letter d
                case 't' -> result.append('\uFF54'); // Fullwidth latin small letter t
                default -> result.append('\uFF41'); // Convert all other chars to fullwidth 'a' for attack
            }
        }
        return result.toString();
    }

    /**
     * Create attacks using Unicode combining characters.
     */
    private String createCombiningCharacterAttack(String pattern) {
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            result.append(c);
            // Add random combining characters
            switch (c % 5) {
                case 0 -> result.append('\u0300'); // Combining grave accent
                case 1 -> result.append('\u0301'); // Combining acute accent
                case 2 -> result.append('\u0302'); // Combining circumflex accent
                case 3 -> result.append('\u0303'); // Combining tilde
                case 4 -> result.append('\u0304'); // Combining macron
            }
        }
        return result.toString();
    }

    /**
     * Create homograph attacks using lookalike characters.
     */
    private String createHomographAttack(String pattern) {
        String result = pattern.replace("a", "\u0430")     // Cyrillic small letter a (looks like Latin a)
                .replace("o", "\u043E")           // Cyrillic small letter o (looks like Latin o)
                .replace("p", "\u0440")           // Cyrillic small letter p (looks like Latin p)
                .replace("c", "\u0441")           // Cyrillic small letter c (looks like Latin c)
                .replace("e", "\u0435")           // Cyrillic small letter e (looks like Latin e)
                .replace("x", "\u0445")           // Cyrillic small letter x (looks like Latin x)
                .replace(".", "\u06D4")           // Arabic full stop (looks similar to period)
                .replace("/", "\u2215");          // Division slash (similar to solidus)
        
        // Ensure we always create an attack pattern by using Cyrillic lookalikes
        if (result.equals(pattern)) {
            result = "\u0430dmin" + pattern + "\u0440\u043E\u043E\u0442"; // Cyrillic "admin" + pattern + "root"
        }
        return result;
    }

    /**
     * Create attacks using overlong UTF-8 sequences that normalize differently.
     */
    private String createOverlongSequenceAttack(String pattern) {
        // Simulate overlong sequences by using characters that might be confused
        // during normalization or encoding conversion
        StringBuilder result = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '.' -> {
                    // Use a character that might be interpreted as dot after normalization
                    result.append('\u2024'); // One dot leader
                }
                case '/' -> {
                    // Use fraction slash which might normalize to regular slash
                    result.append('\u2044'); // Fraction slash
                }
                case '\\' -> {
                    // Use set minus which might be confused with backslash
                    result.append('\u2216'); // Set minus
                }
                default -> result.append(c);
            }
        }

        // Ensure we always create an attack by adding overlong-style characters if no substitutions
        String resultStr = result.toString();
        if (resultStr.equals(pattern)) {
            result.append('\u2024').append('\u2044'); // Add dot leader and fraction slash
        }
        return result.toString();
    }

    /**
     * Create mixed script attacks using different Unicode blocks.
     */
    private String createMixedScriptAttack(String pattern) {
        StringBuilder result = new StringBuilder();
        boolean useCyrillic = false;
        for (char c : pattern.toCharArray()) {
            if (Character.isLetter(c)) {
                if (useCyrillic) {
                    // Use Cyrillic lookalikes
                    switch (c) {
                        case 'a' -> result.append('\u0430');
                        case 'o' -> result.append('\u043E');
                        case 'p' -> result.append('\u0440');
                        case 'c' -> result.append('\u0441');
                        case 'e' -> result.append('\u0435');
                        default -> result.append(c);
                    }
                } else {
                    // Use Greek lookalikes
                    switch (c) {
                        case 'a' -> result.append('\u03B1'); // Greek alpha
                        case 'o' -> result.append('\u03BF'); // Greek omicron
                        case 'p' -> result.append('\u03C1'); // Greek rho
                        default -> result.append(c);
                    }
                }
                useCyrillic = !useCyrillic;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Create attacks using zero-width character injection.
     */
    private String createZeroWidthInjectionAttack(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Insert zero-width characters between regular characters
            switch (i % 4) {
                case 0 -> result.append('\u200B'); // Zero width space
                case 1 -> result.append('\u200C'); // Zero width non-joiner
                case 2 -> result.append('\u200D'); // Zero width joiner
                case 3 -> result.append('\uFEFF'); // Zero width no-break space
            }
        }
        return result.toString();
    }

    /**
     * Create bidirectional text override attacks.
     */
    private String createBidirectionalOverrideAttack(String pattern) {
        StringBuilder result = new StringBuilder();

        // Insert bidirectional control characters
        result.append('\u202E'); // Right-to-left override
        result.append(pattern);
        result.append('\u202C'); // Pop directional formatting
        
        // Add some additional confusion
        result.append('\u061C'); // Arabic letter mark
        result.append("config");
        result.append('\u200E'); // Left-to-right mark
        
        return result.toString();
    }

    /**
     * Get a normalized version of the pattern for comparison testing.
     */
    public String getNormalizedVersion(String input) {
        return Normalizer.normalize(input, Normalizer.Form.NFC);
    }

    /**
     * Check if two strings are equivalent after normalization.
     */
    public boolean areEquivalentAfterNormalization(String str1, String str2) {
        String normalized1 = Normalizer.normalize(str1, Normalizer.Form.NFC);
        String normalized2 = Normalizer.normalize(str2, Normalizer.Form.NFC);
        return normalized1.equals(normalized2);
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}