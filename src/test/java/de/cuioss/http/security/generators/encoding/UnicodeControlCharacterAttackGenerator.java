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
package de.cuioss.http.security.generators.encoding;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generates Unicode control character attack patterns for security testing.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * <p>
 * This generator creates attack patterns that exploit Unicode control characters
 * which can be used to bypass security filters, manipulate display, or cause
 * parsing issues. Control characters are non-printing characters that can
 * affect text processing, formatting, and security validation in unexpected ways.
 * These attacks leverage the fact that many security filters don't properly
 * handle or sanitize control characters.
 * </p>
 *
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>C0 Control Characters (0x00-0x1F) - ASCII control range</li>
 *   <li>C1 Control Characters (0x80-0x9F) - Extended ASCII control range</li>
 *   <li>Format Control Characters (Line/Paragraph separators)</li>
 *   <li>Bidirectional Control Characters (LTR/RTL overrides)</li>
 *   <li>Zero-Width Characters (ZWSP, ZWNJ, ZWJ, ZWNBSP)</li>
 *   <li>Variation Selectors and Combining Marks</li>
 *   <li>Private Use Area Characters</li>
 *   <li>Surrogate Pairs and Invalid Unicode</li>
 *   <li>Line Breaking and Whitespace Control Characters</li>
 *   <li>Control Character Injection in URLs</li>
 *   <li>Mixed Control Character Sequences</li>
 *   <li>Control Character Encoding Bypasses</li>
 * </ul>
 *
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>CWE-74: Improper Neutralization of Special Elements</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-176: Improper Handling of Unicode Encoding</li>
 *   <li>CWE-838: Inappropriate Encoding for Output Context</li>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>Unicode Technical Standard #39 (Security Mechanisms)</li>
 *   <li>RFC 3629 - UTF-8 Character Encoding</li>
 *   <li>ISO/IEC 10646 Unicode Standard</li>
 * </ul>
 *
 * Implements: Generator for Task T10 from HTTP verification specification
 *
 * @author Claude Code Generator
 * @since 2.5
 */
public class UnicodeControlCharacterAttackGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components - fully converted from fixedValues()
    private final TypedGenerator<Integer> basePatternTypeGen = Generators.integers(1, 6);
    private final TypedGenerator<Integer> attackTypeGen = Generators.integers(1, 12);
    private final TypedGenerator<Integer> traversalSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> scriptSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> protocolSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> systemSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> pathSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> commandSelector = Generators.integers(1, 4);

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int attackType = attackTypeGen.next();

        return switch (attackType) {
            case 1 -> injectC0ControlCharacters(basePattern);
            case 2 -> injectC1ControlCharacters(basePattern);
            case 3 -> injectFormatControlCharacters(basePattern);
            case 4 -> injectBidirectionalControl(basePattern);
            case 5 -> injectZeroWidthCharacters(basePattern);
            case 6 -> injectVariationSelectors(basePattern);
            case 7 -> injectPrivateUseCharacters(basePattern);
            case 8 -> injectSurrogatePairs(basePattern);
            case 9 -> injectLineBreakControl(basePattern);
            case 10 -> injectUrlControlCharacters(basePattern);
            case 11 -> injectMixedControlSequences(basePattern);
            case 12 -> injectEncodedControlBypasses(basePattern);
            default -> basePattern;
        };
    }

    private String generateBasePattern() {
        return switch (basePatternTypeGen.next()) {
            case 1 -> generateTraversalPattern();
            case 2 -> generateScriptTag();
            case 3 -> generateProtocol();
            case 4 -> generateSystemTarget();
            case 5 -> generateSystemPath();
            case 6 -> generateCommand();
            default -> generateTraversalPattern();
        };
    }

    /**
     * Inject C0 control characters (0x00-0x1F) into the pattern.
     */
    private String injectC0ControlCharacters(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Inject C0 control characters based on position
            switch (i % 8) {
                case 0 -> result.append('\u0000'); // NULL
                case 1 -> result.append('\u0001'); // SOH (Start of Heading)
                case 2 -> result.append('\u0008'); // BS (Backspace)
                case 3 -> result.append('\u0009'); // HT (Horizontal Tab)
                case 4 -> result.append('\n'); // LF (Line Feed)
                case 5 -> result.append('\r'); // CR (Carriage Return)
                case 6 -> result.append('\u001B'); // ESC (Escape)
                case 7 -> result.append('\u001F'); // US (Unit Separator)
            }
        }
        return result.toString();
    }

    /**
     * Inject C1 control characters (0x80-0x9F) into the pattern.
     */
    private String injectC1ControlCharacters(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Inject C1 control characters
            switch (i % 6) {
                case 0 -> result.append('\u0080'); // PAD (Padding Character)
                case 1 -> result.append('\u0081'); // HOP (High Octet Preset)
                case 2 -> result.append('\u008D'); // RI (Reverse Line Feed)
                case 3 -> result.append('\u0090'); // DCS (Device Control String)
                case 4 -> result.append('\u009C'); // ST (String Terminator)
                case 5 -> result.append('\u009F'); // APC (Application Program Command)
            }
        }
        return result.toString();
    }

    /**
     * Inject format control characters that affect text layout.
     */
    private String injectFormatControlCharacters(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            switch (i % 4) {
                case 0 -> result.append('\u2028'); // Line Separator
                case 1 -> result.append('\u2029'); // Paragraph Separator
                case 2 -> result.append('\u00A0'); // Non-Breaking Space
                case 3 -> result.append('\u1680'); // Ogham Space Mark
            }
        }
        return result.toString();
    }

    /**
     * Inject bidirectional text control characters.
     */
    private String injectBidirectionalControl(String pattern) {
        StringBuilder result = new StringBuilder();

        // Add bidirectional override at the beginning
        result.append('\u202E'); // Right-to-Left Override

        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Insert various BiDi control characters
            switch (i % 5) {
                case 0 -> result.append('\u202C'); // Pop Directional Formatting
                case 1 -> result.append('\u202D'); // Left-to-Right Override
                case 2 -> result.append('\u200E'); // Left-to-Right Mark
                case 3 -> result.append('\u200F'); // Right-to-Left Mark
                case 4 -> result.append('\u061C'); // Arabic Letter Mark
            }
        }

        result.append('\u202C'); // Pop Directional Formatting at the end
        return result.toString();
    }

    /**
     * Inject zero-width characters that are invisible but affect processing.
     */
    private String injectZeroWidthCharacters(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            switch (i % 5) {
                case 0 -> result.append('\u200B'); // Zero Width Space
                case 1 -> result.append('\u200C'); // Zero Width Non-Joiner
                case 2 -> result.append('\u200D'); // Zero Width Joiner
                case 3 -> result.append('\uFEFF'); // Zero Width No-Break Space (BOM)
                case 4 -> result.append('\u180E'); // Mongolian Vowel Separator
            }
        }
        return result.toString();
    }

    /**
     * Inject Unicode variation selectors and combining marks.
     */
    private String injectVariationSelectors(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            switch (i % 4) {
                case 0 -> result.append('\uFE00'); // Variation Selector-1
                case 1 -> result.append('\uFE0F'); // Variation Selector-16
                case 2 -> result.append('\u0300'); // Combining Grave Accent
                case 3 -> result.append('\u036F'); // Combining Latin Small Letter X
            }
        }
        return result.toString();
    }

    /**
     * Inject private use area characters that have undefined behavior.
     */
    private String injectPrivateUseCharacters(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            switch (i % 6) {
                case 0 -> result.append('\uE000'); // Private Use Area start
                case 1 -> result.append('\uE001'); // Private Use Area
                case 2 -> result.append('\uF8FF'); // Private Use Area (Apple logo)
                case 3 -> result.append('\uF000'); // Private Use Area
                case 4 -> result.append('\uE100'); // Private Use Area
                case 5 -> result.append('\uF900'); // CJK Compatibility Ideographs
            }
        }
        return result.toString();
    }

    /**
     * Inject invalid surrogate pairs that can cause parsing issues.
     */
    private String injectSurrogatePairs(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Inject invalid surrogate sequences
            switch (i % 3) {
                case 0 -> {
                    // Invalid high surrogate without low surrogate
                    result.append('\uD800');
                }
                case 1 -> {
                    // Invalid low surrogate without high surrogate
                    result.append('\uDC00');
                }
                case 2 -> {
                    // Invalid surrogate pair (reversed)
                    result.append('\uDC00').append('\uD800');
                }
            }
        }
        return result.toString();
    }

    /**
     * Inject line breaking and whitespace control characters.
     */
    private String injectLineBreakControl(String pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            switch (i % 7) {
                case 0 -> result.append('\n'); // Line Feed
                case 1 -> result.append('\r'); // Carriage Return
                case 2 -> result.append('\u0085'); // Next Line (NEL)
                case 3 -> result.append('\u2028'); // Line Separator
                case 4 -> result.append('\u2029'); // Paragraph Separator
                case 5 -> result.append('\u000B'); // Vertical Tab
                case 6 -> result.append('\u000C'); // Form Feed
            }
        }
        return result.toString();
    }

    /**
     * Inject control characters specifically in URL contexts.
     */
    private String injectUrlControlCharacters(String pattern) {
        StringBuilder result = new StringBuilder();

        // Add URL prefix with control characters
        result.append("http").append('\u0000').append("://");
        result.append("evil").append('\u200B').append("site.com");
        result.append('\u202E').append("/").append('\u202C');

        // Add the pattern with interspersed control characters
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            if (i % 3 == 0) {
                result.append('\u2028'); // Line Separator in URL
            }
            if (i % 4 == 0) {
                result.append('\u0000'); // Null byte in URL
            }
        }

        return result.toString();
    }

    /**
     * Inject mixed sequences of different control character types.
     */
    private String injectMixedControlSequences(String pattern) {
        StringBuilder result = new StringBuilder();

        // Start with bidirectional override
        result.append('\u202E');

        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Mix different types of control characters
            switch (i % 10) {
                case 0 -> result.append('\u0000'); // C0: NULL
                case 1 -> result.append('\u200B'); // Zero Width Space
                case 2 -> result.append('\u0080'); // C1: PAD
                case 3 -> result.append('\u2028'); // Line Separator
                case 4 -> result.append('\uFE00'); // Variation Selector
                case 5 -> result.append('\uE000'); // Private Use
                case 6 -> result.append('\u001B'); // C0: ESC
                case 7 -> result.append('\u202C'); // Pop Directional
                case 8 -> result.append('\uD800'); // Invalid Surrogate
                case 9 -> result.append('\u0300'); // Combining Grave
            }
        }

        result.append('\u202C'); // Pop Directional Formatting
        return result.toString();
    }

    /**
     * Inject URL-encoded control character bypasses.
     */
    private String injectEncodedControlBypasses(String pattern) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            result.append(c);

            // Add URL-encoded control characters
            switch (i % 8) {
                case 0 -> result.append("%00"); // Encoded NULL
                case 1 -> result.append("%01"); // Encoded SOH
                case 2 -> result.append("%08"); // Encoded BS
                case 3 -> result.append("%0A"); // Encoded LF
                case 4 -> result.append("%0D"); // Encoded CR
                case 5 -> result.append("%1B"); // Encoded ESC
                case 6 -> result.append("%7F"); // Encoded DEL
                case 7 -> result.append("%C2%80"); // UTF-8 encoded C1 control
            }
        }

        return result.toString();
    }

    /**
     * Check if a string contains control characters.
     */
    public boolean containsControlCharacters(String input) {
        if (input == null) {
            return false;
        }

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isISOControl(c) ||
                    isC1Control(c) ||
                    isFormatControl(c) ||
                    isZeroWidth(c) ||
                    isBidirectionalControl(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if character is C1 control character (0x80-0x9F).
     */
    private boolean isC1Control(char c) {
        return c >= 0x80 && c <= 0x9F;
    }

    /**
     * Check if character is format control character.
     */
    private boolean isFormatControl(char c) {
        return c == '\u2028' || c == '\u2029' || c == '\u00A0' || c == '\u1680';
    }

    /**
     * Check if character is zero-width character.
     */
    private boolean isZeroWidth(char c) {
        return c == '\u200B' || c == '\u200C' || c == '\u200D' ||
                c == '\uFEFF' || c == '\u180E';
    }

    /**
     * Check if character is bidirectional control character.
     */
    private boolean isBidirectionalControl(char c) {
        return c == '\u202C' || c == '\u202D' || c == '\u202E' ||
                c == '\u200E' || c == '\u200F' || c == '\u061C';
    }

    // QI-6: Dynamic generation helper methods
    private String generateTraversalPattern() {
        return switch (traversalSelector.next()) {
            case 1 -> "../";
            case 2 -> "..\\";
            case 3 -> "../../";
            case 4 -> "../../../";
            default -> "../";
        };
    }

    private String generateScriptTag() {
        return switch (scriptSelector.next()) {
            case 1 -> "<script>";
            case 2 -> "<iframe>";
            case 3 -> "<img>";
            case 4 -> "<svg>";
            default -> "<script>";
        };
    }

    private String generateProtocol() {
        return switch (protocolSelector.next()) {
            case 1 -> "javascript:";
            case 2 -> "data:";
            case 3 -> "file:";
            case 4 -> "vbscript:";
            default -> "javascript:";
        };
    }

    private String generateSystemTarget() {
        return switch (systemSelector.next()) {
            case 1 -> "admin";
            case 2 -> "root";
            case 3 -> "config";
            case 4 -> "system";
            default -> "admin";
        };
    }

    private String generateSystemPath() {
        return switch (pathSelector.next()) {
            case 1 -> "/etc/passwd";
            case 2 -> "/windows/system32";
            case 3 -> "/proc/self";
            case 4 -> "/var/log";
            default -> "/etc/passwd";
        };
    }

    private String generateCommand() {
        return switch (commandSelector.next()) {
            case 1 -> "cmd.exe";
            case 2 -> "shell";
            case 3 -> "bash";
            case 4 -> "powershell";
            default -> "cmd.exe";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}