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
package de.cuioss.http.security.database;

import java.util.List;

/**
 * Database of legitimate special character patterns that must be accepted by the validation system.
 *
 * <p><strong>FALSE POSITIVE PREVENTION - T32:</strong> This database contains legitimate
 * URL patterns with special characters that represent valid business use cases. These patterns
 * ensure the security validation correctly handles various character sets and encodings without
 * triggering false positives.</p>
 *
 * <h3>Coverage Areas</h3>
 * <ul>
 *   <li><strong>RFC 3986 Unreserved</strong> - Characters explicitly allowed by RFC 3986</li>
 *   <li><strong>Encoded Reserved</strong> - Properly encoded reserved characters</li>
 *   <li><strong>International Characters</strong> - UTF-8 encoded international text</li>
 *   <li><strong>Mathematical/Scientific</strong> - Technical notation characters</li>
 *   <li><strong>Business Identifiers</strong> - Common business naming patterns</li>
 * </ul>
 *
 * @since 2.5
 */
public class LegitimateSpecialCharactersDatabase implements LegitimatePatternDatabase {

    // RFC 3986 Unreserved Characters
    public static final LegitimateTestCase HYPHEN_UNDERSCORE = new LegitimateTestCase(
            "/api/user-profile_v2",
            "Path with hyphens and underscores (RFC 3986 unreserved)",
            "Hyphens and underscores are explicitly allowed as unreserved characters in RFC 3986"
    );

    public static final LegitimateTestCase TILDE_PATH = new LegitimateTestCase(
            "/~username/public",
            "Unix-style user directory with tilde",
            "Tilde is an unreserved character commonly used for user directories"
    );

    public static final LegitimateTestCase DOT_NOTATION = new LegitimateTestCase(
            "/api/v2.1/users",
            "Version number with dot notation",
            "Dots are unreserved characters commonly used in version numbers"
    );

    // Properly Encoded Reserved Characters
    public static final LegitimateTestCase ENCODED_PLUS = new LegitimateTestCase(
            "/search/c%2B%2B",
            "Search for 'C++' with encoded plus signs",
            "Plus signs must be encoded as %2B in paths, representing legitimate search terms"
    );

    public static final LegitimateTestCase ENCODED_AMPERSAND = new LegitimateTestCase(
            "/companies/johnson%26johnson",
            "Company name with encoded ampersand",
            "Ampersands in company names must be encoded as %26"
    );

    public static final LegitimateTestCase ENCODED_EQUALS = new LegitimateTestCase(
            "/formula/e%3Dmc2",
            "Scientific formula with encoded equals sign",
            "Equals signs in paths must be encoded as %3D for formulas and equations"
    );

    // International Characters (UTF-8 Encoded)
    public static final LegitimateTestCase FRENCH_ACCENTS = new LegitimateTestCase(
            "/ville/montr%C3%A9al",
            "French city name 'Montréal' with encoded accent",
            "UTF-8 encoded accented characters (%C3%A9 for é) are legitimate for internationalization"
    );

    public static final LegitimateTestCase GERMAN_UMLAUT = new LegitimateTestCase(
            "/stadt/m%C3%BCnchen",
            "German city name 'München' with encoded umlaut",
            "UTF-8 encoded umlauts (%C3%BC for ü) are required for German language support"
    );

    public static final LegitimateTestCase SPANISH_TILDE = new LegitimateTestCase(
            "/año/2024",
            "Spanish word 'año' (year) with encoded ñ",
            "Spanish ñ character properly encoded for language support"
    );

    public static final LegitimateTestCase JAPANESE_HIRAGANA = new LegitimateTestCase(
            "/search/%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF",
            "Japanese 'こんにちは' (hello) in UTF-8 encoding",
            "Japanese characters must be UTF-8 encoded and accepted for CJK support"
    );

    // Mathematical and Scientific Notation
    public static final LegitimateTestCase MATH_OPERATORS = new LegitimateTestCase(
            "/calc/5%2B3%2A2",
            "Mathematical expression '5+3*2' with encoded operators",
            "Mathematical operators properly encoded for calculator applications"
    );

    public static final LegitimateTestCase CHEMICAL_FORMULA = new LegitimateTestCase(
            "/molecule/H2O",
            "Chemical formula with numbers",
            "Chemical formulas with mixed alphanumeric characters are legitimate"
    );

    public static final LegitimateTestCase COORDINATES = new LegitimateTestCase(
            "/location/40.7128,-74.0060",
            "GPS coordinates with comma and negative sign",
            "Geographic coordinates with decimal points and negative signs are valid"
    );

    // Business and Technical Identifiers
    public static final LegitimateTestCase EMAIL_LIKE_ID = new LegitimateTestCase(
            "/user/john.doe%40example.com",
            "User identifier resembling email format",
            "Email-like identifiers with encoded @ symbol (%40) are common in REST APIs"
    );

    public static final LegitimateTestCase PHONE_NUMBER = new LegitimateTestCase(
            "/contact/%2B1-555-123-4567",
            "International phone number with encoded plus",
            "Phone numbers with country codes require encoded plus signs"
    );

    public static final LegitimateTestCase SKU_WITH_SLASH = new LegitimateTestCase(
            "/product/ABC%2F123%2FXL",
            "Product SKU 'ABC/123/XL' with encoded slashes",
            "SKUs often contain slashes that must be encoded as %2F"
    );

    // Currency and Financial
    public static final LegitimateTestCase CURRENCY_SYMBOL = new LegitimateTestCase(
            "/price/%2410.99",
            "Price with encoded dollar sign",
            "Currency symbols like $ must be encoded as %24 in paths"
    );

    public static final LegitimateTestCase PERCENTAGE = new LegitimateTestCase(
            "/discount/25%25off",
            "Discount '25%off' with encoded percent sign",
            "Percent signs must be encoded as %25 to avoid confusion with encoding"
    );

    // Special Formatting
    public static final LegitimateTestCase PARENTHESES = new LegitimateTestCase(
            "/section/(draft)",
            "Section marked as draft with parentheses",
            "Parentheses are valid in paths for annotations and grouping"
    );

    public static final LegitimateTestCase ENCODED_BRACKETS = new LegitimateTestCase(
            "/array/items%5B0%5D",
            "Array notation with encoded brackets",
            "Square brackets must be encoded as %5B and %5D in URL paths"
    );

    private static final List<LegitimateTestCase> ALL_LEGITIMATE_TEST_CASES = List.of(
            HYPHEN_UNDERSCORE,
            TILDE_PATH,
            DOT_NOTATION,
            ENCODED_PLUS,
            ENCODED_AMPERSAND,
            ENCODED_EQUALS,
            FRENCH_ACCENTS,
            GERMAN_UMLAUT,
            SPANISH_TILDE,
            JAPANESE_HIRAGANA,
            MATH_OPERATORS,
            CHEMICAL_FORMULA,
            COORDINATES,
            EMAIL_LIKE_ID,
            PHONE_NUMBER,
            SKU_WITH_SLASH,
            CURRENCY_SYMBOL,
            PERCENTAGE,
            PARENTHESES,
            ENCODED_BRACKETS
    );

    @Override
    public Iterable<LegitimateTestCase> getLegitimateTestCases() {
        return ALL_LEGITIMATE_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Legitimate Special Characters Database (T32)";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of legitimate special character patterns including RFC 3986 characters, international text, scientific notation, and business identifiers";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing.
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends LegitimatePatternDatabase.ArgumentsProvider<LegitimateSpecialCharactersDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}