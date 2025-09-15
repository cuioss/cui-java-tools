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
 * Database of edge case valid URLs that must be accepted despite being unusual.
 *
 * <p><strong>FALSE POSITIVE PREVENTION - T33:</strong> This database contains edge case
 * URL patterns that are technically valid according to RFC specifications but might appear
 * suspicious or unusual. These patterns ensure the security validation correctly handles
 * uncommon but legitimate URL constructs.</p>
 *
 * <h3>Coverage Areas</h3>
 * <ul>
 *   <li><strong>RFC Edge Cases</strong> - Valid but unusual RFC 3986 constructs</li>
 *   <li><strong>Empty Components</strong> - Valid URLs with empty path segments</li>
 *   <li><strong>Repetitive Patterns</strong> - Legitimate repeated characters</li>
 *   <li><strong>Length Extremes</strong> - Very short or long valid paths</li>
 *   <li><strong>Special Schemes</strong> - Non-HTTP URL patterns</li>
 * </ul>
 *
 * @since 2.5
 */
public class EdgeCaseValidURLsDatabase implements LegitimatePatternDatabase {

    // Single Character and Minimal Paths
    public static final LegitimateTestCase SINGLE_CHAR_PATH = new LegitimateTestCase(
            "/a",
            "Single character path segment",
            "Single character paths are valid and used for minimalist APIs"
    );

    public static final LegitimateTestCase ROOT_ONLY = new LegitimateTestCase(
            "/",
            "Root path only",
            "The root path '/' is the most basic valid path"
    );

    public static final LegitimateTestCase SINGLE_DOT_SEGMENT = new LegitimateTestCase(
            "/.",
            "Path ending with single dot",
            "Single dot at end of path is valid though unusual"
    );

    // Multiple Consecutive Slashes (normalized differently by servers)
    public static final LegitimateTestCase DOUBLE_SLASH_MIDDLE = new LegitimateTestCase(
            "/api//v1/users",
            "Path with double slash in middle",
            "Some servers normalize double slashes, but they're technically valid in paths"
    );

    public static final LegitimateTestCase TRAILING_SLASH = new LegitimateTestCase(
            "/api/users/",
            "Path with trailing slash",
            "Trailing slashes are valid and often have semantic meaning in REST APIs"
    );

    // Repetitive but Valid Patterns
    public static final LegitimateTestCase REPEATED_SEGMENTS = new LegitimateTestCase(
            "/data/data/data",
            "Path with repeated identical segments",
            "Repeated path segments might indicate poor design but are technically valid"
    );

    public static final LegitimateTestCase MANY_DOTS = new LegitimateTestCase(
            "/file.backup.old.2024.tar.gz",
            "Filename with multiple dots",
            "Multiple dots in filenames are valid for compound extensions"
    );

    public static final LegitimateTestCase CONSECUTIVE_HYPHENS = new LegitimateTestCase(
            "/my---special---page",
            "Path with multiple consecutive hyphens",
            "Multiple hyphens are valid though unusual in URL paths"
    );

    // Very Long but Valid Components
    public static final LegitimateTestCase LONG_SEGMENT = new LegitimateTestCase(
            "/verylongpathsegmentthatexceedsnormalexpectationsbutisvalid",
            "Single very long path segment (60+ characters)",
            "Long path segments are valid as long as total URL length is within limits"
    );

    public static final LegitimateTestCase DEEP_NESTING = new LegitimateTestCase(
            "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p",
            "Deeply nested path with 16 levels",
            "Deep nesting is valid for complex hierarchical structures"
    );

    // Mixed Case Patterns
    public static final LegitimateTestCase CAMEL_CASE = new LegitimateTestCase(
            "/getUserProfileById",
            "CamelCase method-style path",
            "CamelCase paths are valid and used in some RPC-style APIs"
    );

    public static final LegitimateTestCase MIXED_CASE = new LegitimateTestCase(
            "/Api/V2/Users",
            "Mixed case with capital letters",
            "Mixed case paths are valid though not recommended for REST"
    );

    // Numeric Edge Cases
    public static final LegitimateTestCase ALL_NUMERIC = new LegitimateTestCase(
            "/123456789",
            "Path consisting only of numbers",
            "Purely numeric paths are valid for ID-based routing"
    );

    public static final LegitimateTestCase LEADING_ZEROS = new LegitimateTestCase(
            "/item/000123",
            "Numeric ID with leading zeros",
            "Leading zeros in IDs are valid for fixed-width identifiers"
    );

    public static final LegitimateTestCase NEGATIVE_NUMBER = new LegitimateTestCase(
            "/balance/-100",
            "Path with negative number",
            "Negative numbers are valid in paths for signed values"
    );

    // Special Valid Constructs
    public static final LegitimateTestCase EMPTY_SEGMENT = new LegitimateTestCase(
            "/before//after",
            "Path with empty segment between slashes",
            "Empty segments are technically valid though often normalized away"
    );

    public static final LegitimateTestCase PERCENT_ENCODED_SLASH = new LegitimateTestCase(
            "/path%2Fwith%2Fencoded%2Fslashes",
            "Path with percent-encoded slashes",
            "Encoded slashes (%2F) are valid when slashes are data, not separators"
    );

    public static final LegitimateTestCase SEMICOLON_PARAMS = new LegitimateTestCase(
            "/path;param=value",
            "Path with semicolon parameters (matrix parameters)",
            "Semicolon parameters are valid per RFC 3986 for matrix parameters"
    );

    // RFC-Compliant but Unusual
    public static final LegitimateTestCase COLON_IN_PATH = new LegitimateTestCase(
            "/time/12:30:00",
            "Time value with colons in path",
            "Colons are valid in path segments for time representations"
    );

    public static final LegitimateTestCase COMMA_SEPARATED = new LegitimateTestCase(
            "/items/1,2,3,4,5",
            "Comma-separated list in path",
            "Commas are valid for representing lists in path segments"
    );

    private static final List<LegitimateTestCase> ALL_LEGITIMATE_TEST_CASES = List.of(
            SINGLE_CHAR_PATH,
            ROOT_ONLY,
            SINGLE_DOT_SEGMENT,
            DOUBLE_SLASH_MIDDLE,
            TRAILING_SLASH,
            REPEATED_SEGMENTS,
            MANY_DOTS,
            CONSECUTIVE_HYPHENS,
            LONG_SEGMENT,
            DEEP_NESTING,
            CAMEL_CASE,
            MIXED_CASE,
            ALL_NUMERIC,
            LEADING_ZEROS,
            NEGATIVE_NUMBER,
            EMPTY_SEGMENT,
            PERCENT_ENCODED_SLASH,
            SEMICOLON_PARAMS,
            COLON_IN_PATH,
            COMMA_SEPARATED
    );

    @Override
    public Iterable<LegitimateTestCase> getLegitimateTestCases() {
        return ALL_LEGITIMATE_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Edge Case Valid URLs Database (T33)";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of edge case URL patterns that are technically valid but unusual, including RFC edge cases, repetitive patterns, and length extremes";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing.
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends LegitimatePatternDatabase.ArgumentsProvider<EdgeCaseValidURLsDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}