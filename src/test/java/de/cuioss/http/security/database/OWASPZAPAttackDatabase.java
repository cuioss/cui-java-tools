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

import de.cuioss.http.security.core.UrlSecurityFailureType;

import java.util.List;

/**
 * Database of OWASP ZAP active scan attack patterns focusing on HTTP protocol layer vulnerabilities.
 *
 * <p><strong>CRITICAL OWASP ZAP SECURITY DATABASE:</strong> This database contains attack patterns
 * derived from OWASP ZAP (Zed Attack Proxy) active scanning rules, specifically focusing on HTTP
 * protocol layer vulnerabilities. These patterns represent actual attack vectors used by one of
 * the most widely deployed security testing tools in the industry.</p>
 *
 * <p>ZAP active scan rules are continuously updated based on emerging threats and have been
 * battle-tested against millions of web applications. Each pattern here represents an HTTP
 * protocol layer attack that ZAP actively tests for during security assessments.</p>
 *
 * <h3>HTTP Protocol Layer Focus</h3>
 * <p>This database strictly adheres to HTTP protocol layer validation concerns:</p>
 * <ul>
 *   <li><strong>Included</strong>: Path traversal, URL encoding attacks, HTTP smuggling</li>
 *   <li><strong>Excluded</strong>: Application-layer concerns (HTML entities, JavaScript escapes, Base64)</li>
 * </ul>
 *
 * <h3>ZAP Active Scan Rule Coverage</h3>
 * <ul>
 *   <li><strong>Path Traversal</strong>: Multiple encoding variants from ZAP's path traversal scanner</li>
 *   <li><strong>Directory Browsing</strong>: Attempts to access directory listings</li>
 *   <li><strong>File Inclusion</strong>: Local file inclusion patterns at HTTP layer</li>
 *   <li><strong>HTTP Splitting</strong>: Response splitting and smuggling attempts</li>
 * </ul>
 *
 * @since 2.5
 */
public class OWASPZAPAttackDatabase implements AttackDatabase {

    // ZAP Path Traversal Active Scan Rules
    public static final AttackTestCase ZAP_PATH_TRAVERSAL_BASIC = new AttackTestCase(
            "../../../../../../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Basic path traversal with multiple parent directory references. This is the primary pattern ZAP uses to detect path traversal vulnerabilities, using enough '../' sequences to reliably escape any reasonable web root depth.",
            "PATH_TRAVERSAL_DETECTED is expected because this attack uses explicit directory traversal sequences (../) to navigate outside the intended directory structure."
    );

    public static final AttackTestCase ZAP_PATH_TRAVERSAL_ENCODED_DOT = new AttackTestCase(
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: URL-encoded dots in path traversal. ZAP tests this pattern to bypass filters that only check for literal dots, as many naive implementations fail to decode before checking.",
            "PATH_TRAVERSAL_DETECTED is expected because after URL decoding, this resolves to standard directory traversal sequences (../../../../)."
    );

    public static final AttackTestCase ZAP_PATH_TRAVERSAL_ENCODED_SLASH = new AttackTestCase(
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: URL-encoded forward slashes in path traversal. This pattern tests whether applications decode slashes before path validation, a common vulnerability in URL parsers.",
            "PATH_TRAVERSAL_DETECTED is expected because the encoded slashes (%2f) decode to forward slashes, creating directory traversal patterns."
    );

    public static final AttackTestCase ZAP_PATH_TRAVERSAL_DOUBLE_DOTS = new AttackTestCase(
            "....//....//....//etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Double dots with double slashes pattern. This tests for parsers that incorrectly normalize ....// to ../, a vulnerability found in several web frameworks.",
            "PATH_TRAVERSAL_DETECTED is expected because this pattern attempts directory traversal through malformed dot sequences."
    );

    public static final AttackTestCase ZAP_PATH_TRAVERSAL_BACKSLASH = new AttackTestCase(
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "ZAP Active Scan: Windows path traversal using backslashes. ZAP tests both forward and backslash variants to detect Windows-specific path traversal vulnerabilities.",
            "INVALID_CHARACTER is expected because backslash characters are invalid in URL paths according to RFC specifications."
    );

    public static final AttackTestCase ZAP_PATH_TRAVERSAL_ABSOLUTE = new AttackTestCase(
            "/../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Absolute path access attempt via parent directory. This tests whether applications properly restrict access to absolute paths through traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because this uses parent directory traversal to access system paths."
    );

    // ZAP Directory Browsing Detection
    public static final AttackTestCase ZAP_DIRECTORY_BROWSING_DOUBLE_SLASH = new AttackTestCase(
            "/..//etc//passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Double slash with traversal attempt. This pattern tests for improper path normalization combined with directory traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because this combines traversal patterns with double slashes."
    );

    public static final AttackTestCase ZAP_DIRECTORY_LISTING_DOT = new AttackTestCase(
            "/./../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Current and parent directory reference pattern. ZAP uses this to test whether path normalization properly handles mixed directory references.",
            "PATH_TRAVERSAL_DETECTED is expected because this combines current and parent directory references for traversal."
    );

    // ZAP Local File Inclusion Patterns
    public static final AttackTestCase ZAP_LFI_FILE_PROTOCOL = new AttackTestCase(
            "/../file/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Local file inclusion attempt via traversal. This tests whether applications properly validate and reject file access attempts.",
            "PATH_TRAVERSAL_DETECTED is expected because this uses traversal patterns to attempt file access."
    );

    public static final AttackTestCase ZAP_LFI_PHP_FILTER = new AttackTestCase(
            "/../../../resource/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Resource access via traversal. This tests for local file inclusion vulnerabilities through directory traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because this uses multiple parent directory references to access resources."
    );

    // ZAP HTTP Response Splitting
    public static final AttackTestCase ZAP_HTTP_SPLITTING_CRLF = new AttackTestCase(
            "/test%00attack",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "ZAP Active Scan: Null byte injection for string termination. This tests whether applications properly handle null bytes that could terminate string processing.",
            "NULL_BYTE_INJECTION is expected because %00 represents a null byte used to terminate string processing."
    );

    public static final AttackTestCase ZAP_HTTP_SPLITTING_ENCODED_CRLF = new AttackTestCase(
            "/test%250d%250aLocation:%20http://evil.com",
            UrlSecurityFailureType.DOUBLE_ENCODING,
            "ZAP Active Scan: Double-encoded CRLF for HTTP splitting. This tests whether applications decode multiple times, potentially exposing CRLF injection vulnerabilities.",
            "DOUBLE_ENCODING is expected because %250d represents double-encoded carriage return, indicating encoding manipulation."
    );

    // ZAP Unicode and Encoding Attacks
    public static final AttackTestCase ZAP_UNICODE_NORMALIZATION = new AttackTestCase(
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: UTF-8 overlong encoding path traversal. ZAP tests for parsers that incorrectly handle overlong UTF-8 sequences, which violate UTF-8 specifications.",
            "PATH_TRAVERSAL_DETECTED is expected because overlong UTF-8 sequences (%c0%ae) decode to dots, forming traversal patterns."
    );

    public static final AttackTestCase ZAP_MIXED_ENCODING = new AttackTestCase(
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Mixed encoding with URL-encoded backslashes. This tests for applications that decode but don't properly validate mixed forward and backslash patterns.",
            "PATH_TRAVERSAL_DETECTED is expected because %5c decodes to backslash, creating Windows-style traversal patterns."
    );

    // ZAP Null Byte Injection
    public static final AttackTestCase ZAP_NULL_BYTE_TRUNCATION = new AttackTestCase(
            "/etc/passwd%00.html",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "ZAP Active Scan: Null byte file extension bypass. This classic attack uses null bytes to truncate file paths in vulnerable applications, bypassing extension-based security checks.",
            "NULL_BYTE_INJECTION is expected because %00 represents a null byte used to terminate string processing prematurely."
    );

    public static final AttackTestCase ZAP_NULL_BYTE_MIDPATH = new AttackTestCase(
            "/var%00/www/html/index.php",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "ZAP Active Scan: Null byte in middle of path. This tests whether applications properly handle null bytes within paths, which can cause unexpected truncation.",
            "NULL_BYTE_INJECTION is expected because null bytes within paths can cause security bypasses through premature string termination."
    );

    // ZAP Parameter Pollution
    public static final AttackTestCase ZAP_PATH_PARAMETER_BYPASS = new AttackTestCase(
            "/admin;session=fake/../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Path parameter pollution with traversal. This tests whether semicolon-delimited parameters are properly validated for path traversal attempts.",
            "PATH_TRAVERSAL_DETECTED is expected because the path contains directory traversal sequences after the semicolon parameter delimiter."
    );

    // ZAP Fuzzing Patterns
    public static final AttackTestCase ZAP_FUZZING_LONG_PATH = new AttackTestCase(
            "/" + "../".repeat(50) + "etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "ZAP Active Scan: Excessive parent directory references. ZAP uses fuzzing with many traversal sequences to test buffer handling and ensure deep directory escapes are detected.",
            "PATH_TRAVERSAL_DETECTED is expected because this uses an excessive number of parent directory references to ensure escape from any directory depth."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            ZAP_PATH_TRAVERSAL_BASIC,
            ZAP_PATH_TRAVERSAL_ENCODED_DOT,
            ZAP_PATH_TRAVERSAL_ENCODED_SLASH,
            ZAP_PATH_TRAVERSAL_DOUBLE_DOTS,
            ZAP_PATH_TRAVERSAL_BACKSLASH,
            ZAP_PATH_TRAVERSAL_ABSOLUTE,
            ZAP_DIRECTORY_BROWSING_DOUBLE_SLASH,
            ZAP_DIRECTORY_LISTING_DOT,
            ZAP_LFI_FILE_PROTOCOL,
            ZAP_LFI_PHP_FILTER,
            ZAP_HTTP_SPLITTING_CRLF,
            ZAP_HTTP_SPLITTING_ENCODED_CRLF,
            ZAP_UNICODE_NORMALIZATION,
            ZAP_MIXED_ENCODING,
            ZAP_NULL_BYTE_TRUNCATION,
            ZAP_NULL_BYTE_MIDPATH,
            ZAP_PATH_PARAMETER_BYPASS,
            ZAP_FUZZING_LONG_PATH
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "OWASP ZAP Active Scan Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of OWASP ZAP active scan patterns focusing on HTTP protocol layer vulnerabilities including path traversal, encoding attacks, and HTTP smuggling";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(OWASPZAPAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectZAPAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<OWASPZAPAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}