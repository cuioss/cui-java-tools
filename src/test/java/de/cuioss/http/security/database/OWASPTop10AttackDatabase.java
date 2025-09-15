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
 * Database of OWASP Top 10 attack patterns with comprehensive vulnerability coverage.
 *
 * <p><strong>CRITICAL OWASP TOP 10 SECURITY DATABASE:</strong> This database contains proven attack vectors
 * from the OWASP Top 10 2021 list, representing the most critical web application security risks.
 * Each pattern has been validated to bypass specific security filters and represents actual
 * vulnerability exploitation techniques found in real-world applications.</p>
 *
 * <p>These patterns cover advanced encoding techniques, path traversal variants, injection attacks,
 * and authentication bypasses that are commonly used by attackers and security researchers
 * to test web application security controls.</p>
 *
 * <h3>OWASP Top 10 2021 Coverage (HTTP/URL Layer Scope)</h3>
 * <ul>
 *   <li><strong>A01: Broken Access Control</strong> - Path traversal with various encoding techniques</li>
 *   <li><strong>A06: Vulnerable Components</strong> - Framework-specific traversal attacks</li>
 *   <li><strong>A07: Authentication Failures</strong> - Directory traversal authentication bypasses</li>
 * </ul>
 *
 * <p><strong>Architectural Note:</strong> Application-layer attacks (SQL injection, XSS, Command injection, SSRF)
 * are intentionally excluded as they should be handled by application security validation, not HTTP/URL
 * security validation. This maintains proper separation of concerns between HTTP protocol security
 * and application logic security.</p>
 *
 * @since 2.5
 */
public class OWASPTop10AttackDatabase implements AttackDatabase {

    // A01: Broken Access Control - Classic Path Traversal
    public static final AttackTestCase CLASSIC_PATH_TRAVERSAL_UNIX = new AttackTestCase(
            "../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A01: Classic Unix path traversal attack attempting to access the system password file. This is the most fundamental path traversal attack using relative path navigation (..) to escape the web root directory and access sensitive system files.",
            "PATH_TRAVERSAL_DETECTED is expected because this attack uses standard directory traversal sequences (../) to navigate outside the intended directory structure and access unauthorized files."
    );

    public static final AttackTestCase CLASSIC_PATH_TRAVERSAL_WINDOWS = new AttackTestCase(
            "..\\..\\..\\windows\\win.ini",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "OWASP A01: Windows-specific path traversal using backslash separators to access the win.ini configuration file. This demonstrates cross-platform path traversal techniques targeting Windows file systems.",
            "INVALID_CHARACTER is expected because backslash characters (\\) are invalid in URL paths and rejected by character validation before traversal pattern analysis."
    );

    // A01: Encoded Path Traversal
    public static final AttackTestCase URL_ENCODED_TRAVERSAL = new AttackTestCase(
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A01: URL-encoded path traversal where directory traversal sequences are percent-encoded (%2e = '.' and %2f = '/') to bypass basic string-matching security filters that only detect literal '../' patterns.",
            "PATH_TRAVERSAL_DETECTED is expected because despite URL encoding, the decoded sequence represents standard directory traversal patterns attempting unauthorized file system access."
    );

    public static final AttackTestCase DOUBLE_ENCODED_TRAVERSAL = new AttackTestCase(
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A01: Double URL-encoded path traversal where %252e represents double-encoded dots (%2e -> %252e). This technique bypasses security filters that decode input only once, as the first decoding yields %2e which then decodes to '.' on second processing.",
            "PATH_TRAVERSAL_DETECTED is expected because after double URL decoding, the pattern resolves to standard directory traversal sequences (../../../) for accessing unauthorized files."
    );

    // A01: UTF-8 Overlong Encoding
    public static final AttackTestCase UTF8_OVERLONG_TRAVERSAL = new AttackTestCase(
            "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A01: UTF-8 overlong encoding attack using invalid UTF-8 sequences (%c0%ae for '.' and %c0%af for '/') to bypass security filters. These are overlong encodings that violate UTF-8 specifications but may be processed by vulnerable parsers.",
            "PATH_TRAVERSAL_DETECTED is expected because after processing overlong UTF-8 sequences, the pattern resolves to directory traversal sequences (../../../) for accessing system files."
    );

    // A01: Null Byte Injection
    public static final AttackTestCase NULL_BYTE_TRAVERSAL = new AttackTestCase(
            "../../../etc/passwd%00.jpg",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "OWASP A01: Null byte injection combined with path traversal, appending %00.jpg to bypass file extension restrictions. The null byte terminates string processing in vulnerable applications, effectively truncating the filename and ignoring the .jpg extension.",
            "NULL_BYTE_INJECTION is expected because the null byte sequence (%00) is detected before directory traversal pattern analysis in the validation pipeline."
    );

    // NOTE: SQL injection, XSS script tags, and Command injection patterns removed
    // as they represent application-layer security concerns that should be handled
    // by application security validation, not HTTP/URL security validation

    // A06: Vulnerable Components
    public static final AttackTestCase STRUTS2_COMPONENT_TRAVERSAL = new AttackTestCase(
            "/struts2-showcase/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A06: Path traversal attack targeting Apache Struts 2 framework installations. This exploits known vulnerabilities in specific Struts2 showcase applications to perform directory traversal and access system files outside the web application root.",
            "PATH_TRAVERSAL_DETECTED is expected because despite targeting a specific framework component, the attack mechanism uses standard directory traversal patterns to escape the intended directory structure."
    );

    // A07: Authentication Failures
    public static final AttackTestCase AUTH_BYPASS_TRAVERSAL = new AttackTestCase(
            "/admin/../user/profile",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A07: Authentication bypass attempt using path traversal to access user profiles by circumventing admin directory restrictions. This exploits path-based access controls that don't properly validate the final resolved path.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal (../) to navigate from a restricted admin directory to bypass access controls and reach unauthorized resources."
    );

    // NOTE: SSRF (Server-Side Request Forgery) patterns removed as they represent
    // application-layer logic where the application decides what external requests to make
    // HTTP/URL layer should only validate URL structure, not application request logic

    // Advanced encoding combinations
    public static final AttackTestCase MIXED_ENCODING_BYPASS = new AttackTestCase(
            "..%2F..%2f..%2Fetc%2Fpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "OWASP A01: Mixed case URL encoding bypass technique combining upper and lower case encoded forward slashes (%2F vs %2f) to evade security filters that don't properly normalize case in encoded characters.",
            "PATH_TRAVERSAL_DETECTED is expected because despite mixed case encoding, this represents a standard directory traversal attack attempting to access unauthorized system files."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            // HTTP/URL Layer Appropriate Attacks Only
            CLASSIC_PATH_TRAVERSAL_UNIX,
            CLASSIC_PATH_TRAVERSAL_WINDOWS,
            URL_ENCODED_TRAVERSAL,
            DOUBLE_ENCODED_TRAVERSAL,
            UTF8_OVERLONG_TRAVERSAL,
            NULL_BYTE_TRAVERSAL,
            STRUTS2_COMPONENT_TRAVERSAL,
            AUTH_BYPASS_TRAVERSAL,
            MIXED_ENCODING_BYPASS
    // Application-layer patterns (SQL injection, XSS script tags, Command injection, SSRF)
    // removed - these should be handled by application security validation
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "OWASP Top 10 Attack Database";
    }

    @Override
    public String getDescription() {
        return "HTTP/URL-layer OWASP Top 10 2021 attack patterns including broken access control via path traversal, vulnerable components, and authentication bypasses using URL manipulation techniques";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
     * void shouldRejectOWASPAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<OWASPTop10AttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}