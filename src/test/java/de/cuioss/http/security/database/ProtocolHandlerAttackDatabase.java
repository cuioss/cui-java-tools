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
 * Database of protocol handler attack patterns with comprehensive URI scheme security coverage.
 *
 * <p><strong>CRITICAL PROTOCOL SECURITY DATABASE:</strong> This database contains protocol
 * handler attack patterns designed to test security validation against protocol-based attacks
 * including custom protocol exploitation, protocol confusion attacks, scheme manipulation,
 * and handler bypass attempts.</p>
 *
 * <p>These attacks exploit the complexity of URI parsing, protocol handler registration,
 * browser security policies, and application-level protocol validation to bypass security
 * controls and execute malicious actions through protocol manipulation.</p>
 *
 * <h3>Protocol Attack Categories</h3>
 * <ul>
 *   <li><strong>JS Protocol Injection</strong> - Script execution through javascript: URLs</li>
 *   <li><strong>Data URI Exploitation</strong> - Malicious content via data: scheme</li>
 *   <li><strong>File Protocol Access</strong> - Local file system access via file: URLs</li>
 *   <li><strong>Custom Protocol Schemes</strong> - Malicious custom protocol handlers</li>
 *   <li><strong>Protocol Confusion</strong> - Mixing different protocol contexts</li>
 *   <li><strong>Malformed Protocols</strong> - Invalid protocol syntax exploitation</li>
 *   <li><strong>Encoding Attacks</strong> - URL-encoded protocol manipulation</li>
 * </ul>
 *
 * <h3>Security Standards</h3>
 * <ul>
 *   <li><strong>RFC 3986</strong> - URI Generic Syntax specification</li>
 *   <li><strong>RFC 2397</strong> - data: URL scheme specification</li>
 *   <li><strong>CWE-79</strong> - Cross-site Scripting via protocol injection</li>
 *   <li><strong>CWE-88</strong> - Improper Neutralization of Script in Attributes</li>
 *   <li><strong>CWE-73</strong> - External Control of File Name or Path</li>
 * </ul>
 *
 * @since 2.5
 */
public class ProtocolHandlerAttackDatabase implements AttackDatabase {

    // JS Protocol Injection Attacks
    public static final AttackTestCase JAVASCRIPT_ALERT_BASIC = new AttackTestCase(
            "javascript:alert('XSS')/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "JS protocol injection using basic test() function to test XSS vulnerability detection. The javascript: URI scheme allows execution of arbitrary JS code, combined with path traversal to demonstrate multi-vector attack capabilities.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the javascript: protocol contains script execution code (alert function) designed to execute cross-site scripting attacks in browser contexts."
    );

    public static final AttackTestCase JAVASCRIPT_ENCODED_EVAL = new AttackTestCase(
            "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))/admin",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Advanced JS protocol attack using eval() with String.fromCharCode() encoding to obfuscate XSS payload. This technique bypasses simple string-based XSS filters by encoding the test('XSS') call as character codes (97=a, 108=l, etc.).",
            "SUSPICIOUS_PATTERN_DETECTED is expected because despite character code obfuscation, the javascript: protocol contains eval() function calls designed to execute dynamically constructed malicious scripts."
    );

    public static final AttackTestCase JAVASCRIPT_LOCATION_REDIRECT = new AttackTestCase(
            "javascript:window.location='http://evil.com'/../../config",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "JS protocol attack using window.location manipulation to perform malicious redirects. This exploits client-side navigation controls to redirect users to attacker-controlled domains while maintaining path traversal capabilities for server-side exploitation.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the javascript: protocol contains client-side script code (window.location) designed to manipulate browser navigation and perform unauthorized redirects."
    );

    public static final AttackTestCase JAVASCRIPT_FETCH_EXFILTRATION = new AttackTestCase(
            "javascript:fetch('/../../etc/passwd').then(r=>r.text()).then(console.log)",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Sophisticated JS protocol attack using fetch() API for data exfiltration. This modern attack technique combines path traversal with JS fetch API to read sensitive files and exfiltrate data through console output or network requests.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the javascript: protocol contains complex script execution (fetch API calls) designed to read and exfiltrate sensitive data through client-side JS execution."
    );

    // Data URI Exploitation Attacks
    public static final AttackTestCase DATA_URI_HTML_SCRIPT = new AttackTestCase(
            "data:text/html,<script>alert('XSS')</script>/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Data URI attack embedding HTML with JS in data: scheme. This exploits the data: protocol to inject malicious HTML containing scripts directly into the URL, bypassing traditional XSS filters that don't examine data URI contents.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the data: URI contains embedded HTML with script tags designed to execute cross-site scripting attacks through inline content injection."
    );

    public static final AttackTestCase DATA_URI_BASE64_SCRIPT = new AttackTestCase(
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=/../etc/hosts",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Base64-encoded data URI attack containing XSS payload. The base64 string 'PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=' decodes to '<script>test('XSS')</script>', demonstrating how data URIs can obfuscate malicious content through encoding.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because despite base64 encoding, the data: URI contains encoded script content designed to execute cross-site scripting when decoded and processed by browsers."
    );

    public static final AttackTestCase DATA_URI_SVG_SCRIPT = new AttackTestCase(
            "data:image/svg+xml,<svg><script>alert('XSS')</script></svg>/../../sensitive",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "SVG data URI attack embedding JavaScript within SVG content. This exploits the ability of SVG images to contain executable script content, using the data: scheme to inject malicious SVG documents that execute JavaScript when processed.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the SVG data URI contains embedded script elements within the SVG markup, enabling cross-site scripting through image content manipulation."
    );

    // File Protocol Access Attacks
    public static final AttackTestCase FILE_PROTOCOL_UNIX_PASSWD = new AttackTestCase(
            "file:///../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "File protocol attack for local file system access to Unix password file. The file: scheme allows direct access to local file system resources, combined with directory traversal to access sensitive system files outside intended boundaries.",
            "PATH_TRAVERSAL_DETECTED is expected because the file: protocol uses directory traversal sequences (../../../) to navigate the local file system and access unauthorized files outside the application's intended directory scope."
    );

    public static final AttackTestCase FILE_PROTOCOL_LOCALHOST = new AttackTestCase(
            "file://localhost/../../../etc/shadow",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "File protocol attack with explicit localhost specification targeting shadow password file. This demonstrates how file: URLs can specify hosts (including localhost) while performing directory traversal to access highly sensitive authentication data.",
            "PATH_TRAVERSAL_DETECTED is expected because despite the localhost specification, the file: protocol employs directory traversal to access system files containing password hashes outside the intended file access boundaries."
    );

    public static final AttackTestCase FILE_PROTOCOL_WINDOWS = new AttackTestCase(
            "file:///c:/../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "File protocol attack targeting Windows systems using drive letter specification. This demonstrates cross-platform file: protocol exploitation targeting Windows system files through directory traversal from the C: drive root.",
            "PATH_TRAVERSAL_DETECTED is expected because the file: protocol uses Windows-specific path traversal (../../) to access system configuration files outside the intended directory structure on Windows systems."
    );

    // Custom Protocol Schemes
    public static final AttackTestCase CUSTOM_PROTOCOL_MALWARE = new AttackTestCase(
            "malware://evil.com/../../admin/config",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Custom protocol attack using 'malware:' scheme to test protocol handler validation. Custom protocols can be registered by applications or malware to handle specific URI schemes, potentially bypassing security controls that only validate standard protocols.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because non-standard protocol schemes like 'malware:' indicate potential custom protocol exploitation attempts that may bypass standard URL validation mechanisms."
    );

    public static final AttackTestCase CUSTOM_PROTOCOL_EXPLOIT = new AttackTestCase(
            "exploit://attacker.com/../etc/hosts",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Exploit-themed custom protocol scheme targeting system hosts file. This tests whether applications properly validate and restrict custom protocol handlers that might be registered to execute malicious actions when invoked.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because security-themed protocol schemes like 'exploit:' represent suspicious custom protocols that may be used to invoke malicious protocol handlers or bypass security validation."
    );

    // Protocol Confusion Attacks
    public static final AttackTestCase PROTOCOL_CONFUSION_HTTP_JS = new AttackTestCase(
            "http://javascript:alert('XSS')@evil.com/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Protocol confusion attack embedding javascript: within HTTP URL authority section. This exploits URL parsing inconsistencies where embedded protocols in the authority section might be processed differently by various parsers, potentially executing the embedded JavaScript.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because despite the HTTP protocol context, the embedded javascript: scheme contains script execution code that may be processed as executable content by vulnerable parsers."
    );

    public static final AttackTestCase PROTOCOL_CONFUSION_HTTPS_DATA = new AttackTestCase(
            "https://data:text/html,<script>@evil.com/../../config",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "HTTPS protocol confusion with embedded data: URI in authority section. This tests parser handling when data URIs containing malicious content are embedded within the authority component of HTTPS URLs, potentially causing execution of embedded scripts.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the embedded data: URI contains HTML script content that may be processed as executable content despite being within the HTTPS URL authority section."
    );

    // Malformed Protocol Schemes
    public static final AttackTestCase MALFORMED_HTTP_SPACE = new AttackTestCase(
            "ht tp://evil.com/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Malformed HTTP protocol with embedded space character. This tests URL parser robustness against malformed protocol schemes that might bypass protocol-based security filters while still being processed by lenient parsers.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the malformed protocol scheme 'ht tp:' with embedded space represents invalid URL syntax that may be used to bypass protocol validation mechanisms."
    );

    public static final AttackTestCase MALFORMED_TRIPLE_SLASH = new AttackTestCase(
            "http:///evil.com/../../admin/config",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Malformed HTTP protocol with triple slash separator. This tests parser handling of invalid protocol syntax where extra slashes might cause parsing confusion or bypass validation that expects standard double-slash format (://).",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the malformed protocol syntax 'http:///' with triple slashes violates standard URI syntax and may indicate attempts to exploit URL parser inconsistencies."
    );

    // Protocol with Special Characters
    public static final AttackTestCase PROTOCOL_NULL_BYTE = new AttackTestCase(
            "http\u0000://evil.com/../../admin/config",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "HTTP protocol with embedded null byte character. This exploits null byte injection vulnerabilities in URL parsing where null characters might terminate string processing in vulnerable parsers, potentially bypassing security validation.",
            "NULL_BYTE_INJECTION is expected because the embedded null character (\\u0000) in the protocol scheme represents null byte injection designed to terminate string processing and bypass URL validation mechanisms."
    );

    public static final AttackTestCase PROTOCOL_CONTROL_CHAR = new AttackTestCase(
            "http\n://attacker.com/../etc/hosts",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "HTTP protocol with embedded newline control character. This tests parser handling of control characters within protocol schemes that might cause parsing errors, security bypass, or unexpected behavior in URL processing.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because control characters (newline) embedded in protocol schemes violate URL syntax standards and may be used to exploit parser vulnerabilities or bypass validation."
    );

    // Double Protocol Schemes
    public static final AttackTestCase DOUBLE_HTTP_PROTOCOL = new AttackTestCase(
            "http://http://evil.com/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Double HTTP protocol scheme attack testing parser confusion with nested protocol specifications. This exploits URL parsing ambiguities where nested protocols might cause parsers to process the URL differently than intended.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because nested protocol schemes 'http://http://' represent malformed URL syntax that may be used to confuse parsers and bypass protocol-based security validation."
    );

    public static final AttackTestCase DOUBLE_JAVASCRIPT_PROTOCOL = new AttackTestCase(
            "javascript://javascript:alert('XSS')/../../sensitive",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Nested JavaScript protocol attack with double javascript: specification. This tests whether XSS filters properly handle nested JavaScript protocols that might be processed recursively or bypass single-layer protocol detection.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because despite nesting, the URL contains JavaScript protocol schemes with script execution code (alert function) designed to execute cross-site scripting attacks."
    );

    // Protocol Encoding Attacks
    public static final AttackTestCase URL_ENCODED_HTTP_PROTOCOL = new AttackTestCase(
            "%68%74%74%70://evil.com/../../../etc/passwd",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "URL-encoded HTTP protocol scheme bypass using percent-encoding. The encoded string '%68%74%74%70' decodes to 'http', potentially bypassing protocol filters that only check for literal protocol strings without decoding.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because URL-encoded protocol schemes (%68%74%74%70) may indicate attempts to bypass protocol validation through encoding obfuscation techniques."
    );

    public static final AttackTestCase URL_ENCODED_JAVASCRIPT = new AttackTestCase(
            "%6a%61%76%61%73%63%72%69%70%74:alert('XSS')/../admin",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "URL-encoded JavaScript protocol attack using percent-encoding to obfuscate the javascript: scheme. This bypasses XSS filters that detect literal 'javascript:' strings but don't properly decode URL-encoded protocol specifications.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because the URL-encoded protocol (%6a%61%76%61%73%63%72%69%70%74) decodes to 'javascript:' containing script execution code designed to perform cross-site scripting attacks."
    );

    // Protocol with Authentication Bypass
    public static final AttackTestCase HTTP_AUTH_BYPASS = new AttackTestCase(
            "http://admin:password@evil.com/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "HTTP protocol with embedded authentication credentials in URL authority. This tests whether applications properly validate URLs containing authentication information that might bypass access controls or reveal credentials in logs and referrers.",
            "PATH_TRAVERSAL_DETECTED is expected because despite the authentication context, the primary attack mechanism uses directory traversal (../../../) to access files outside the intended directory structure."
    );

    public static final AttackTestCase MALFORMED_AUTH_ENCODING = new AttackTestCase(
            "http://:%40@evil.com/../../sensitive",
            UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED,
            "Malformed authentication with URL-encoded @ symbol (%40) in userinfo section. This exploits URL parsing edge cases where encoded characters in the authority section might cause parsing confusion or bypass validation.",
            "SUSPICIOUS_PATTERN_DETECTED is expected because malformed authentication syntax with encoded characters (:%40) represents suspicious URL manipulation that may be used to exploit parser vulnerabilities."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            JAVASCRIPT_ALERT_BASIC,
            JAVASCRIPT_ENCODED_EVAL,
            JAVASCRIPT_LOCATION_REDIRECT,
            JAVASCRIPT_FETCH_EXFILTRATION,
            DATA_URI_HTML_SCRIPT,
            DATA_URI_BASE64_SCRIPT,
            DATA_URI_SVG_SCRIPT,
            FILE_PROTOCOL_UNIX_PASSWD,
            FILE_PROTOCOL_LOCALHOST,
            FILE_PROTOCOL_WINDOWS,
            CUSTOM_PROTOCOL_MALWARE,
            CUSTOM_PROTOCOL_EXPLOIT,
            PROTOCOL_CONFUSION_HTTP_JS,
            PROTOCOL_CONFUSION_HTTPS_DATA,
            MALFORMED_HTTP_SPACE,
            MALFORMED_TRIPLE_SLASH,
            PROTOCOL_NULL_BYTE,
            PROTOCOL_CONTROL_CHAR,
            DOUBLE_HTTP_PROTOCOL,
            DOUBLE_JAVASCRIPT_PROTOCOL,
            URL_ENCODED_HTTP_PROTOCOL,
            URL_ENCODED_JAVASCRIPT,
            HTTP_AUTH_BYPASS,
            MALFORMED_AUTH_ENCODING
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Protocol Handler Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of protocol handler attack patterns including JavaScript injection, data URI exploitation, file protocol access, custom schemes, protocol confusion, malformed protocols, and encoding attacks";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(ProtocolHandlerAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectProtocolHandlerAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<ProtocolHandlerAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}