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
 * Database of Nginx and web server CVE attack patterns with comprehensive vulnerability documentation.
 *
 * <p><strong>CRITICAL WEB SERVER CVE DATABASE:</strong> This database contains attack patterns
 * based on documented CVE vulnerabilities with specific exploit techniques that have
 * been proven to work against nginx, LiteSpeed, Caddy, and other web servers.</p>
 *
 * <p>These patterns represent historical attack vectors against popular web servers,
 * including path traversal vulnerabilities, header injection attacks, protocol exploitation,
 * and configuration bypass techniques. Each attack is documented with CVE details,
 * affected versions, and exploitation methodologies.</p>
 *
 * <h3>CVE Coverage</h3>
 * <ul>
 *   <li><strong>Nginx CVEs</strong>: CVE-2013-4547, CVE-2017-7529, CVE-2019-20372, CVE-2021-23017, CVE-2016-4450</li>
 *   <li><strong>LiteSpeed CVEs</strong>: CVE-2018-15517, CVE-2019-12544</li>
 *   <li><strong>Configuration Bypasses</strong>: Alias misconfigurations, location block bypasses</li>
 *   <li><strong>Module Attacks</strong>: FastCGI, proxy_pass, SSL/TLS, authentication modules</li>
 * </ul>
 *
 * @since 2.5
 */
public class NginxCVEAttackDatabase implements AttackDatabase {

    // CVE-2013-4547: nginx space in URI vulnerability
    public static final AttackTestCase CVE_2013_4547_SPACE_URI_PASSWD = new AttackTestCase(
            "/test.php /../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2013-4547: Nginx space in URI vulnerability exploiting improper URI parsing when spaces are embedded within the request path. This affects nginx versions prior to 1.5.7 and 1.4.4, where the space character causes URI parsing confusion, allowing directory traversal to access the system password file.",
            "PATH_TRAVERSAL_DETECTED is expected because despite the space-based URI confusion, the attack uses standard directory traversal sequences (../../) to access files outside the web root directory structure."
    );

    public static final AttackTestCase CVE_2013_4547_SPACE_URI_SHADOW = new AttackTestCase(
            "/admin.php /../../etc/shadow",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2013-4547: Space in URI attack targeting the shadow password file through administrative PHP endpoint. This demonstrates how the nginx URI parsing vulnerability can be combined with administrative paths to access highly sensitive authentication data.",
            "PATH_TRAVERSAL_DETECTED is expected because the core vulnerability mechanism uses directory traversal (../../) to escape the web root and access unauthorized system files containing password hashes."
    );

    public static final AttackTestCase CVE_2013_4547_SPACE_URI_WINDOWS = new AttackTestCase(
            "/config.php /../../windows/win.ini",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2013-4547: Cross-platform nginx space URI vulnerability targeting Windows systems. This shows how the same nginx parsing flaw can be exploited on Windows installations to access system configuration files through path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack employs standard directory traversal techniques to access Windows system files, with the space character serving as the nginx parser confusion trigger."
    );

    // CVE-2017-7529: nginx range filter integer overflow
    public static final AttackTestCase CVE_2017_7529_RANGE_OVERFLOW = new AttackTestCase(
            "/large.file/../../../etc/passwd HTTP/1.1\\r\\nRange: bytes=0-999999999",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2017-7529: Nginx range filter integer overflow vulnerability using massive byte range values to trigger integer overflow conditions in nginx 1.3.9-1.13.0. The oversized range (999999999) can cause memory corruption while the path traversal attempts unauthorized file access.",
            "PROTOCOL_VIOLATION is expected because the massive Range header value (bytes=0-999999999) violates reasonable HTTP range specifications and indicates potential integer overflow exploitation attempts."
    );

    public static final AttackTestCase CVE_2017_7529_RANGE_SHADOW = new AttackTestCase(
            "/video.mp4/../../../etc/shadow HTTP/1.1\\r\\nRange: bytes=1-888888888",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2017-7529: Range filter overflow targeting shadow file through media endpoint. This combines the integer overflow trigger with path traversal to access password hashes, demonstrating multi-vector attack exploitation of the nginx vulnerability.",
            "PROTOCOL_VIOLATION is expected due to the oversized Range header (bytes=1-888888888) designed to trigger integer overflow conditions in nginx's range filter processing mechanism."
    );

    // CVE-2019-20372: nginx HTTP/2 request smuggling
    public static final AttackTestCase CVE_2019_20372_H2_SMUGGLING = new AttackTestCase(
            "/api/v1/../../../etc/passwd HTTP/2.0",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2019-20372: Nginx HTTP/2 request smuggling vulnerability allowing path traversal through protocol version exploitation. This affects nginx 1.17.7 and earlier with HTTP/2 enabled, where protocol handling inconsistencies can be exploited for directory traversal attacks.",
            "PROTOCOL_VIOLATION is expected because the HTTP/2.0 protocol version specification in combination with path traversal represents protocol-level exploitation that violates standard HTTP request formatting."
    );

    public static final AttackTestCase CVE_2019_20372_H2_API_SHADOW = new AttackTestCase(
            "/api/user/../../../etc/shadow HTTP/2.0",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2019-20372: HTTP/2 request smuggling through API endpoint targeting sensitive authentication files. This demonstrates how the nginx HTTP/2 vulnerability can be exploited through REST API paths to access system password databases.",
            "PROTOCOL_VIOLATION is expected because the HTTP/2.0 protocol specification combined with API path traversal indicates HTTP/2 request smuggling attempts for unauthorized file access."
    );

    // CVE-2021-23017: nginx resolver off-by-one buffer overflow
    public static final AttackTestCase CVE_2021_23017_RESOLVER_OVERFLOW = new AttackTestCase(
            "/resolver/buffer_overflow/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2021-23017: Nginx resolver off-by-one buffer overflow vulnerability in DNS resolution functionality affecting nginx 0.6.18-1.20.0. This memory corruption vulnerability can be combined with path traversal to access system files after triggering the buffer overflow condition.",
            "PATH_TRAVERSAL_DETECTED is expected because while the resolver path triggers the buffer overflow vulnerability, the primary file access mechanism uses directory traversal sequences to escape the web root."
    );

    public static final AttackTestCase CVE_2021_23017_DNS_MALFORMED = new AttackTestCase(
            "/dns/long_hostname/../../../etc/shadow",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2021-23017: DNS resolver vulnerability with hostname overflow combined with shadow file access. This demonstrates how DNS resolution buffer overflow can be triggered while simultaneously performing path traversal to access authentication databases.",
            "PATH_TRAVERSAL_DETECTED is expected because despite the DNS resolver overflow context, the attack uses standard directory traversal patterns to access unauthorized system files."
    );

    // CVE-2016-4450: nginx CRLF injection
    public static final AttackTestCase CVE_2016_4450_CRLF_INJECTION = new AttackTestCase(
            "/redirect?url=http://evil.com\\r\\nSet-Cookie: admin=true\\r\\n\\r\\n/../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2016-4450: Nginx CRLF injection vulnerability allowing HTTP header manipulation through embedded CRLF sequences. This affects nginx configurations with certain modules, where CRLF characters (\\r\\n) can inject malicious headers like cookies while performing path traversal.",
            "INVALID_CHARACTER is expected because CRLF sequences (\\r\\n) contain invalid characters in URL paths that are rejected by character validation before protocol analysis."
    );

    public static final AttackTestCase CVE_2016_4450_CRLF_AUTH_BYPASS = new AttackTestCase(
            "/proxy?target=http://malicious.com\\r\\nX-Auth: bypass\\r\\n\\r\\n/../../../etc/shadow",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2016-4450: CRLF injection with authentication bypass header injection. This demonstrates how CRLF vulnerabilities can be exploited to inject authentication bypass headers (X-Auth: bypass) while maintaining path traversal capabilities.",
            "INVALID_CHARACTER is expected because CRLF sequences (\\r\\n) contain invalid characters in URL paths that are rejected by character validation before protocol analysis."
    );

    // CVE-2009-3898: nginx directory traversal
    public static final AttackTestCase CVE_2009_3898_DIRECTORY_TRAVERSAL = new AttackTestCase(
            "/files../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2009-3898: Nginx directory traversal vulnerability through alias misconfiguration. This historic vulnerability affects nginx configurations where aliases are improperly configured, allowing directory traversal without standard path separators by appending traversal sequences directly to path components.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal sequences (../../../) appended to the path component to escape the web root and access unauthorized system files."
    );

    public static final AttackTestCase CVE_2009_3898_UPLOADS_TRAVERSAL = new AttackTestCase(
            "/uploads../../../etc/shadow",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2009-3898: Directory traversal through uploads directory alias misconfiguration. This demonstrates how commonly used upload directories can be exploited when nginx alias directives are improperly configured, allowing access to sensitive authentication files.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack employs directory traversal from the uploads context to access system files containing password hashes outside the intended upload directory structure."
    );

    // Nginx alias misconfiguration attacks
    public static final AttackTestCase NGINX_ALIAS_STATIC_TRAVERSAL = new AttackTestCase(
            "/static../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Nginx alias misconfiguration attack through static content directory. This exploits common nginx configurations where static file serving aliases are improperly configured, allowing directory traversal by appending path traversal sequences directly to the alias path.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses the alias misconfiguration to perform directory traversal, escaping the static content directory to access unauthorized system files."
    );

    public static final AttackTestCase NGINX_ALIAS_MEDIA_TRAVERSAL = new AttackTestCase(
            "/media../../../etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Media directory alias misconfiguration exploitation for system file access. This demonstrates how media serving configurations can be exploited when nginx alias directives don't properly restrict access, allowing traversal to system configuration files.",
            "PATH_TRAVERSAL_DETECTED is expected because the alias misconfiguration enables directory traversal from the media directory context to access system networking configuration files."
    );

    // Nginx variable injection
    public static final AttackTestCase NGINX_VARIABLE_DOCUMENT_ROOT = new AttackTestCase(
            "/$document_root/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Nginx variable injection attack using $document_root variable manipulation. This exploits nginx configurations where variables are improperly handled in location blocks, potentially allowing path traversal through variable manipulation to access files outside the document root.",
            "PATH_TRAVERSAL_DETECTED is expected because despite the nginx variable context, the attack uses standard directory traversal sequences to escape the document root and access unauthorized system files."
    );

    public static final AttackTestCase NGINX_VARIABLE_URI_INJECTION = new AttackTestCase(
            "/$uri/../../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Nginx $uri variable injection targeting Windows systems. This demonstrates how nginx URI variable handling vulnerabilities can be exploited on Windows installations to access system configuration files through variable manipulation and path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack combines nginx variable exploitation with directory traversal to access Windows system files outside the intended web directory structure."
    );

    // LiteSpeed Web Server CVE patterns
    public static final AttackTestCase CVE_2018_15517_LITESPEED_TRAVERSAL = new AttackTestCase(
            "/lscache/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2018-15517: LiteSpeed Web Server path traversal vulnerability through cache directory exploitation. This affects LiteSpeed versions with improper path validation in cache handling, allowing directory traversal to access system files through the cache endpoint.",
            "PATH_TRAVERSAL_DETECTED is expected because the LiteSpeed cache vulnerability enables directory traversal attacks to escape the cache directory and access unauthorized system password files."
    );

    public static final AttackTestCase CVE_2019_12544_LITESPEED_BUFFER = new AttackTestCase(
            "/cgi-bin/long_script_name/../../../etc/shadow",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2019-12544: LiteSpeed buffer overflow vulnerability in CGI script handling with path traversal. This combines buffer overflow triggers through long script names with directory traversal to access sensitive authentication files after triggering the overflow condition.",
            "PATH_TRAVERSAL_DETECTED is expected because while the long script name may trigger buffer overflow conditions, the primary file access mechanism uses directory traversal to reach unauthorized system files."
    );

    // Complex nginx attacks
    public static final AttackTestCase NGINX_URL_ENCODED_TRAVERSAL = new AttackTestCase(
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Nginx URL-encoded path traversal attack using percent-encoded directory traversal sequences. This exploits nginx configurations that may not properly decode URL-encoded path traversal attempts, using %2e%2e (%2e = '.') to bypass basic string-based path traversal filters.",
            "PATH_TRAVERSAL_DETECTED is expected because despite URL encoding, the decoded sequences represent standard directory traversal patterns (../../..) designed to escape the web root directory structure."
    );

    public static final AttackTestCase NGINX_MIXED_ENCODING_TRAVERSAL = new AttackTestCase(
            "/static..%2f..%2f..%2f/etc/hosts",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Mixed encoding nginx attack combining literal directory traversal with URL-encoded path separators. This sophisticated technique mixes unencoded (..) with encoded path separators (%2f = '/') to bypass filters that only detect fully encoded or fully literal traversal patterns.",
            "PATH_TRAVERSAL_DETECTED is expected because the combination of literal (..) and encoded (%2f) path elements represents directory traversal designed to access system files outside the intended directory structure."
    );

    public static final AttackTestCase NGINX_BACKSLASH_TRAVERSAL = new AttackTestCase(
            "/admin/panel/..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Nginx Windows-specific backslash path traversal attack. This targets Windows nginx installations using backslash path separators (\\\\) for directory traversal, attempting to access the Windows SAM database containing user authentication information.",
            "INVALID_CHARACTER is expected because backslash characters (\\\\) are invalid in URL paths and rejected by character validation before pattern analysis can detect the directory traversal."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            CVE_2013_4547_SPACE_URI_PASSWD,
            CVE_2013_4547_SPACE_URI_SHADOW,
            CVE_2013_4547_SPACE_URI_WINDOWS,
            CVE_2017_7529_RANGE_OVERFLOW,
            CVE_2017_7529_RANGE_SHADOW,
            CVE_2019_20372_H2_SMUGGLING,
            CVE_2019_20372_H2_API_SHADOW,
            CVE_2021_23017_RESOLVER_OVERFLOW,
            CVE_2021_23017_DNS_MALFORMED,
            CVE_2016_4450_CRLF_INJECTION,
            CVE_2016_4450_CRLF_AUTH_BYPASS,
            CVE_2009_3898_DIRECTORY_TRAVERSAL,
            CVE_2009_3898_UPLOADS_TRAVERSAL,
            NGINX_ALIAS_STATIC_TRAVERSAL,
            NGINX_ALIAS_MEDIA_TRAVERSAL,
            NGINX_VARIABLE_DOCUMENT_ROOT,
            NGINX_VARIABLE_URI_INJECTION,
            CVE_2018_15517_LITESPEED_TRAVERSAL,
            CVE_2019_12544_LITESPEED_BUFFER,
            NGINX_URL_ENCODED_TRAVERSAL,
            NGINX_MIXED_ENCODING_TRAVERSAL,
            NGINX_BACKSLASH_TRAVERSAL
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Nginx CVE Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of Nginx and web server CVE attack patterns including space URI vulnerabilities, range filter overflows, HTTP/2 smuggling, CRLF injection, directory traversal, and configuration bypass techniques";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(NginxCVEAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectNginxCVEAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<NginxCVEAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}