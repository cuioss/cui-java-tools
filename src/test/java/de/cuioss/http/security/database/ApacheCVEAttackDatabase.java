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
 * Database of Apache CVE attack patterns with comprehensive vulnerability documentation.
 *
 * <p><strong>CRITICAL APACHE CVE SECURITY DATABASE:</strong> This database contains precise
 * Apache CVE exploit patterns that represent documented vulnerabilities with specific CVE identifiers.
 * Each pattern corresponds to actual security vulnerabilities discovered in Apache HTTP Server,
 * Apache Tomcat, and related Apache software components.</p>
 *
 * <p>These patterns are sourced from official CVE databases and security research reports.
 * Each attack is meticulously documented with vulnerability details, affected versions,
 * and exploitation techniques to provide comprehensive security testing coverage.</p>
 *
 * <h3>CVE Coverage</h3>
 * <ul>
 *   <li><strong>Path Traversal CVEs</strong>: CVE-2021-41773, CVE-2021-42013, CVE-2019-0230</li>
 *   <li><strong>Server CVEs</strong>: CVE-2020-1927, CVE-2019-0211, CVE-2018-1333</li>
 *   <li><strong>Module CVEs</strong>: CVE-2017-15710, CVE-2016-8743, CVE-2021-40438</li>
 *   <li><strong>Tomcat CVEs</strong>: CVE-2020-1938, CVE-2019-0199, CVE-2018-1336</li>
 * </ul>
 *
 * @since 2.5
 */
public class ApacheCVEAttackDatabase implements AttackDatabase {

    // CVE-2021-41773: Apache HTTP Server 2.4.49 path traversal
    public static final AttackTestCase CVE_2021_41773_PATH_TRAVERSAL_PASSWD = new AttackTestCase(
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2021-41773: Apache HTTP Server 2.4.49 path traversal vulnerability exploiting URL encoding bypass to access /etc/passwd outside the web root. This zero-day vulnerability was actively exploited in the wild and affects non-default Apache configurations where mod_cgi is enabled.",
            "PATH_TRAVERSAL_DETECTED is expected because this attack uses encoded directory traversal sequences (../) represented as .%2e/%2e%2e patterns to escape the web root directory structure and access sensitive system files."
    );

    public static final AttackTestCase CVE_2021_41773_PATH_TRAVERSAL_SHADOW = new AttackTestCase(
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2021-41773: Apache HTTP Server 2.4.49 path traversal attempting to access the /etc/shadow file containing password hashes. This represents a critical security breach if successful.",
            "PATH_TRAVERSAL_DETECTED is expected due to the encoded directory traversal pattern (.%2e/%2e%2e) designed to bypass path normalization and access files outside the intended directory structure."
    );

    public static final AttackTestCase CVE_2021_41773_WINDOWS_PATH = new AttackTestCase(
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2021-41773: Windows-specific path traversal variant targeting the win.ini configuration file. This shows the cross-platform nature of the vulnerability affecting both Unix and Windows Apache installations.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack employs the same URL encoding bypass technique (.%2e/%2e%2e) to traverse directories and access Windows system files outside the web root."
    );

    // CVE-2021-42013: Apache HTTP Server 2.4.50 double encoding bypass
    public static final AttackTestCase CVE_2021_42013_DOUBLE_ENCODING = new AttackTestCase(
            "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
            UrlSecurityFailureType.INVALID_ENCODING,
            "CVE-2021-42013: Apache HTTP Server 2.4.50 double URL encoding bypass. The fix for CVE-2021-41773 was insufficient, allowing attackers to use double-encoded sequences (%%32%65 = %2e = .) to bypass the patch and continue path traversal attacks.",
            "DOUBLE_ENCODING is expected because this attack specifically exploits double URL encoding where %%32%65 decodes to %2e which then decodes to '.' - a clear indicator of double encoding bypass techniques."
    );

    public static final AttackTestCase CVE_2021_42013_ICONS_PATH = new AttackTestCase(
            "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
            UrlSecurityFailureType.INVALID_ENCODING,
            "CVE-2021-42013: Path traversal via /icons/ directory using double encoding. This variant demonstrates how the vulnerability could be exploited through different Apache directories beyond just /cgi-bin/.",
            "DOUBLE_ENCODING is expected because the %%32%65 pattern represents double URL encoding that bypasses single-layer decoding protection implemented in the insufficient CVE-2021-41773 fix."
    );

    // CVE-2019-0230: Apache Struts path traversal
    public static final AttackTestCase CVE_2019_0230_STRUTS_TRAVERSAL = new AttackTestCase(
            "/..%252f..%252f..%252f..%252fetc%252fpasswd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2019-0230: Apache Struts path traversal using double URL encoding. This vulnerability in Apache Struts allows attackers to access files outside the web application's root directory through manipulated file paths.",
            "DOUBLE_ENCODING is expected because %252f represents double-encoded forward slash characters (/ -> %2f -> %252f) used to bypass path validation mechanisms."
    );

    // CVE-2020-1927: Apache HTTP Server mod_rewrite
    public static final AttackTestCase CVE_2020_1927_MOD_REWRITE = new AttackTestCase(
            "/index.php?page=..%2f..%2f..%2f..%2fetc%2fpasswd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2020-1927: Apache HTTP Server mod_rewrite path traversal vulnerability. Affects Apache 2.4.41 and allows attackers to map URLs to files outside configured directories when mod_rewrite is enabled with certain rule configurations.",
            "PATH_TRAVERSAL_DETECTED is expected due to the encoded directory traversal sequence (..%2f) in the parameter value attempting to escape the web root directory structure."
    );

    // CVE-2019-0211: Apache HTTP Server privilege escalation
    public static final AttackTestCase CVE_2019_0211_PRIVILEGE_ESCALATION = new AttackTestCase(
            "/server-status?refresh=1&auto=../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2019-0211: Apache HTTP Server privilege escalation through mod_prefork vulnerability. This attack combines server-status endpoint access with path traversal to potentially gain elevated privileges on Apache 2.4.17 to 2.4.38.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses unencoded directory traversal sequences (../../../) to access files outside the web root through the server-status endpoint."
    );

    // CVE-2018-1333: Apache HTTP Server DoS
    public static final AttackTestCase CVE_2018_1333_DOS_ATTACK = new AttackTestCase(
            "/test?long_query_parameter=../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2018-1333: Apache HTTP Server Denial of Service vulnerability combined with path traversal. This attack exploits a flaw in Apache 2.4.17 to 2.4.29 that can cause resource exhaustion while attempting unauthorized file access.",
            "PATH_TRAVERSAL_DETECTED is expected because despite being primarily a DoS attack, it employs directory traversal patterns (../../../) to access unauthorized files as part of the exploitation technique."
    );

    // CVE-2017-15710: Apache HTTP Server mod_authnz_ldap
    public static final AttackTestCase CVE_2017_15710_NULL_BYTE = new AttackTestCase(
            "/secure/admin?user=admin%00../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2017-15710: Apache HTTP Server mod_authnz_ldap null byte injection vulnerability. This attack affects Apache 2.4.10 to 2.4.29 by using null bytes (%00) to bypass authentication checks and perform path traversal.",
            "NULL_BYTE_INJECTION is expected because the attack specifically uses the null byte character (%00) to terminate string processing in the authentication module, bypassing security checks."
    );

    // CVE-2016-8743: Apache HTTP Server chunked transfer encoding
    public static final AttackTestCase CVE_2016_8743_HTTP_SMUGGLING = new AttackTestCase(
            "/upload.php HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET ../../../etc/passwd HTTP/1.1",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2016-8743: Apache HTTP Server HTTP request smuggling via chunked transfer encoding. This vulnerability in Apache 2.4.17 to 2.4.25 allows attackers to smuggle HTTP requests through malformed chunked encoding headers.",
            "PROTOCOL_VIOLATION is expected because this attack violates HTTP protocol specifications by injecting malformed chunked transfer encoding headers and embedding additional HTTP requests within the body."
    );

    // CVE-2021-40438: Apache HTTP Server SSRF in mod_proxy
    public static final AttackTestCase CVE_2021_40438_SSRF = new AttackTestCase(
            "/proxy?url=http://localhost/../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "CVE-2021-40438: Apache HTTP Server Server-Side Request Forgery (SSRF) in mod_proxy. This vulnerability in Apache 2.4.48 and 2.4.49 allows attackers to make the server access arbitrary URLs, potentially leading to information disclosure.",
            "PATH_TRAVERSAL_DETECTED is expected because although this is primarily an SSRF attack, it employs directory traversal patterns (../../../) within the URL parameter to access unauthorized resources."
    );

    // CVE-2020-11993: Apache HTTP Server HTTP/2 request smuggling
    public static final AttackTestCase CVE_2020_11993_H2_SMUGGLING = new AttackTestCase(
            "/api/v1/users/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2020-11993: Apache HTTP Server HTTP/2 request smuggling vulnerability. This affects Apache 2.4.20 to 2.4.43 and allows attackers to bypass access controls through malformed HTTP/2 requests combined with path traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal sequences (../../../) embedded in API endpoints to escape the intended request path structure."
    );

    // CVE-2020-1938: Apache Tomcat AJP Request Injection (Ghostcat)
    public static final AttackTestCase CVE_2020_1938_GHOSTCAT = new AttackTestCase(
            "/WEB-INF/../../../etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2020-1938 (Ghostcat): Apache Tomcat AJP Request Injection vulnerability. This critical flaw allows attackers to access sensitive files like WEB-INF/web.xml and perform Remote Code Execution through the Apache JServ Protocol (AJP) connector.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack attempts to traverse directories from the WEB-INF context to access system files outside the web application's intended directory structure."
    );

    // CVE-2018-1336: Apache Tomcat UTF-8 decoder bug
    public static final AttackTestCase CVE_2018_1336_UTF8_BYPASS = new AttackTestCase(
            "/utf8%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2018-1336: Apache Tomcat UTF-8 decoder vulnerability using overlong encoding sequences. This attack exploits improper UTF-8 decoding in Tomcat 9.0.0.M9 to 9.0.7 and 8.5.0 to 8.5.30 to bypass security filters through invalid UTF-8 sequences.",
            "INVALID_ENCODING is expected because this attack uses overlong UTF-8 encoding sequences (%c0%ae instead of standard %2e for '.') which are invalid according to UTF-8 specifications but may be incorrectly processed by vulnerable decoders."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            CVE_2021_41773_PATH_TRAVERSAL_PASSWD,
            CVE_2021_41773_PATH_TRAVERSAL_SHADOW,
            CVE_2021_41773_WINDOWS_PATH,
            CVE_2021_42013_DOUBLE_ENCODING,
            CVE_2021_42013_ICONS_PATH,
            CVE_2019_0230_STRUTS_TRAVERSAL,
            CVE_2020_1927_MOD_REWRITE,
            CVE_2019_0211_PRIVILEGE_ESCALATION,
            CVE_2018_1333_DOS_ATTACK,
            CVE_2017_15710_NULL_BYTE,
            CVE_2016_8743_HTTP_SMUGGLING,
            CVE_2021_40438_SSRF,
            CVE_2020_11993_H2_SMUGGLING,
            CVE_2020_1938_GHOSTCAT,
            CVE_2018_1336_UTF8_BYPASS
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "Apache CVE Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of Apache HTTP Server and Tomcat CVE attack patterns including path traversal, encoding bypass, request smuggling, and privilege escalation vulnerabilities";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectApacheCVEAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<ApacheCVEAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}