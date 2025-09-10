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
package de.cuioss.tools.security.http.database;

import de.cuioss.tools.security.http.core.UrlSecurityFailureType;

import java.util.List;

/**
 * Database of IIS/Windows specific CVE attack patterns with comprehensive vulnerability documentation.
 * 
 * <p><strong>CRITICAL IIS CVE DATABASE:</strong> This database contains attack patterns
 * based on documented Microsoft IIS CVE vulnerabilities with specific exploit techniques
 * that have been proven to work against various IIS versions and Windows configurations.</p>
 * 
 * <p>These patterns represent historical attack vectors against Microsoft IIS servers,
 * including buffer overflows, path traversal vulnerabilities, Unicode bypass attacks,
 * and Windows-specific encoding exploits. Each attack is documented with CVE details,
 * affected versions, and exploitation techniques.</p>
 * 
 * <h3>CVE Coverage</h3>
 * <ul>
 *   <li><strong>Buffer Overflow CVEs</strong>: CVE-2017-7269 (IIS 6.0 WebDAV)</li>
 *   <li><strong>Remote Code Execution CVEs</strong>: CVE-2015-1635 (HTTP.sys)</li>
 *   <li><strong>Path Traversal CVEs</strong>: CVE-2003-0226, CVE-2008-0075</li>
 *   <li><strong>Authentication Bypass CVEs</strong>: CVE-2009-1535 (WebDAV)</li>
 * </ul>
 * 
 * @since 2.5
 */
public class IISCVEAttackDatabase implements AttackDatabase {

    // CVE-2017-7269: IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow
    public static final AttackTestCase CVE_2017_7269_WEBDAV_OVERFLOW = new AttackTestCase(
            "/webdav/long_filename/../../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2017-7269: IIS 6.0 WebDAV buffer overflow in ScStoragePathFromUrl function. This critical vulnerability allows remote code execution via crafted PROPFIND requests with long filenames. Affects Windows Server 2003 R2 with IIS 6.0. No patch available - Microsoft recommends upgrading to IIS 7.0+.",
            "PATH_TRAVERSAL_DETECTED is expected because despite being primarily a buffer overflow attack, it employs directory traversal patterns (../../../) to access files outside the web root as part of the exploitation payload."
    );

    public static final AttackTestCase CVE_2017_7269_WEBDAV_SAM = new AttackTestCase(
            "/dav/buffer_overflow/../../../windows/system32/config/sam",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2017-7269: WebDAV buffer overflow variant targeting the Windows SAM database file. This attack combines the buffer overflow trigger with path traversal to access sensitive authentication data.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal sequences to navigate to sensitive system files (/windows/system32/config/sam) outside the intended web directory."
    );

    // CVE-2015-1635: IIS HTTP.sys remote code execution
    public static final AttackTestCase CVE_2015_1635_HTTPSYS_RCE = new AttackTestCase(
            "/default.aspx/../../../windows/win.ini HTTP/1.1\\r\\nRange: bytes=0-0-",
            UrlSecurityFailureType.PROTOCOL_VIOLATION,
            "CVE-2015-1635: HTTP.sys remote code execution vulnerability via malformed Range headers. This critical flaw (CVSS 10.0) affects Windows 7/Server 2008 R2 and later, allowing remote code execution through specially crafted HTTP requests. Fixed in MS15-034.",
            "PROTOCOL_VIOLATION is expected because the attack exploits malformed Range header syntax ('bytes=0-0-' with invalid trailing dash) that violates HTTP protocol specifications and triggers the HTTP.sys vulnerability."
    );

    public static final AttackTestCase CVE_2015_1635_RANGE_HEADER = new AttackTestCase(
            "/index.html/../../../windows/system32/drivers/etc/hosts HTTP/1.1\\r\\nRange: bytes=1-1-",
            UrlSecurityFailureType.PROTOCOL_VIOLATION,
            "CVE-2015-1635: HTTP.sys Range header exploit variant. The malformed Range header causes buffer overflow conditions in HTTP.sys, potentially leading to Blue Screen of Death (BSoD) or remote code execution in System context.",
            "PROTOCOL_VIOLATION is expected due to the syntactically incorrect Range header ('bytes=1-1-') that violates HTTP/1.1 Range request specifications and triggers the HTTP.sys parsing vulnerability."
    );

    // CVE-2010-2730: IIS ASP.NET request validation bypass
    public static final AttackTestCase CVE_2010_2730_ASPNET_BYPASS = new AttackTestCase(
            "/default.aspx?input=<script>alert(1)</script>/../../../windows/win.ini",
            UrlSecurityFailureType.XSS_DETECTED,
            "CVE-2010-2730: IIS ASP.NET request validation bypass vulnerability. This flaw allows attackers to bypass ASP.NET's request validation mechanisms and inject malicious scripts by using specific encoding techniques.",
            "XSS_DETECTED is expected because the attack contains JavaScript code (<script>alert(1)</script>) designed to bypass ASP.NET request validation and execute cross-site scripting attacks."
    );

    public static final AttackTestCase CVE_2010_2730_UNICODE_BYPASS = new AttackTestCase(
            "/page.aspx?data=%u003Cscript%u003Ealert(1)%u003C/script%u003E/../../../windows/temp",
            UrlSecurityFailureType.XSS_DETECTED,
            "CVE-2010-2730: ASP.NET request validation bypass using Unicode encoding (%u003C = '<', %u003E = '>'). This technique exploits ASP.NET's Unicode handling to inject script content that bypasses standard XSS filters.",
            "XSS_DETECTED is expected because the Unicode-encoded payload (%u003Cscript%u003E) decodes to script tags containing malicious JavaScript, representing a cross-site scripting attack vector."
    );

    // CVE-2009-1535: IIS WebDAV authentication bypass
    public static final AttackTestCase CVE_2009_1535_WEBDAV_BYPASS = new AttackTestCase(
            "/default.asp\\..\\..\\..\\windows\\win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2009-1535: IIS WebDAV authentication bypass vulnerability using Windows-specific path separators. This attack exploits WebDAV's Translate:f header handling to bypass authentication and perform directory traversal using backslashes.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses Windows-specific directory traversal sequences (\\..\\..\\..\\) with backslash separators to navigate outside the web root directory structure."
    );

    // CVE-2008-0075: IIS FTP service path traversal
    public static final AttackTestCase CVE_2008_0075_FTP_TRAVERSAL = new AttackTestCase(
            "/ftp://anonymous@ftpserver/../../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "CVE-2008-0075: IIS FTP service path traversal vulnerability. This flaw allows attackers to access files outside the FTP root directory by exploiting improper path validation in the IIS FTP service component.",
            "PATH_TRAVERSAL_DETECTED is expected due to the directory traversal pattern (../../../) embedded in the FTP URL that attempts to escape the FTP service's root directory restrictions."
    );

    // CVE-2006-0026: IIS ASP path disclosure vulnerability
    public static final AttackTestCase CVE_2006_0026_DOUBLE_DECODE = new AttackTestCase(
            "/scripts/..%255c..%255c..%255cwindows%255cwin.ini",
            UrlSecurityFailureType.DOUBLE_ENCODING,
            "CVE-2006-0026: IIS ASP path disclosure vulnerability using double URL encoding. This attack exploits double encoding (%255c = %5c = \\) to bypass path validation and access files outside the web root using Windows path separators.",
            "DOUBLE_ENCODING is expected because %255c represents double-encoded backslash characters (\\) where the attack uses double encoding to bypass IIS path validation mechanisms."
    );

    // CVE-2003-0226: IIS Unicode directory traversal (Nimda-style)
    public static final AttackTestCase CVE_2003_0226_UNICODE_TRAVERSAL = new AttackTestCase(
            "/scripts/..%c0%af..%c0%af..%c0%afwinnt%c0%afsystem32%c0%afcmd.exe?/c+dir+c:\\",
            UrlSecurityFailureType.INVALID_ENCODING,
            "CVE-2003-0226: IIS Unicode directory traversal vulnerability (Nimda worm variant). This historic attack uses overlong UTF-8 encoding (%c0%af for '/') to bypass IIS security filters and execute system commands. Part of the famous Code Red/Nimda attack family.",
            "INVALID_ENCODING is expected because %c0%af is an invalid overlong UTF-8 encoding for the forward slash character, violating UTF-8 specifications but potentially processed by vulnerable IIS versions."
    );

    // Windows UNC path attacks
    public static final AttackTestCase WINDOWS_UNC_PATH = new AttackTestCase(
            "/default.asp/../../../\\\\server\\share\\windows\\win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Windows UNC (Universal Naming Convention) path attack exploiting Windows network path handling. This attack attempts to access files through network shares using UNC notation (\\\\server\\share) combined with directory traversal.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack combines directory traversal (../../../) with UNC path notation (\\\\server\\share) to access files outside the intended directory structure through Windows network paths."
    );

    // IIS null byte attacks
    public static final AttackTestCase IIS_NULL_BYTE_ATTACK = new AttackTestCase(
            "/default.asp%00.jpg/../../../windows/win.ini",
            UrlSecurityFailureType.NULL_BYTE_INJECTION,
            "IIS null byte injection attack exploiting file extension handling. This technique uses null bytes (%00) to terminate string processing in IIS, allowing attackers to bypass file extension restrictions and access sensitive files.",
            "NULL_BYTE_INJECTION is expected because the %00 character represents a null byte that can terminate string processing in vulnerable applications, effectively truncating the filename and bypassing file extension security checks."
    );

    // IIS alternate data stream attacks
    public static final AttackTestCase IIS_ADS_ATTACK = new AttackTestCase(
            "/default.asp:$DATA/../../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "IIS Alternate Data Stream (ADS) attack exploiting NTFS ADS functionality. This Windows-specific attack uses ADS notation (:$DATA) to access file data streams while bypassing standard file access restrictions.",
            "PATH_TRAVERSAL_DETECTED is expected because despite using ADS notation, the primary attack vector is directory traversal (../../../) to access files outside the web root directory structure."
    );

    // Windows short filename attacks
    public static final AttackTestCase WINDOWS_8DOT3_ATTACK = new AttackTestCase(
            "/PROGRA~1/../../../windows/win.ini",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "Windows 8.3 short filename attack exploiting legacy DOS filename compatibility. This attack uses Windows short filename notation (PROGRA~1 for 'Program Files') combined with directory traversal to access system files.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal sequences (../../../) with Windows 8.3 short filename conventions to navigate outside the intended directory structure."
    );

    // IIS metabase attacks
    public static final AttackTestCase IIS_METABASE_ATTACK = new AttackTestCase(
            "/iisadmin/default.asp/../../../windows/system32/inetsrv/MetaBase.xml",
            UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
            "IIS metabase configuration file access attack. This attack attempts to access the IIS metabase configuration file (MetaBase.xml) which contains sensitive server configuration information including passwords and security settings.",
            "PATH_TRAVERSAL_DETECTED is expected because the attack uses directory traversal patterns (../../../) to escape the web root and access the IIS metabase configuration file containing sensitive server information."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            CVE_2017_7269_WEBDAV_OVERFLOW,
            CVE_2017_7269_WEBDAV_SAM,
            CVE_2015_1635_HTTPSYS_RCE,
            CVE_2015_1635_RANGE_HEADER,
            CVE_2010_2730_ASPNET_BYPASS,
            CVE_2010_2730_UNICODE_BYPASS,
            CVE_2009_1535_WEBDAV_BYPASS,
            CVE_2008_0075_FTP_TRAVERSAL,
            CVE_2006_0026_DOUBLE_DECODE,
            CVE_2003_0226_UNICODE_TRAVERSAL,
            WINDOWS_UNC_PATH,
            IIS_NULL_BYTE_ATTACK,
            IIS_ADS_ATTACK,
            WINDOWS_8DOT3_ATTACK,
            IIS_METABASE_ATTACK
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "IIS CVE Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of Microsoft IIS and Windows-specific CVE attack patterns including buffer overflow, path traversal, Unicode bypass, and authentication bypass vulnerabilities";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     * 
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(IISCVEAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectIISCVEAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     * 
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<IISCVEAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}