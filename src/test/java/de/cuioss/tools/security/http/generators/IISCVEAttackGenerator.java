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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for IIS/Windows specific CVE attack patterns.
 * 
 * <p>
 * Provides malicious patterns based on known IIS/Windows CVEs designed to test security 
 * validation against documented Microsoft IIS vulnerabilities including path traversal,
 * directory traversal, buffer overflows, and various Windows-specific attack vectors.
 * </p>
 * 
 * <h3>CVE Categories Generated</h3>
 * <ul>
 *   <li><strong>CVE-2017-7269</strong>: IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow</li>
 *   <li><strong>CVE-2015-1635</strong>: IIS HTTP.sys remote code execution</li>
 *   <li><strong>CVE-2010-2730</strong>: IIS ASP.NET request validation bypass</li>
 *   <li><strong>CVE-2009-1535</strong>: IIS WebDAV authentication bypass</li>
 *   <li><strong>CVE-2008-0075</strong>: IIS FTP service path traversal</li>
 *   <li><strong>CVE-2006-0026</strong>: IIS ASP path disclosure vulnerability</li>
 *   <li><strong>CVE-2005-4360</strong>: IIS WebDAV privilege escalation</li>
 *   <li><strong>CVE-2003-0226</strong>: IIS directory traversal via Unicode</li>
 * </ul>
 * 
 * Implements: Task G-IISCVE from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class IISCVEAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> iisCVEPatterns = Generators.fixedValues(
            // CVE-2017-7269: IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow
            "/webdav/long_filename/../../../windows/win.ini",
            "/dav/buffer_overflow/../../../windows/system32/config/sam",
            "/webdav/test.txt_extended/../../../boot.ini",

            // CVE-2015-1635: IIS HTTP.sys remote code execution (HTTP Range header)
            "/default.aspx/../../../windows/win.ini HTTP/1.1\\r\\nRange: bytes=0-0-",
            "/index.html/../../../windows/system32/drivers/etc/hosts HTTP/1.1\\r\\nRange: bytes=1-1-",
            "/app/../../../windows/system32/config/system HTTP/1.1\\r\\nRange: bytes=2-2-",

            // CVE-2010-2730: IIS ASP.NET request validation bypass
            "/default.aspx?input=<script>alert(1)</script>/../../../windows/win.ini",
            "/login.aspx?user=%3Cscript%3Ealert(1)%3C%2Fscript%3E/../../../boot.ini",
            "/search.aspx?q=javascript:alert(1)/../../../windows/system32/config/sam",
            "/page.aspx?data=%u003Cscript%u003Ealert(1)%u003C/script%u003E/../../../windows/temp",

            // CVE-2009-1535: IIS WebDAV authentication bypass with translate:f
            "/default.asp\\..\\..\\..\\windows\\win.ini",
            "/index.asp\\..\\..\\..\\windows\\system32\\config\\sam",
            "/admin.asp\\..\\..\\..\\boot.ini",
            "/login.asp\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

            // CVE-2008-0075: IIS FTP service path traversal
            "/ftp://anonymous@ftpserver/../../../windows/win.ini",
            "/ftp://user:pass@server/../../../windows/system32/config/system",
            "/ftproot/../../../windows/system32/drivers/etc/hosts",

            // CVE-2006-0026: IIS ASP path disclosure vulnerability
            "/scripts/..%255c..%255c..%255cwindows%255cwin.ini",
            "/iisadmin/..%255c..%255c..%255cwindows%255csystem32%255cconfig%255csam",
            "/msadc/..%255c..%255c..%255cboot.ini",
            "/scripts/..%c1%1c..%c1%1c..%c1%1cwindows%c1%1cwin.ini",

            // CVE-2005-4360: IIS WebDAV privilege escalation
            "PROPFIND /webdav/../../../windows/win.ini HTTP/1.1",
            "MKCOL /dav/../../../windows/system32/config/sam HTTP/1.1",
            "PROPPATCH /webdav/../../../boot.ini HTTP/1.1",
            "MOVE /webdav/test/../../../windows/system32/drivers/etc/hosts HTTP/1.1",

            // CVE-2003-0226: IIS directory traversal via Unicode (Nimda-style)
            "/scripts/..%c0%af..%c0%af..%c0%afwinnt%c0%afsystem32%c0%afcmd.exe?/c+dir+c:\\",
            "/msadc/..%c0%af..%c0%af..%c0%afwinnt%c0%afwin.ini",
            "/iisadmin/..%c0%af..%c0%af..%c0%afboot.ini",
            "/scripts/..%c1%9c..%c1%9c..%c1%9cwinnt%c1%9csystem32%c1%9ccmd.exe",

            // Windows-specific directory traversal patterns
            "/default.asp/..\\..\\..\\windows\\win.ini",
            "/index.aspx/..\\..\\..\\windows\\system32\\config\\sam",
            "/login.asp/..\\..\\..\\boot.ini",
            "/admin.aspx/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

            // IIS short filename (8.3) attacks
            "/PROGRA~1/../../../windows/win.ini",
            "/DOCUME~1/../../../windows/system32/config/sam",
            "/WINDOW~1/../../../boot.ini",
            "/SYSTEM~1/../../../windows/system32/drivers/etc/hosts",

            // IIS alternate data stream attacks
            "/default.asp:$DATA/../../../windows/win.ini",
            "/index.html:$INDEX_ALLOCATION/../../../windows/system32/config/system",
            "/login.asp::$DATA/../../../boot.ini",
            "/admin.aspx:ads/../../../windows/system32/drivers/etc/hosts",

            // IIS case sensitivity bypass
            "/DEFAULT.ASP/../../../windows/WIN.INI",
            "/INDEX.HTML/../../../WINDOWS/SYSTEM32/CONFIG/SAM",
            "/Login.Asp/../../../Boot.Ini",
            "/ADMIN.ASPX/../../../Windows/System32/Drivers/Etc/Hosts",

            // Windows UNC path attacks
            "/default.asp/../../../\\\\server\\share\\windows\\win.ini",
            "/index.html/../../../\\\\localhost\\c$\\windows\\system32\\config\\sam",
            "/login.asp/../../../\\\\127.0.0.1\\c$\\boot.ini",
            "/admin.aspx/../../../\\\\\\\\server\\admin$\\windows\\system32\\drivers\\etc\\hosts",

            // IIS null byte attacks (historical)
            "/default.asp%00.jpg/../../../windows/win.ini",
            "/index.html%00.gif/../../../windows/system32/config/sam",
            "/login.asp%00.txt/../../../boot.ini",
            "/admin.aspx%00.pdf/../../../windows/system32/drivers/etc/hosts",

            // IIS double decoding attacks
            "/scripts/..%252f..%252f..%252fwindows%252fwin.ini",
            "/msadc/..%252f..%252f..%252fwindows%252fsystem32%252fconfig%252fsam",
            "/iisadmin/..%252f..%252f..%252fboot.ini",
            "/scripts/..%252f..%252f..%252fwindows%252fsystem32%252fdrivers%252fetc%252fhosts",

            // IIS request smuggling patterns
            "/default.asp/../../../windows/win.ini HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1",
            "/index.html/../../../windows/system32/config/sam HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "/login.asp/../../../boot.ini HTTP/1.1\r\nConnection: keep-alive\r\n\r\nPOST /upload HTTP/1.1",

            // Windows registry access attempts
            "/default.asp/../../../windows/system32/config/SOFTWARE",
            "/index.html/../../../windows/system32/config/SECURITY",
            "/login.asp/../../../windows/system32/config/SYSTEM",
            "/admin.aspx/../../../windows/system32/config/DEFAULT",

            // Windows service file attacks
            "/default.asp/../../../windows/system32/services.exe",
            "/index.html/../../../windows/system32/lsass.exe",
            "/login.asp/../../../windows/system32/winlogon.exe",
            "/admin.aspx/../../../windows/system32/svchost.exe",

            // IIS specific file extensions bypass
            "/test.asp;jpg/../../../windows/win.ini",
            "/upload.aspx;txt/../../../windows/system32/config/sam",
            "/download.asp;gif/../../../boot.ini",
            "/admin.aspx;pdf/../../../windows/system32/drivers/etc/hosts",

            // Complex Windows encoding combinations
            "/scripts/..%5c..%5c..%5cwindows%5cwin.ini",
            "/msadc/..%2f..%5c..%2fwindows%5csystem32%2fconfig%5csam",
            "/iisadmin/..%5c..%2f..%5cboot.ini",
            "/scripts/..%2f..%5c..%2fwindows%2fsystem32%5cdrivers%2fetc%5chosts",

            // IIS metabase attacks
            "/iisadmin/default.asp/../../../windows/system32/inetsrv/MetaBase.xml",
            "/scripts/default.asp/../../../windows/system32/inetsrv/MBSchema.xml",
            "/msadc/default.asp/../../../windows/system32/LogFiles/W3SVC1/",

            // Windows temp directory attacks
            "/default.asp/../../../windows/temp/malicious.exe",
            "/index.html/../../../temp/upload.asp",
            "/login.asp/../../../tmp/backdoor.exe",
            "/admin.aspx/../../../windows/temp/../system32/cmd.exe"
    );

    @Override
    public String next() {
        return iisCVEPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}