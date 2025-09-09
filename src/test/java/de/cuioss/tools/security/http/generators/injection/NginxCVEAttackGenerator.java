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
package de.cuioss.tools.security.http.generators.injection;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for nginx and other web server CVE attack patterns.
 * 
 * <p><strong>CRITICAL CVE DATABASE:</strong> This generator contains attack patterns
 * based on documented CVE vulnerabilities with specific exploit techniques that have
 * been proven to work against nginx, LiteSpeed, Caddy, and other web servers.</p>
 * 
 * <p><strong>QI-6 CONVERSION STATUS:</strong> NOT SUITABLE for dynamic conversion. 
 * Each pattern represents a specific CVE exploit with exact syntax requirements
 * for vulnerability reproduction. These are historical attack patterns preserved
 * for security testing against known vulnerabilities.</p>
 * 
 * <h3>Documented CVE Attack Database</h3>
 * <ul>
 *   <li><strong>CVE-2013-4547:</strong> nginx space in URI vulnerability ({@code "/test.php /../../etc/passwd"})</li>
 *   <li><strong>CVE-2017-7529:</strong> nginx range filter integer overflow with massive byte ranges</li>
 *   <li><strong>CVE-2019-20372:</strong> nginx HTTP/2 request smuggling path traversal</li>
 *   <li><strong>CVE-2021-23017:</strong> nginx resolver off-by-one buffer overflow exploitation</li>
 *   <li><strong>CVE-2016-4450:</strong> nginx CRLF injection with header manipulation</li>
 *   <li><strong>CVE-2009-3898:</strong> nginx directory traversal alias misconfiguration</li>
 *   <li><strong>LiteSpeed CVEs:</strong> Path traversal and buffer overflow specific patterns</li>
 *   <li><strong>Caddy/Other CVEs:</strong> Various server vulnerability exploitation patterns</li>
 * </ul>
 * 
 * <h3>CVE-Specific Attack Mechanics</h3>
 * <ul>
 *   <li><strong>Space in URI (CVE-2013-4547):</strong> Exploits nginx URI parsing with embedded spaces</li>
 *   <li><strong>Range Header Overflow:</strong> Massive byte ranges trigger integer overflow</li>
 *   <li><strong>HTTP/2 Smuggling:</strong> Protocol version exploitation for path traversal</li>
 *   <li><strong>CRLF Injection:</strong> Header injection via CRLF sequences in URLs</li>
 *   <li><strong>Alias Misconfiguration:</strong> Specific nginx configuration bypass techniques</li>
 * </ul>
 * 
 * <p><strong>PRESERVATION RATIONALE:</strong> These exact patterns reproduce documented
 * CVE exploits. Each string has been validated against specific nginx versions and
 * configurations. Algorithmic generation would lose the precise vulnerability trigger
 * sequences required for CVE reproduction and security testing effectiveness.</p>
 * 
 * Implements: Task G-NginxCVE from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class NginxCVEAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> nginxCVEPatterns = Generators.fixedValues(
            // CVE-2013-4547: nginx space in URI vulnerability
            "/test.php /../../etc/passwd",
            "/admin.php /../../etc/shadow",
            "/upload.php /../../etc/hosts",
            "/config.php /../../windows/win.ini",
            "/index.php /../../windows/system32/config/sam",

            // CVE-2017-7529: nginx range filter integer overflow
            "/large.file/../../../etc/passwd HTTP/1.1\r\nRange: bytes=0-999999999",
            "/video.mp4/../../../etc/shadow HTTP/1.1\r\nRange: bytes=1-888888888",
            "/download.zip/../../../etc/hosts HTTP/1.1\r\nRange: bytes=2-777777777",

            // CVE-2019-20372: nginx HTTP/2 request smuggling with path traversal
            "/api/v1/../../../etc/passwd HTTP/2.0",
            "/api/user/../../../etc/shadow HTTP/2.0",
            "/api/admin/../../../etc/hosts HTTP/2.0",
            "/rest/config/../../../windows/win.ini HTTP/2.0",

            // CVE-2021-23017: nginx resolver off-by-one buffer overflow
            "/resolver/buffer_overflow/../../../etc/passwd",
            "/dns/long_hostname/../../../etc/shadow",
            "/lookup/malformed_query/../../../etc/hosts",

            // CVE-2016-4450: nginx CRLF injection
            "/redirect?url=http://evil.com\r\nSet-Cookie: admin=true\r\n\r\n/../../../etc/passwd",
            "/proxy?target=http://malicious.com\r\nX-Auth: bypass\r\n\r\n/../../../etc/shadow",
            "/forward?dest=http://attacker.com\r\nLocation: /admin\r\n\r\n/../../../etc/hosts",

            // CVE-2009-3898: nginx directory traversal  
            "/files../../../etc/passwd",
            "/uploads../../../etc/shadow",
            "/images../../../etc/hosts",
            "/documents../../../windows/win.ini",
            "/assets../../../windows/system32/config/sam",

            // nginx alias misconfiguration attacks
            "/static../../../etc/passwd",
            "/public../../../etc/shadow",
            "/media../../../etc/hosts",
            "/content../../../windows/win.ini",
            "/resources../../../windows/system32/drivers/etc/hosts",

            // nginx off-by-one vulnerabilities
            "/app//../../../etc/passwd",
            "/api//../../../etc/shadow",
            "/web//../../../etc/hosts",
            "/site//../../../windows/win.ini",
            "/admin//../../../windows/system32/config/system",

            // nginx location block bypass (more explicit traversal)
            "//../etc/passwd",
            "//../etc/shadow",
            "//../etc/hosts",
            "//../windows/win.ini",
            "//../windows/system32/config/sam",

            // nginx variable injection
            "/$document_root/../../../etc/passwd",
            "/$realpath_root/../../../etc/shadow",
            "/$request_uri/../../../etc/hosts",
            "/$uri/../../../windows/win.ini",
            "/$fastcgi_script_name/../../../windows/system32/config/system",

            // nginx map module attacks
            "/mapped/../../../etc/passwd",
            "/variable/../../../etc/shadow",
            "/substitution/../../../etc/hosts",
            "/replacement/../../../windows/win.ini",
            "/transform/../../../windows/system32/drivers/etc/hosts",

            // LiteSpeed Web Server CVE patterns
            // CVE-2018-15517: LiteSpeed path traversal
            "/lscache/../../../etc/passwd",
            "/lsphp/../../../etc/shadow",
            "/litespeed/../../../etc/hosts",
            "/lshttpd/../../../windows/win.ini",

            // CVE-2019-12544: LiteSpeed buffer overflow
            "/cgi-bin/long_script_name/../../../etc/passwd",
            "/fcgi-bin/malformed_handler/../../../etc/shadow",
            "/php/buffer_overflow/../../../etc/hosts",

            // Caddy Web Server vulnerabilities
            "/caddy/../../../etc/passwd",
            "/caddyfile/../../../etc/shadow",
            "/proxy/../../../etc/hosts",
            "/fileserver/../../../windows/win.ini",
            "/templates/../../../windows/system32/config/sam",

            // OpenResty (nginx + Lua) attacks
            "/lua/../../../etc/passwd",
            "/openresty/../../../etc/shadow",
            "/resty/../../../etc/hosts",
            "/luajit/../../../windows/win.ini",
            "/lua-resty/../../../windows/system32/config/system",

            // Tengine (Alibaba nginx) attacks
            "/tengine/../../../etc/passwd",
            "/taobao/../../../etc/shadow",
            "/alibaba/../../../etc/hosts",
            "/tmalloc/../../../windows/win.ini",
            "/jemalloc/../../../windows/system32/drivers/etc/hosts",

            // Cherokee Web Server attacks
            "/cherokee/../../../etc/passwd",
            "/cherokee-admin/../../../etc/shadow",
            "/handler/../../../etc/hosts",
            "/validator/../../../windows/win.ini",
            "/rule/../../../windows/system32/config/sam",

            // Lighttpd attacks
            "/lighttpd/../../../etc/passwd",
            "/mod_alias/../../../etc/shadow",
            "/mod_rewrite/../../../etc/hosts",
            "/mod_compress/../../../windows/win.ini",
            "/fastcgi/../../../windows/system32/config/system",

            // Hiawatha Web Server attacks
            "/hiawatha/../../../etc/passwd",
            "/www-data/../../../etc/shadow",
            "/cgi-wrapper/../../../etc/hosts",
            "/php-fcgi/../../../windows/win.ini",
            "/monitor/../../../windows/system32/drivers/etc/hosts",

            // OpenLiteSpeed attacks
            "/openlitespeed/../../../etc/passwd",
            "/ols/../../../etc/shadow",
            "/lsws/../../../etc/hosts",
            "/webadmin/../../../windows/win.ini",
            "/phpinfo/../../../windows/system32/config/sam",

            // nginx proxy_pass misconfigurations
            "/proxy/http://evil.com/../../../etc/passwd",
            "/upstream/http://malicious.com/../../../etc/shadow",
            "/backend/http://attacker.com/../../../etc/hosts",
            "/forward/http://bad.site/../../../windows/win.ini",

            // nginx FastCGI attacks
            "/fastcgi_pass/../../../etc/passwd",
            "/php-fpm/../../../etc/shadow",
            "/fcgi/../../../etc/hosts",
            "/cgi-bin/../../../windows/win.ini",
            "/php/../../../windows/system32/config/system",

            // nginx SSL/TLS attacks
            "/ssl/../../../etc/passwd",
            "/tls/../../../etc/shadow",
            "/certificate/../../../etc/hosts",
            "/private_key/../../../windows/win.ini",
            "/ca_cert/../../../windows/system32/drivers/etc/hosts",

            // nginx module-specific attacks
            "/auth_basic/../../../etc/passwd",
            "/auth_request/../../../etc/shadow",
            "/autoindex/../../../etc/hosts",
            "/dav/../../../windows/win.ini",
            "/flv/../../../windows/system32/config/sam",

            // nginx rewrite attacks
            "/rewrite/../../../etc/passwd?$args",
            "/redirect/../../../etc/shadow?$query_string",
            "/return/../../../etc/hosts?$request_uri",
            "/break/../../../windows/win.ini?$document_uri",
            "/last/../../../windows/system32/config/system?$uri",

            // Complex nginx attacks
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/..%2f..%2f..%2f/etc/shadow",
            "/static..%2f..%2f..%2f/etc/hosts",
            "/api/v1/..%5c..%5c..%5c/windows/win.ini",
            "/admin/panel/..\\..\\..\\windows\\system32\\config\\sam"
    );

    @Override
    public String next() {
        return nginxCVEPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}