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
 * Generator for protocol handler attack patterns.
 * 
 * <p>
 * Provides malicious protocol handler patterns designed to test security validation
 * against protocol-based attacks including custom protocol exploitation, protocol
 * confusion attacks, scheme manipulation, and handler bypass attempts.
 * </p>
 * 
 * <h3>Attack Categories Generated</h3>
 * <ul>
 *   <li><strong>Custom protocol exploitation</strong>: Malicious custom schemes</li>
 *   <li><strong>Protocol confusion</strong>: Mixing different protocol handlers</li>
 *   <li><strong>Scheme manipulation</strong>: Invalid or malformed schemes</li>
 *   <li><strong>Handler bypass</strong>: Attempts to bypass protocol restrictions</li>
 *   <li><strong>Protocol injection</strong>: Injecting protocols into URLs</li>
 *   <li><strong>Data URI exploitation</strong>: Malicious data: scheme usage</li>
 *   <li><strong>Javascript protocol</strong>: javascript: scheme attacks</li>
 *   <li><strong>File protocol abuse</strong>: file: scheme for local access</li>
 * </ul>
 * 
 * Implements: Task G-Protocol from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class ProtocolHandlerAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> protocolAttackPatterns = Generators.fixedValues(
            // Javascript protocol attacks
            "javascript:alert('XSS')/../../../etc/passwd",
            "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))/admin",
            "javascript:window.location='http://evil.com'/../../config",
            "javascript:document.location.href='malicious.com'/../sensitive",
            "javascript:fetch('/../../etc/passwd').then(r=>r.text()).then(console.log)",
            "javascript://comment%0Aalert('XSS')/../etc/hosts",

            // Data URI exploitation
            "data:text/html,<script>alert('XSS')</script>/../../../etc/passwd",
            "data:application/javascript,alert('XSS')/../admin/config",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=/../etc/hosts",
            "data:image/svg+xml,<svg><script>alert('XSS')</script></svg>/../../sensitive",
            "data:text/plain,../../../etc/passwd",
            "data:,../../admin/config",

            // File protocol with path traversal (these will be caught by path traversal detection)
            "file:///../../../etc/passwd",
            "file:////etc/passwd/../../../sensitive",
            "file://../../../etc/hosts",
            "file://localhost/../../../etc/passwd",
            "file:///c:/../../windows/win.ini",
            "file://./../../etc/shadow",
            "file://.././../etc/passwd",
            "file:///etc/../../../passwd",

            // Custom protocol schemes
            "custom://malicious.com/../../../etc/passwd",
            "malware://evil.com/../../admin/config",
            "exploit://attacker.com/../etc/hosts",
            "backdoor://malicious.site/../../sensitive",
            "trojan://evil.domain/../admin",
            "virus://malicious.host/../../config",

            // Protocol confusion attacks
            "http://javascript:alert('XSS')@evil.com/../../../etc/passwd",
            "https://data:text/html,<script>@malicious.com/../../config",
            "ftp://file@evil.com/../../../admin/config",
            "mailto://javascript:alert('XSS')@attacker.com/../sensitive",
            "tel://data:text/html@malicious.com/../../etc/hosts",

            // Protocol injection
            "http://evil.com#javascript:alert('XSS')/../../../etc/passwd",
            "https://malicious.com?redirect=javascript:alert('XSS')/../../config",
            "http://attacker.com/path?url=file:///etc/passwd",
            "https://evil.site/redirect?to=data:text/html,<script>/admin",
            "http://malicious.host/proxy?target=javascript:alert(1)/../sensitive",

            // Malformed protocol schemes
            "ht tp://evil.com/../../../etc/passwd",
            "htt p://malicious.com/../../admin/config",
            "http ://attacker.com/../etc/hosts",
            "http:////evil.com/../../sensitive",
            "http:///evil.com/../admin",
            "http::evil.com/../../etc/passwd",

            // Protocol case manipulation
            "HTTP://EVIL.COM/../../../etc/passwd",
            "hTtP://MaLiCiOuS.cOm/../../admin/config",
            "HTTPS://ATTACKER.COM/../etc/hosts",
            "FTP://EVIL.SITE/../../sensitive",
            "JAVASCRIPT:alert('XSS')/../admin",
            "DATA:text/html,<script>/../../etc/passwd",

            // Protocol with special characters
            "http\u0001://evil.com/../../../etc/passwd",
            "http\u0000://malicious.com/../../admin/config",
            """
            http
            ://attacker.com/../etc/hosts""",
            """
            http\
            \
            ://evil.site/../../sensitive""",
            "http\u0009://malicious.host/../admin",
            "http\u0020://evil.domain/../../etc/passwd",

            // Double protocol schemes
            "http://http://evil.com/../../../etc/passwd",
            "https://https://malicious.com/../../admin/config",
            "ftp://ftp://attacker.com/../etc/hosts",
            "javascript://javascript:alert('XSS')/../../sensitive",
            "data://data:text/html,<script>alert(1)</script>/../admin",

            // Protocol with authentication bypass
            "http://admin:password@evil.com/../../../etc/passwd",
            "https://root:toor@malicious.com/../../admin/config",
            "ftp://user:pass@attacker.com/../etc/hosts",
            "http://:%40@evil.site/../../sensitive",
            "https://user@:@malicious.host/../admin",

            // Protocol with port manipulation
            "http://evil.com:0/../../../etc/passwd",
            "https://malicious.com:65536/../../admin/config",
            "http://attacker.com:-80/../etc/hosts",
            "https://evil.site:99999/../../sensitive",
            "ftp://malicious.host:21;ls/../../admin",

            // Nested protocol attacks
            "http://evil.com/redirect?url=javascript:alert('XSS')/../etc/passwd",
            "https://malicious.com/proxy?target=file:///etc/shadow",
            "http://attacker.com/gateway?dest=data:text/html,<script>/admin",
            "https://evil.site/forward?to=custom://malicious/../../config",

            // Protocol with path traversal
            "http://evil.com/../../../etc/passwd",
            "https://malicious.com/../../admin/config",
            "ftp://attacker.com/../etc/hosts",
            "file://localhost/../../../etc/passwd",
            "javascript:location='http://evil.com'/../sensitive",

            // Protocol handler exploitation
            "gopher://evil.com/../../../etc/passwd",
            "ldap://malicious.com/../../admin/config",
            "dict://attacker.com/../etc/hosts",
            "tftp://evil.site/../../sensitive",
            "imap://malicious.host/../admin",
            "pop3://evil.domain/../../etc/passwd",

            // Protocol with fragment manipulation
            "http://evil.com#/../../../etc/passwd",
            "https://malicious.com#/../../admin/config",
            "javascript:alert('XSS')#/../etc/hosts",
            "data:text/html,<script>alert(1)</script>#/../../sensitive",
            "file:///etc/passwd#/../admin",

            // Protocol encoding attacks
            "%68%74%74%70://evil.com/../../../etc/passwd",
            "%6a%61%76%61%73%63%72%69%70%74:alert('XSS')/../admin",
            "%64%61%74%61:text/html,<script>/../../etc/hosts",
            "%66%69%6c%65:///../../../etc/passwd",
            "h%74%74p://malicious.com/../../sensitive"
    );

    @Override
    public String next() {
        return protocolAttackPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}