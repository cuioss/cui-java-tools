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
package de.cuioss.http.security.generators.injection;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for protocol handler attack patterns.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
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

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> attackCategoryGen = Generators.integers(1, 17);
    private final TypedGenerator<Integer> hostSelector = Generators.integers(1, 6);
    private final TypedGenerator<Integer> pathSelector = Generators.integers(1, 6);

    @Override
    public String next() {
        return switch (attackCategoryGen.next()) {
            case 1 -> generateJavaScriptProtocolAttack();
            case 2 -> generateDataUriExploitation();
            case 3 -> generateFileProtocolAttack();
            case 4 -> generateCustomProtocolSchemes();
            case 5 -> generateProtocolConfusionAttacks();
            case 6 -> generateProtocolInjection();
            case 7 -> generateMalformedProtocolSchemes();
            case 8 -> generateProtocolCaseManipulation();
            case 9 -> generateProtocolWithSpecialCharacters();
            case 10 -> generateDoubleProtocolSchemes();
            case 11 -> generateProtocolWithAuthBypass();
            case 12 -> generateProtocolWithPortManipulation();
            case 13 -> generateNestedProtocolAttacks();
            case 14 -> generateProtocolWithPathTraversal();
            case 15 -> generateProtocolHandlerExploitation();
            case 16 -> generateProtocolWithFragmentManipulation();
            case 17 -> generateProtocolEncodingAttacks();
            default -> generateJavaScriptProtocolAttack();
        };
    }

    private String generateJavaScriptProtocolAttack() {
        int type = Generators.integers(1, 6).next();
        String path = generatePath();

        return switch (type) {
            case 1 -> "javascript:alert('XSS')" + path;
            case 2 -> "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))/admin";
            case 3 -> "javascript:window.location='http://evil.com'/../../config";
            case 4 -> "javascript:document.location.href='malicious.com'/../sensitive";
            case 5 -> "javascript:fetch('/../../etc/passwd').then(r=>r.text()).then(console.log)";
            case 6 -> "javascript://comment%0Aalert('XSS')/../etc/hosts";
            default -> "javascript:alert('XSS')" + path;
        };
    }

    private String generateDataUriExploitation() {
        int type = Generators.integers(1, 6).next();
        String path = generatePath();

        return switch (type) {
            case 1 -> "data:text/html,<script>alert('XSS')</script>" + path;
            case 2 -> "data:application/javascript,alert('XSS')/../admin/config";
            case 3 -> "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=/../etc/hosts";
            case 4 -> "data:image/svg+xml,<svg><script>alert('XSS')</script></svg>/../../sensitive";
            case 5 -> "data:text/plain,../../../etc/passwd";
            case 6 -> "data:,../../admin/config";
            default -> "data:text/html,<script>alert('XSS')</script>" + path;
        };
    }

    private String generateFileProtocolAttack() {
        int type = Generators.integers(1, 8).next();

        return switch (type) {
            case 1 -> "file:///../../../etc/passwd";
            case 2 -> "file:////etc/passwd/../../../sensitive";
            case 3 -> "file://../../../etc/hosts";
            case 4 -> "file://localhost/../../../etc/passwd";
            case 5 -> "file:///c:/../../windows/win.ini";
            case 6 -> "file://./../../etc/shadow";
            case 7 -> "file://.././../etc/passwd";
            case 8 -> "file:///etc/../../../passwd";
            default -> "file:///../../../etc/passwd";
        };
    }

    private String generateCustomProtocolSchemes() {
        int type = Generators.integers(1, 6).next();
        String host = generateHost();
        String path = generatePath();

        return switch (type) {
            case 1 -> "custom://" + host + path;
            case 2 -> "malware://" + host + "/../../admin/config";
            case 3 -> "exploit://" + host + "/../etc/hosts";
            case 4 -> "backdoor://" + host + "/../../sensitive";
            case 5 -> "trojan://" + host + "/../admin";
            case 6 -> "virus://" + host + "/../../config";
            default -> "custom://" + host + path;
        };
    }

    private String generateProtocolConfusionAttacks() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://javascript:alert('XSS')@" + host + "/../../../etc/passwd";
            case 2 -> "https://data:text/html,<script>@" + host + "/../../config";
            case 3 -> "ftp://file@" + host + "/../../../admin/config";
            case 4 -> "mailto://javascript:alert('XSS')@" + host + "/../sensitive";
            case 5 -> "tel://data:text/html@" + host + "/../../etc/hosts";
            default -> "http://javascript:alert('XSS')@" + host + "/../../../etc/passwd";
        };
    }

    private String generateProtocolInjection() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://" + host + "#javascript:alert('XSS')/../../../etc/passwd";
            case 2 -> "https://" + host + "?redirect=javascript:alert('XSS')/../../config";
            case 3 -> "http://" + host + "/path?url=file:///etc/passwd";
            case 4 -> "https://" + host + "/redirect?to=data:text/html,<script>/admin";
            case 5 -> "http://" + host + "/proxy?target=javascript:alert(1)/../sensitive";
            default -> "http://" + host + "#javascript:alert('XSS')/../../../etc/passwd";
        };
    }

    private String generateMalformedProtocolSchemes() {
        int type = Generators.integers(1, 6).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "ht tp://" + host + "/../../../etc/passwd";
            case 2 -> "htt p://" + host + "/../../admin/config";
            case 3 -> "http ://" + host + "/../etc/hosts";
            case 4 -> "http:////" + host + "/../../sensitive";
            case 5 -> "http:///" + host + "/../admin";
            case 6 -> "http::" + host + "/../../etc/passwd";
            default -> "ht tp://" + host + "/../../../etc/passwd";
        };
    }

    private String generateProtocolCaseManipulation() {
        int type = Generators.integers(1, 6).next();

        return switch (type) {
            case 1 -> "HTTP://EVIL.COM/../../../etc/passwd";
            case 2 -> "hTtP://MaLiCiOuS.cOm/../../admin/config";
            case 3 -> "HTTPS://ATTACKER.COM/../etc/hosts";
            case 4 -> "FTP://EVIL.SITE/../../sensitive";
            case 5 -> "JAVASCRIPT:alert('XSS')/../admin";
            case 6 -> "DATA:text/html,<script>/../../etc/passwd";
            default -> "HTTP://EVIL.COM/../../../etc/passwd";
        };
    }

    private String generateProtocolWithSpecialCharacters() {
        int type = Generators.integers(1, 6).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http\u0001://" + host + "/../../../etc/passwd";
            case 2 -> "http\u0000://" + host + "/../../admin/config";
            case 3 -> "http\n://attacker.com/../etc/hosts";
            case 4 -> "http\\\n\\\n://evil.site/../../sensitive";
            case 5 -> "http\u0009://" + host + "/../admin";
            case 6 -> "http\u0020://" + host + "/../../etc/passwd";
            default -> "http\u0001://" + host + "/../../../etc/passwd";
        };
    }

    private String generateDoubleProtocolSchemes() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://http://" + host + "/../../../etc/passwd";
            case 2 -> "https://https://" + host + "/../../admin/config";
            case 3 -> "ftp://ftp://" + host + "/../etc/hosts";
            case 4 -> "javascript://javascript:alert('XSS')/../../sensitive";
            case 5 -> "data://data:text/html,<script>alert(1)</script>/../admin";
            default -> "http://http://" + host + "/../../../etc/passwd";
        };
    }

    private String generateProtocolWithAuthBypass() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://admin:password@" + host + "/../../../etc/passwd";
            case 2 -> "https://root:toor@" + host + "/../../admin/config";
            case 3 -> "ftp://user:pass@" + host + "/../etc/hosts";
            case 4 -> "http://:%40@" + host + "/../../sensitive";
            case 5 -> "https://user@:@" + host + "/../admin";
            default -> "http://admin:password@" + host + "/../../../etc/passwd";
        };
    }

    private String generateProtocolWithPortManipulation() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://" + host + ":0/../../../etc/passwd";
            case 2 -> "https://" + host + ":65536/../../admin/config";
            case 3 -> "http://" + host + ":-80/../etc/hosts";
            case 4 -> "https://" + host + ":99999/../../sensitive";
            case 5 -> "ftp://" + host + ":21;ls/../../admin";
            default -> "http://" + host + ":0/../../../etc/passwd";
        };
    }

    private String generateNestedProtocolAttacks() {
        int type = Generators.integers(1, 4).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://" + host + "/redirect?url=javascript:alert('XSS')/../etc/passwd";
            case 2 -> "https://" + host + "/proxy?target=file:///etc/shadow";
            case 3 -> "http://" + host + "/gateway?dest=data:text/html,<script>/admin";
            case 4 -> "https://" + host + "/forward?to=custom://malicious/../../config";
            default -> "http://" + host + "/redirect?url=javascript:alert('XSS')/../etc/passwd";
        };
    }

    private String generateProtocolWithPathTraversal() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://" + host + "/../../../etc/passwd";
            case 2 -> "https://" + host + "/../../admin/config";
            case 3 -> "ftp://" + host + "/../etc/hosts";
            case 4 -> "file://localhost/../../../etc/passwd";
            case 5 -> "javascript:location='http://evil.com'/../sensitive";
            default -> "http://" + host + "/../../../etc/passwd";
        };
    }

    private String generateProtocolHandlerExploitation() {
        int type = Generators.integers(1, 6).next();
        String host = generateHost();
        String path = generatePath();

        return switch (type) {
            case 1 -> "gopher://" + host + path;
            case 2 -> "ldap://" + host + "/../../admin/config";
            case 3 -> "dict://" + host + "/../etc/hosts";
            case 4 -> "tftp://" + host + "/../../sensitive";
            case 5 -> "imap://" + host + "/../admin";
            case 6 -> "pop3://" + host + "/../../etc/passwd";
            default -> "gopher://" + host + path;
        };
    }

    private String generateProtocolWithFragmentManipulation() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "http://" + host + "#/../../../etc/passwd";
            case 2 -> "https://" + host + "#/../../admin/config";
            case 3 -> "javascript:alert('XSS')#/../etc/hosts";
            case 4 -> "data:text/html,<script>alert(1)</script>#/../../sensitive";
            case 5 -> "file:///etc/passwd#/../admin";
            default -> "http://" + host + "#/../../../etc/passwd";
        };
    }

    private String generateProtocolEncodingAttacks() {
        int type = Generators.integers(1, 5).next();
        String host = generateHost();

        return switch (type) {
            case 1 -> "%68%74%74%70://" + host + "/../../../etc/passwd";
            case 2 -> "%6a%61%76%61%73%63%72%69%70%74:alert('XSS')/../admin";
            case 3 -> "%64%61%74%61:text/html,<script>/../../etc/hosts";
            case 4 -> "%66%69%6c%65:///../../../etc/passwd";
            case 5 -> "h%74%74p://" + host + "/../../sensitive";
            default -> "%68%74%74%70://" + host + "/../../../etc/passwd";
        };
    }

    private String generateHost() {
        return switch (hostSelector.next()) {
            case 1 -> "evil.com";
            case 2 -> "malicious.com";
            case 3 -> "attacker.com";
            case 4 -> "evil.site";
            case 5 -> "malicious.host";
            case 6 -> "evil.domain";
            default -> "evil.com";
        };
    }

    private String generatePath() {
        return switch (pathSelector.next()) {
            case 1 -> "../../../etc/passwd";
            case 2 -> "/../../admin/config";
            case 3 -> "/../etc/hosts";
            case 4 -> "/../../sensitive";
            case 5 -> "/../admin";
            case 6 -> "/../../config";
            default -> "../../../etc/passwd";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}