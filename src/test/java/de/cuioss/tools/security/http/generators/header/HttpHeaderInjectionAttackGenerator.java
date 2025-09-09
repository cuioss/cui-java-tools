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
package de.cuioss.tools.security.http.generators.header;

import de.cuioss.test.generator.TypedGenerator;

/**
 * T15: HTTP Header Injection Attack Generator
 * 
 * <p>
 * This generator creates comprehensive HTTP header injection attack patterns that attempt
 * to manipulate HTTP headers through web application inputs. HTTP header injection is a
 * critical vulnerability that can lead to response splitting, cache poisoning, cross-site
 * scripting, session hijacking, and other security issues by allowing attackers to inject
 * malicious content into HTTP response headers.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>CRLF Injection - Carriage Return Line Feed character injection</li>
 *   <li>HTTP Response Splitting - Complete HTTP response manipulation</li>
 *   <li>Header Injection via URL Parameters - Parameter-based header injection</li>
 *   <li>Cookie Injection Attacks - Malicious cookie header manipulation</li>
 *   <li>Location Header Injection - Redirect header manipulation</li>
 *   <li>Content-Type Header Injection - MIME type manipulation attacks</li>
 *   <li>Cache Poisoning Attacks - Cache-Control and related header manipulation</li>
 *   <li>Session Hijacking Headers - Session-related header injection</li>
 *   <li>XSS via Header Injection - Script injection through headers</li>
 *   <li>Authentication Header Bypass - Authorization header manipulation</li>
 *   <li>CORS Header Manipulation - Cross-origin header injection attacks</li>
 *   <li>Security Header Bypass - Security policy header manipulation</li>
 *   <li>Custom Header Injection - Application-specific header attacks</li>
 *   <li>Multi-line Header Injection - Complex multi-header attacks</li>
 *   <li>Encoded Header Injection - URL/Base64 encoded header attacks</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>RFC 7230: Hypertext Transfer Protocol (HTTP/1.1): Message Syntax</li>
 *   <li>NIST SP 800-53: SI-10 Information Input Validation</li>
 * </ul>
 * 
 * @see de.cuioss.tools.security.http.tests.HttpHeaderInjectionAttackTest
 * @author Generated for HTTP Security Validation (T15)
 * @version 1.0.0
 */
public class HttpHeaderInjectionAttackGenerator implements TypedGenerator<String> {

    private static final String[] BASE_URLS = {
            "http://example.com/redirect",
            "https://app.domain.com/login",
            "http://localhost:8080/header",
            "https://secure.site.org/api/response",
            "http://test.example.com/cookie"
    };

    @Override
    public String next() {
        String baseUrl = BASE_URLS[hashBasedSelection(BASE_URLS.length)];

        return switch (hashBasedSelection(15)) {
            case 0 -> createCrlfInjection(baseUrl);
            case 1 -> createHttpResponseSplitting(baseUrl);
            case 2 -> createHeaderInjectionViaUrlParameters(baseUrl);
            case 3 -> createCookieInjectionAttack(baseUrl);
            case 4 -> createLocationHeaderInjection(baseUrl);
            case 5 -> createContentTypeHeaderInjection(baseUrl);
            case 6 -> createCachePoisoningAttack(baseUrl);
            case 7 -> createSessionHijackingHeaders(baseUrl);
            case 8 -> createXssViaHeaderInjection(baseUrl);
            case 9 -> createAuthenticationHeaderBypass(baseUrl);
            case 10 -> createCorsHeaderManipulation(baseUrl);
            case 11 -> createSecurityHeaderBypass(baseUrl);
            case 12 -> createCustomHeaderInjection(baseUrl);
            case 13 -> createMultiLineHeaderInjection(baseUrl);
            case 14 -> createEncodedHeaderInjection(baseUrl);
            default -> createCrlfInjection(baseUrl);
        };
    }

    private String createCrlfInjection(String pattern) {
        String[] crlfAttacks = {
                "normal%0d%0aX-Injected: malicious",
                "test%0d%0aLocation: http://evil.com",
                "value%0aSet-Cookie: admin=true",
                "param%0AContent-Type: text/html",
                "data%0d%0aX-Custom: injected",
                "input%0d%0aCache-Control: no-cache",
                "normal%0d%0a%0d%0a<html><script>alert('XSS')</script></html>"
        };
        String attack = crlfAttacks[hashBasedSelection(crlfAttacks.length)];
        return pattern + "?redirect=" + attack;
    }

    private String createHttpResponseSplitting(String pattern) {
        String[] responseSplittingAttacks = {
                "test%0d%0a%0d%0a<html><body><h1>Hacked</h1></body></html>",
                "normal%0d%0a%0d%0a<script>document.location='http://evil.com'</script>",
                "value%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",
                "param%0a%0aHTTP/1.1 302 Found%0aLocation: javascript:alert('XSS')",
                "data%0d%0a%0d%0a<html><script>document.cookie='admin=true'</script>",
                "input%0d%0a%0d%0a<iframe src='http://attacker.com'></iframe>",
                "test%0d%0aSet-Cookie: session=hijacked%0d%0a%0d%0a<html>Controlled</html>"
        };
        String attack = responseSplittingAttacks[hashBasedSelection(responseSplittingAttacks.length)];
        return pattern + "?page=" + attack;
    }

    private String createHeaderInjectionViaUrlParameters(String pattern) {
        String[] parameterInjections = {
                "admin%0d%0aX-Admin: true",
                "user%0d%0aAuthorization: Bearer hijacked-token",
                "test%0AX-Forwarded-For: 127.0.0.1",
                "value%0aX-Real-IP: 192.168.1.100",
                "param%0d%0aX-Custom-Auth: bypassed",
                "data%0d%0aContent-Disposition: attachment; filename=evil.exe",
                "input%0aX-Frame-Options: ALLOWALL"
        };
        String attack = parameterInjections[hashBasedSelection(parameterInjections.length)];
        return pattern + "?user=" + attack;
    }

    private String createCookieInjectionAttack(String pattern) {
        String[] cookieAttacks = {
                "normal%0d%0aSet-Cookie: admin=true; Path=/",
                "test%0d%0aSet-Cookie: session=ABC123; HttpOnly; Secure",
                "value%0aSet-Cookie: role=administrator",
                "param%0ASet-Cookie: auth=bypassed; Domain=.evil.com",
                "data%0d%0aSet-Cookie: csrf=disabled; SameSite=None",
                "input%0d%0aSet-Cookie: debug=enabled; Path=/admin",
                "user%0d%0aSet-Cookie: token=hijacked; expires=Thu, 31-Dec-2030 23:59:59 GMT"
        };
        String attack = cookieAttacks[hashBasedSelection(cookieAttacks.length)];
        return pattern + "?name=" + attack;
    }

    private String createLocationHeaderInjection(String pattern) {
        String[] locationAttacks = {
                "safe.com%0d%0aLocation: http://evil.com",
                "redirect%0d%0aLocation: javascript:alert('XSS')",
                "normal%0aLocation: data:text/html,<script>alert('XSS')</script>",
                "param%0ALocation: vbscript:msgbox('XSS')",
                "test%0d%0aLocation: file:///etc/passwd",
                "value%0d%0aLocation: ftp://attacker.com/steal",
                "data%0d%0aLocation: //evil.com/phishing"
        };
        String attack = locationAttacks[hashBasedSelection(locationAttacks.length)];
        return pattern + "?url=" + attack;
    }

    private String createContentTypeHeaderInjection(String pattern) {
        String[] contentTypeAttacks = {
                "text/html%0d%0aContent-Type: text/javascript",
                "application/json%0d%0aContent-Type: text/html",
                "text/plain%0aContent-Type: application/octet-stream",
                "image/png%0AContent-Type: text/html; charset=utf-7",
                "text/css%0d%0aContent-Type: application/x-shockwave-flash",
                "application/xml%0d%0aContent-Type: text/html",
                "text/javascript%0d%0aContent-Encoding: gzip"
        };
        String attack = contentTypeAttacks[hashBasedSelection(contentTypeAttacks.length)];
        return pattern + "?type=" + attack;
    }

    private String createCachePoisoningAttack(String pattern) {
        String[] cachePoisoningAttacks = {
                "normal%0d%0aCache-Control: public, max-age=31536000",
                "test%0d%0aPragma: no-cache%0d%0aExpires: Thu, 01 Jan 1970 00:00:00 GMT",
                "value%0aCache-Control: no-store, must-revalidate",
                "param%0AETag: \"hijacked-etag\"",
                "data%0d%0aVary: User-Agent, Accept-Language",
                "input%0d%0aLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT",
                "cache%0d%0aAge: 0"
        };
        String attack = cachePoisoningAttacks[hashBasedSelection(cachePoisoningAttacks.length)];
        return pattern + "?cache=" + attack;
    }

    private String createSessionHijackingHeaders(String pattern) {
        String[] sessionAttacks = {
                "user%0d%0aSet-Cookie: JSESSIONID=hijacked",
                "test%0d%0aSet-Cookie: PHPSESSID=attacker-controlled",
                "normal%0aSet-Cookie: session_id=stolen-session",
                "param%0ASet-Cookie: auth_token=bypassed-token",
                "data%0d%0aSet-Cookie: user_session=admin-session",
                "value%0d%0aSet-Cookie: login_state=authenticated",
                "session%0d%0aSet-Cookie: csrf_token=disabled"
        };
        String attack = sessionAttacks[hashBasedSelection(sessionAttacks.length)];
        return pattern + "?session=" + attack;
    }

    private String createXssViaHeaderInjection(String pattern) {
        String[] xssHeaderAttacks = {
                "test%0d%0aX-XSS-Protection: 0%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('XSS')</script>",
                "normal%0d%0aRefresh: 0; url=javascript:alert('XSS')",
                "value%0aLink: <javascript:alert('XSS')>; rel=prefetch",
                "param%0AContent-Disposition: inline; filename=\"<script>alert('XSS')</script>\"",
                "data%0d%0aX-Frame-Options: DENY%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('XSS')</script>",
                "input%0d%0aContent-Security-Policy: script-src 'unsafe-inline'",
                "xss%0d%0aX-Content-Type-Options: nosniff%0d%0a%0d%0a<img src=x onerror=alert('XSS')>"
        };
        String attack = xssHeaderAttacks[hashBasedSelection(xssHeaderAttacks.length)];
        return pattern + "?content=" + attack;
    }

    private String createAuthenticationHeaderBypass(String pattern) {
        String[] authBypassAttacks = {
                "user%0d%0aAuthorization: Basic YWRtaW46cGFzc3dvcmQ=",
                "test%0d%0aX-Forwarded-User: admin",
                "normal%0aX-Remote-User: administrator",
                "param%0AX-User-Role: admin",
                "data%0d%0aX-Auth-User: root",
                "value%0d%0aX-Forwarded-For: 127.0.0.1",
                "auth%0d%0aX-Real-IP: localhost"
        };
        String attack = authBypassAttacks[hashBasedSelection(authBypassAttacks.length)];
        return pattern + "?auth=" + attack;
    }

    private String createCorsHeaderManipulation(String pattern) {
        String[] corsAttacks = {
                "normal%0d%0aAccess-Control-Allow-Origin: *",
                "test%0d%0aAccess-Control-Allow-Credentials: true",
                "value%0aAccess-Control-Allow-Methods: GET, POST, PUT, DELETE",
                "param%0AAccess-Control-Allow-Headers: *",
                "data%0d%0aAccess-Control-Max-Age: 86400",
                "input%0d%0aAccess-Control-Expose-Headers: *",
                "cors%0d%0aAccess-Control-Allow-Origin: http://evil.com"
        };
        String attack = corsAttacks[hashBasedSelection(corsAttacks.length)];
        return pattern + "?origin=" + attack;
    }

    private String createSecurityHeaderBypass(String pattern) {
        String[] securityBypassAttacks = {
                "test%0d%0aStrict-Transport-Security: max-age=0",
                "normal%0d%0aX-Content-Type-Options: ",
                "value%0aX-Frame-Options: ALLOWALL",
                "param%0AContent-Security-Policy: default-src *",
                "data%0d%0aX-XSS-Protection: 0",
                "input%0d%0aReferrer-Policy: no-referrer-when-downgrade",
                "security%0d%0aFeature-Policy: geolocation *"
        };
        String attack = securityBypassAttacks[hashBasedSelection(securityBypassAttacks.length)];
        return pattern + "?security=" + attack;
    }

    private String createCustomHeaderInjection(String pattern) {
        String[] customHeaderAttacks = {
                "normal%0d%0aX-Custom-Admin: true",
                "test%0d%0aX-Debug-Mode: enabled",
                "value%0aX-Internal-User: admin",
                "param%0AX-Bypass-Auth: true",
                "data%0d%0aX-Override-Security: disabled",
                "input%0d%0aX-Special-Access: granted",
                "custom%0d%0aX-Application-Role: administrator"
        };
        String attack = customHeaderAttacks[hashBasedSelection(customHeaderAttacks.length)];
        return pattern + "?header=" + attack;
    }

    private String createMultiLineHeaderInjection(String pattern) {
        String[] multiLineAttacks = {
                "test%0d%0aX-First: value1%0d%0aX-Second: value2%0d%0aX-Third: value3",
                "normal%0d%0aLocation: http://evil.com%0d%0aSet-Cookie: admin=true%0d%0aX-Injected: success",
                "value%0aContent-Type: text/html%0aCache-Control: no-cache%0aX-Custom: injected",
                "param%0ASet-Cookie: session=hijacked%0ALocation: javascript:alert('XSS')%0AX-Admin: true",
                "data%0d%0aAuthorization: Bearer token%0d%0aX-Role: admin%0d%0aX-Debug: enabled",
                "input%0d%0aX-Frame-Options: DENY%0d%0aContent-Security-Policy: none%0d%0aX-XSS-Protection: 0",
                "multi%0d%0aAccess-Control-Allow-Origin: *%0d%0aAccess-Control-Allow-Credentials: true"
        };
        String attack = multiLineAttacks[hashBasedSelection(multiLineAttacks.length)];
        return pattern + "?multi=" + attack;
    }

    private String createEncodedHeaderInjection(String pattern) {
        String[] encodedAttacks = {
                "test%250d%250aX-Injected: value",        // Double URL encoded CRLF
                "normal%c0%aaLocation: http://evil.com",   // Overlong UTF-8 encoded LF
                "value%e5%98%8a%e5%98%8dX-Custom: header", // Different Unicode encoding
                "param%0d%0aX-Header: injected",          // Standard CRLF
                "data%0d%0aSet-Cookie: admin=true",  // Standard encoding
                "input%ef%bb%bfX-BOM: header",            // UTF-8 BOM + header
                "encoded%ff%fe%0d%00%0a%00X-Wide: value"  // UTF-16 encoded CRLF
        };
        String attack = encodedAttacks[hashBasedSelection(encodedAttacks.length)];
        return pattern + "?encoded=" + attack;
    }

    private int hashBasedSelection(int max) {
        return Math.abs(this.hashCode()) % max;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}