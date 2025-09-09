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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for HTTP header injection attack patterns.
 * 
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 * 
 * Provides various header injection techniques for testing security validation.
 */
public class HTTPHeaderInjectionGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> injectionTypeGen = Generators.integers(1, 8);
    private final TypedGenerator<String> baseTokenGen = Generators.fixedValues("Bearer token", "auth", "value", "token", "session");
    private final TypedGenerator<String> injectedHeaderGen = Generators.fixedValues("X-Injected", "X-Forwarded-For", "X-Real-IP", "X-Admin", "Authorization");
    private final TypedGenerator<String> maliciousValueGen = Generators.fixedValues("malicious", "evil=value", "admin", "bypass", "attack");
    private final TypedGenerator<String> maliciousUrlGen = Generators.fixedValues("http://evil.com", "https://attacker.example", "//malicious.site", "javascript:alert(1)");
    private final TypedGenerator<String> contentTypeGen = Generators.fixedValues("text/html", "text/javascript", "application/octet-stream", "image/svg+xml");
    private final TypedGenerator<String> hostGen = Generators.fixedValues("evil.example.com", "attacker.com", "127.0.0.1", "localhost");

    @Override
    public String next() {
        return switch (injectionTypeGen.next()) {
            case 1 -> generateCrlfInjection();
            case 2 -> generateHttpResponseSplitting();
            case 3 -> generateNullByteInjection();
            case 4 -> generateCookieInjection();
            case 5 -> generateSecurityHeaderOverride();
            case 6 -> generateContentTypeOverride();
            case 7 -> generateHttpRequestSmuggling();
            case 8 -> generateHostHeaderInjection();
            default -> generateCrlfInjection();
        };
    }

    private String generateCrlfInjection() {
        String baseToken = baseTokenGen.next();
        String injectedHeader = injectedHeaderGen.next();
        String maliciousValue = maliciousValueGen.next();

        // Vary the line ending type
        String lineEnding = switch (Generators.integers(1, 3).next()) {
            case 1 -> "\r\n"; // CRLF
            case 2 -> "\n";   // LF
            case 3 -> "\r";   // CR
            default -> "\r\n";
        };

        return baseToken + lineEnding + injectedHeader + ": " + maliciousValue;
    }

    private String generateHttpResponseSplitting() {
        String baseToken = baseTokenGen.next();
        return baseToken + "\r\n\r\nHTTP/1.1 200 OK";
    }

    private String generateNullByteInjection() {
        String baseToken = baseTokenGen.next();
        return baseToken + "\u0000admin";
    }

    private String generateCookieInjection() {
        String baseToken = baseTokenGen.next();
        String maliciousValue = maliciousValueGen.next();
        return baseToken + "\r\nSet-Cookie: " + maliciousValue;
    }

    private String generateSecurityHeaderOverride() {
        String baseToken = baseTokenGen.next();

        return switch (Generators.integers(1, 4).next()) {
            case 1 -> baseToken + "\r\nX-Frame-Options: DENY";
            case 2 -> baseToken + "\r\nContent-Security-Policy: none";
            case 3 -> baseToken + "\r\nAccess-Control-Allow-Origin: *";
            case 4 -> baseToken + "\r\nX-XSS-Protection: 0";
            default -> baseToken + "\r\nX-Frame-Options: DENY";
        };
    }

    private String generateContentTypeOverride() {
        String baseToken = baseTokenGen.next();
        String contentType = contentTypeGen.next();

        return switch (Generators.integers(1, 3).next()) {
            case 1 -> baseToken + "\r\nContent-Type: " + contentType;
            case 2 -> baseToken + "\r\nContent-Length: 0";
            case 3 -> baseToken + "\r\nTransfer-Encoding: chunked";
            default -> baseToken + "\r\nContent-Type: " + contentType;
        };
    }

    private String generateHttpRequestSmuggling() {
        String baseToken = baseTokenGen.next();
        String method = Generators.fixedValues("GET", "POST", "PUT", "DELETE").next();
        String path = Generators.fixedValues("/admin", "/api", "/config", "/users").next();

        return baseToken + "\n\n" + method + " " + path + " HTTP/1.1";
    }

    private String generateHostHeaderInjection() {
        String baseToken = baseTokenGen.next();
        String host = hostGen.next();

        return switch (Generators.integers(1, 2).next()) {
            case 1 -> baseToken + "\r\nHost: " + host;
            case 2 -> baseToken + "\r\nLocation: " + maliciousUrlGen.next();
            default -> baseToken + "\r\nHost: " + host;
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}