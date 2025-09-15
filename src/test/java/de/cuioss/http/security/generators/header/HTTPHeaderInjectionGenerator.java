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
package de.cuioss.http.security.generators.header;

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
    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> baseTokenSelector = Generators.integers(1, 5);
    private final TypedGenerator<Integer> injectedHeaderSelector = Generators.integers(1, 5);
    private final TypedGenerator<Integer> maliciousValueSelector = Generators.integers(1, 5);
    private final TypedGenerator<Integer> maliciousUrlSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> contentTypeSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> hostGeneratorSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> methodSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> pathInjectionSelector = Generators.integers(1, 4);

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
        String baseToken = generateBaseToken();
        String injectedHeader = generateInjectedHeader();
        String maliciousValue = generateMaliciousValue();

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
        String baseToken = generateBaseToken();
        return baseToken + "\r\n\r\nHTTP/1.1 200 OK";
    }

    private String generateNullByteInjection() {
        String baseToken = generateBaseToken();
        return baseToken + "\u0000admin";
    }

    private String generateCookieInjection() {
        String baseToken = generateBaseToken();
        String maliciousValue = generateMaliciousValue();
        return baseToken + "\r\nSet-Cookie: " + maliciousValue;
    }

    private String generateSecurityHeaderOverride() {
        String baseToken = generateBaseToken();

        return switch (Generators.integers(1, 4).next()) {
            case 1 -> baseToken + "\r\nX-Frame-Options: DENY";
            case 2 -> baseToken + "\r\nContent-Security-Policy: none";
            case 3 -> baseToken + "\r\nAccess-Control-Allow-Origin: *";
            case 4 -> baseToken + "\r\nX-XSS-Protection: 0";
            default -> baseToken + "\r\nX-Frame-Options: DENY";
        };
    }

    private String generateContentTypeOverride() {
        String baseToken = generateBaseToken();
        String contentType = generateContentType();

        return switch (Generators.integers(1, 3).next()) {
            case 1 -> baseToken + "\r\nContent-Type: " + contentType;
            case 2 -> baseToken + "\r\nContent-Length: 0";
            case 3 -> baseToken + "\r\nTransfer-Encoding: chunked";
            default -> baseToken + "\r\nContent-Type: " + contentType;
        };
    }

    private String generateHttpRequestSmuggling() {
        String baseToken = generateBaseToken();
        String method = generateMethod();
        String path = generatePathInjection();

        return baseToken + "\n\n" + method + " " + path + " HTTP/1.1";
    }

    private String generateHostHeaderInjection() {
        String baseToken = generateBaseToken();
        String host = generateHostHeader();

        return switch (Generators.integers(1, 2).next()) {
            case 1 -> baseToken + "\r\nHost: " + host;
            case 2 -> baseToken + "\r\nLocation: " + generateMaliciousUrl();
            default -> baseToken + "\r\nHost: " + host;
        };
    }

    // QI-6: Dynamic generation helper methods
    private String generateBaseToken() {
        return switch (baseTokenSelector.next()) {
            case 1 -> "Bearer token";
            case 2 -> "auth";
            case 3 -> "value";
            case 4 -> "token";
            case 5 -> "session";
            default -> "Bearer token";
        };
    }

    private String generateInjectedHeader() {
        return switch (injectedHeaderSelector.next()) {
            case 1 -> "X-Injected";
            case 2 -> "X-Forwarded-For";
            case 3 -> "X-Real-IP";
            case 4 -> "X-Admin";
            case 5 -> "Authorization";
            default -> "X-Injected";
        };
    }

    private String generateMaliciousValue() {
        return switch (maliciousValueSelector.next()) {
            case 1 -> "malicious";
            case 2 -> "evil=value";
            case 3 -> "admin";
            case 4 -> "bypass";
            case 5 -> "attack";
            default -> "malicious";
        };
    }

    private String generateMaliciousUrl() {
        return switch (maliciousUrlSelector.next()) {
            case 1 -> "http://evil.com";
            case 2 -> "https://attacker.example";
            case 3 -> "//malicious.site";
            case 4 -> "javascript:alert(1)";
            default -> "http://evil.com";
        };
    }

    private String generateContentType() {
        return switch (contentTypeSelector.next()) {
            case 1 -> "text/html";
            case 2 -> "text/javascript";
            case 3 -> "application/octet-stream";
            case 4 -> "image/svg+xml";
            default -> "text/html";
        };
    }

    private String generateHostHeader() {
        return switch (hostGeneratorSelector.next()) {
            case 1 -> "evil.example.com";
            case 2 -> "attacker.com";
            case 3 -> "127.0.0.1";
            case 4 -> "localhost";
            default -> "evil.example.com";
        };
    }

    private String generateMethod() {
        return switch (methodSelector.next()) {
            case 1 -> "GET";
            case 2 -> "POST";
            case 3 -> "PUT";
            case 4 -> "DELETE";
            default -> "GET";
        };
    }

    private String generatePathInjection() {
        return switch (pathInjectionSelector.next()) {
            case 1 -> "/admin";
            case 2 -> "/api";
            case 3 -> "/config";
            case 4 -> "/users";
            default -> "/admin";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}