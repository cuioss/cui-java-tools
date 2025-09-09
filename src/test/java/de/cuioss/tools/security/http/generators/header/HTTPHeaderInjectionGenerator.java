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
 * Provides various header injection techniques for testing security validation.
 */
public class HTTPHeaderInjectionGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> injectionPatterns = Generators.fixedValues(
            "Bearer token\r\nX-Injected: malicious",     // CRLF injection
            "Bearer token\nX-Injected: malicious",       // LF injection  
            "Bearer token\rX-Injected: malicious",       // CR injection
            "Bearer token\r\n\r\nHTTP/1.1 200 OK",       // HTTP response splitting
            "Bearer token\u0000admin",                    // Null byte injection
            "Bearer token\r\nSet-Cookie: evil=value",    // Cookie injection
            "Bearer token\r\nLocation: http://evil.com", // Redirect injection
            "value\r\nContent-Type: text/html",          // Content type override
            "token\r\nContent-Length: 0",                // Content length manipulation
            "auth\r\nTransfer-Encoding: chunked",        // Transfer encoding attack
            "Bearer token\r\nX-Frame-Options: DENY",     // Security header override
            "value\r\nAccess-Control-Allow-Origin: *",   // CORS bypass attempt
            "Bearer token\n\nGET /admin HTTP/1.1",       // HTTP request smuggling
            "token\r\nHost: evil.example.com"            // Host header injection
    );

    @Override
    public String next() {
        return injectionPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}