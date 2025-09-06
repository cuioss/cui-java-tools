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
 * Generator for valid HTTP header names.
 * Provides common standard and custom header name examples for testing.
 */
public class ValidHTTPHeaderNameGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validHeaderNames = Generators.fixedValues(
            "Authorization",
            "Content-Type",
            "X-Forwarded-For",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Cache-Control",
            "X-Custom-Header-Name",
            "Accept-Encoding",
            "Host",
            "Connection",
            "Content-Length",
            "Content-Encoding",
            "X-API-Key",
            "X-Requested-With",
            "Origin",
            "Referer",
            "Cookie",
            "Set-Cookie",
            "Location"
    );

    @Override
    public String next() {
        return validHeaderNames.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}