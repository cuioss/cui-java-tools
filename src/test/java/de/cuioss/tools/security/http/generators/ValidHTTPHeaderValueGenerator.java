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
 * Generator for valid HTTP header values.
 * Provides common header value examples for testing.
 */
public class ValidHTTPHeaderValueGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validHeaderValues = Generators.fixedValues(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "application/json",
            "text/html; charset=utf-8",
            "gzip, deflate, br",
            "en-US,en;q=0.9",
            "max-age=3600, must-revalidate",
            "192.168.1.1, 10.0.0.1",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)",
            "XMLHttpRequest",
            "https%3A%2F%2Fexample.com",
            "no-cache",
            "keep-alive",
            "application/x-www-form-urlencoded",
            "text/plain",
            "utf-8",
            "Basic YWRtaW46cGFzc3dvcmQ=",
            "application/xml",
            "close",
            "private, max-age=0",
            "same-origin"
    );

    @Override
    public String next() {
        return validHeaderValues.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}