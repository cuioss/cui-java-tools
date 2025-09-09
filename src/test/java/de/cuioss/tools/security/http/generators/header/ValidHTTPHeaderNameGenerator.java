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
 * Generator for valid HTTP header names.
 * 
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic HTTP header patterns.
 * 
 * Provides common standard and custom header name examples for testing.
 */
public class ValidHTTPHeaderNameGenerator implements TypedGenerator<String> {

    // Core generation parameters
    private final TypedGenerator<String> standardHeaders = Generators.fixedValues("Authorization", "Content-Type", "User-Agent", "Host");
    private final TypedGenerator<String> acceptHeaders = Generators.fixedValues("Accept", "Accept-Language", "Accept-Encoding");
    private final TypedGenerator<String> contentHeaders = Generators.fixedValues("Content-Length", "Content-Encoding", "Cache-Control");
    private final TypedGenerator<String> customPrefixes = Generators.fixedValues("X-", "X-Custom-", "X-API-", "X-Requested-");
    private final TypedGenerator<String> customSuffixes = Generators.fixedValues("Key", "With", "For", "Header-Name");
    private final TypedGenerator<String> cookieHeaders = Generators.fixedValues("Cookie", "Set-Cookie");
    private final TypedGenerator<String> navigationHeaders = Generators.fixedValues("Origin", "Referer", "Location");
    private final TypedGenerator<String> connectionHeaders = Generators.fixedValues("Connection", "Keep-Alive", "Upgrade");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();

    @Override
    public String next() {
        int headerType = Generators.integers(0, 6).next();
        return switch (headerType) {
            case 0 -> standardHeaders.next();
            case 1 -> acceptHeaders.next();
            case 2 -> contentHeaders.next();
            case 3 -> generateCustomHeader();
            case 4 -> cookieHeaders.next();
            case 5 -> navigationHeaders.next();
            case 6 -> connectionHeaders.next();
            default -> standardHeaders.next();
        };
    }

    private String generateCustomHeader() {
        String prefix = customPrefixes.next();
        String suffix = customSuffixes.next();

        // Sometimes add a middle part for variety
        if (contextSelector.next()) {
            String[] middleParts = {"Request", "Response", "Client", "Server", "Auth", "Session"};
            String middle = middleParts[Generators.integers(0, middleParts.length - 1).next()];
            return prefix + middle + "-" + suffix;
        }

        return prefix + suffix;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}