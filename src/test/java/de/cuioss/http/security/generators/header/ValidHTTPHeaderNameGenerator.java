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
 * Generator for valid HTTP header names.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic HTTP header patterns.
 *
 * Provides common standard and custom header name examples for testing.
 */
public class ValidHTTPHeaderNameGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> headerTypeGen = Generators.integers(1, 7);
    private final TypedGenerator<Integer> standardHeaderGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> acceptHeaderGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> contentHeaderGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> cookieHeaderGen = Generators.integers(1, 2);
    private final TypedGenerator<Integer> navigationHeaderGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> connectionHeaderGen = Generators.integers(1, 3);
    private final TypedGenerator<Boolean> customVariationGen = Generators.booleans();

    @Override
    public String next() {
        return switch (headerTypeGen.next()) {
            case 1 -> generateStandardHeader();
            case 2 -> generateAcceptHeader();
            case 3 -> generateContentHeader();
            case 4 -> generateCustomHeader();
            case 5 -> generateCookieHeader();
            case 6 -> generateNavigationHeader();
            case 7 -> generateConnectionHeader();
            default -> generateStandardHeader();
        };
    }

    private String generateStandardHeader() {
        return switch (standardHeaderGen.next()) {
            case 1 -> "Authorization";
            case 2 -> "Content-Type";
            case 3 -> "User-Agent";
            case 4 -> "Host";
            default -> "Authorization";
        };
    }

    private String generateAcceptHeader() {
        return switch (acceptHeaderGen.next()) {
            case 1 -> "Accept";
            case 2 -> "Accept-Language";
            case 3 -> "Accept-Encoding";
            default -> "Accept";
        };
    }

    private String generateContentHeader() {
        return switch (contentHeaderGen.next()) {
            case 1 -> "Content-Length";
            case 2 -> "Content-Encoding";
            case 3 -> "Cache-Control";
            default -> "Content-Length";
        };
    }

    private String generateCookieHeader() {
        return switch (cookieHeaderGen.next()) {
            case 1 -> "Cookie";
            case 2 -> "Set-Cookie";
            default -> "Cookie";
        };
    }

    private String generateNavigationHeader() {
        return switch (navigationHeaderGen.next()) {
            case 1 -> "Origin";
            case 2 -> "Referer";
            case 3 -> "Location";
            default -> "Origin";
        };
    }

    private String generateConnectionHeader() {
        return switch (connectionHeaderGen.next()) {
            case 1 -> "Connection";
            case 2 -> "Keep-Alive";
            case 3 -> "Upgrade";
            default -> "Connection";
        };
    }

    private String generateCustomHeader() {
        String prefix = generateCustomPrefix();
        String suffix = generateCustomSuffix();

        // Sometimes add a middle part for variety
        if (customVariationGen.next()) {
            String middle = generateMiddlePart();
            return prefix + middle + "-" + suffix;
        }

        return prefix + suffix;
    }

    private String generateCustomPrefix() {
        int type = Generators.integers(1, 4).next();
        return switch (type) {
            case 1 -> "X-";
            case 2 -> "X-Custom-";
            case 3 -> "X-API-";
            case 4 -> "X-Requested-";
            default -> "X-";
        };
    }

    private String generateCustomSuffix() {
        int type = Generators.integers(1, 4).next();
        return switch (type) {
            case 1 -> "Key";
            case 2 -> "With";
            case 3 -> "For";
            case 4 -> "Header-Name";
            default -> "Key";
        };
    }

    private String generateMiddlePart() {
        int type = Generators.integers(1, 6).next();
        return switch (type) {
            case 1 -> "Request";
            case 2 -> "Response";
            case 3 -> "Client";
            case 4 -> "Server";
            case 5 -> "Auth";
            case 6 -> "Session";
            default -> "Request";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}