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
 * Generator for invalid HTTP header names containing control characters.
 * Provides header names with various injection and control character patterns.
 * 
 * QI-6: Converted from fixedValues() to dynamic generation for improved test diversity.
 */
public class InvalidHTTPHeaderNameGenerator implements TypedGenerator<String> {

    private final TypedGenerator<Integer> invalidTypeSelector = Generators.integers(1, 4);
    private final TypedGenerator<String> baseHeaderNames = Generators.fixedValues(
            "Authorization", "Content-Type", "Accept", "User-Agent", "Host", 
            "Referer", "Cookie", "X-Custom", "Cache-Control"
    );

    @Override
    public String next() {
        String baseName = baseHeaderNames.next();
        return switch (invalidTypeSelector.next()) {
            case 1 -> generateCarriageReturnInjection(baseName);
            case 2 -> generateLineFeedInjection(baseName);
            case 3 -> generateCRLFInjection(baseName);
            case 4 -> generateNullByteInjection(baseName);
            default -> throw new IllegalStateException("Invalid type selector");
        };
    }

    private String generateCarriageReturnInjection(String baseName) {
        return baseName + "\r" + "Injected";
    }

    private String generateLineFeedInjection(String baseName) {
        return baseName + "\n" + "Injected";
    }

    private String generateCRLFInjection(String baseName) {
        return baseName + "\r\n" + "Injected";
    }

    private String generateNullByteInjection(String baseName) {
        return baseName + "\u0000" + "Injected";
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}