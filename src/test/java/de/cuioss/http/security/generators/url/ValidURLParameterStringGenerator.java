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
package de.cuioss.http.security.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid URL parameter values.
 * Provides common valid parameter VALUES (not full "name=value" strings) for testing.
 * These values should ALWAYS pass URLParameterValidationPipeline validation.
 *
 * QI-6: Converted from fixedValues() to dynamic generation for improved test diversity.
 */
public class ValidURLParameterStringGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components - all seed-based, no internal state
    private final TypedGenerator<Integer> parameterTypeSelector = Generators.integers(1, 8);
    private final TypedGenerator<Integer> wordSelector = Generators.integers(1, 8);
    private final TypedGenerator<Integer> formatSelector = Generators.integers(1, 6);
    private final TypedGenerator<Integer> languageSelector = Generators.integers(1, 6);
    private final TypedGenerator<Integer> statusSelector = Generators.integers(1, 6);
    private final TypedGenerator<Integer> emailNameSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> emailDomainSelector = Generators.integers(1, 3);

    @Override
    public String next() {
        return switch (parameterTypeSelector.next()) {
            case 1 -> generateNumericValue();
            case 2 -> generateEncodedText();
            case 3 -> generateSimpleText();
            case 4 -> generateBooleanLike();
            case 5 -> generateTimestamp();
            case 6 -> generateAlphanumericId();
            case 7 -> generateEncodedEmail();
            case 8 -> generatePhone();
            default -> throw new IllegalStateException("Invalid parameter type");
        };
    }

    private String generateNumericValue() {
        TypedGenerator<Integer> numbers = Generators.integers(1, 1000);
        return String.valueOf(numbers.next());
    }

    private String generateEncodedText() {
        return generateWord() + "%20" + generateWord(); // URL encoded space
    }

    private String generateSimpleText() {
        return generateWord();
    }

    private String generateBooleanLike() {
        return generateStatus();
    }

    private String generateTimestamp() {
        TypedGenerator<Long> timestamps = Generators.longs(1640995200L, 1700000000L);
        return String.valueOf(timestamps.next());
    }

    private String generateAlphanumericId() {
        TypedGenerator<String> alphanumeric = Generators.letterStrings(3, 6);
        TypedGenerator<Integer> numbers = Generators.integers(100, 999);
        return alphanumeric.next() + numbers.next();
    }

    private String generateEncodedEmail() {
        String name = generateEmailName();
        String domain = generateEmailDomain();
        return name + "%40" + domain; // URL encoded @
    }

    private String generatePhone() {
        TypedGenerator<Integer> area = Generators.integers(100, 999);
        TypedGenerator<Integer> exchange = Generators.integers(100, 999);
        TypedGenerator<Integer> number = Generators.integers(1000, 9999);
        return area.next() + "-" + exchange.next() + "-" + number.next();
    }

    private String generateWord() {
        return switch (wordSelector.next()) {
            case 1 -> "product";
            case 2 -> "user";
            case 3 -> "order";
            case 4 -> "item";
            case 5 -> "data";
            case 6 -> "content";
            case 7 -> "info";
            case 8 -> "system";
            default -> "product";
        };
    }

    private String generateFormat() {
        return switch (formatSelector.next()) {
            case 1 -> "json";
            case 2 -> "xml";
            case 3 -> "csv";
            case 4 -> "txt";
            case 5 -> "pdf";
            case 6 -> "html";
            default -> "json";
        };
    }

    private String generateLanguage() {
        return switch (languageSelector.next()) {
            case 1 -> "en";
            case 2 -> "de";
            case 3 -> "fr";
            case 4 -> "es";
            case 5 -> "it";
            case 6 -> "pt";
            default -> "en";
        };
    }

    private String generateStatus() {
        return switch (statusSelector.next()) {
            case 1 -> "true";
            case 2 -> "false";
            case 3 -> "yes";
            case 4 -> "no";
            case 5 -> "on";
            case 6 -> "off";
            default -> "true";
        };
    }

    private String generateEmailName() {
        return switch (emailNameSelector.next()) {
            case 1 -> "john";
            case 2 -> "jane";
            case 3 -> "mike";
            case 4 -> "sara";
            default -> "john";
        };
    }

    private String generateEmailDomain() {
        return switch (emailDomainSelector.next()) {
            case 1 -> "example.com";
            case 2 -> "test.org";
            case 3 -> "demo.net";
            default -> "example.com";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}