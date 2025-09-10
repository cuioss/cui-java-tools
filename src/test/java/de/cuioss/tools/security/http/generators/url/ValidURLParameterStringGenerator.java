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
package de.cuioss.tools.security.http.generators.url;

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

    private final TypedGenerator<Integer> parameterTypeSelector = Generators.integers(1, 8);
    private final TypedGenerator<String> words = Generators.fixedValues(
            "product", "user", "order", "item", "data", "content", "info", "system"
    );
    private final TypedGenerator<String> formats = Generators.fixedValues(
            "json", "xml", "csv", "pdf", "txt", "html"
    );
    private final TypedGenerator<String> languages = Generators.fixedValues(
            "en", "de", "fr", "es", "it", "pt"
    );
    private final TypedGenerator<String> statuses = Generators.fixedValues(
            "active", "inactive", "pending", "enabled", "disabled", "draft"
    );

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
        return words.next() + "%20" + words.next(); // URL encoded space
    }

    private String generateSimpleText() {
        return words.next();
    }

    private String generateBooleanLike() {
        return statuses.next();
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
        TypedGenerator<String> names = Generators.fixedValues("john", "jane", "mike", "sara");
        TypedGenerator<String> domains = Generators.fixedValues("example.com", "test.org", "demo.net");
        return names.next() + "%40" + domains.next(); // URL encoded @
    }

    private String generatePhone() {
        TypedGenerator<Integer> area = Generators.integers(100, 999);
        TypedGenerator<Integer> exchange = Generators.integers(100, 999);
        TypedGenerator<Integer> number = Generators.integers(1000, 9999);
        return area.next() + "-" + exchange.next() + "-" + number.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}