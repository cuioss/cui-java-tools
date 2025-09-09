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
import de.cuioss.tools.security.http.data.URLParameter;

/**
 * Generates legitimate URLParameter records for testing valid parameter handling.
 * 
 * This generator produces only valid, legitimate URL parameter patterns that should be
 * accepted by security validation systems. It complements AttackURLParameterGenerator
 * which generates malicious patterns.
 * 
 * FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).
 * 
 * Implements: Task G7 (Valid Cases) from HTTP verification specification
 */
public class ValidURLParameterGenerator implements TypedGenerator<URLParameter> {

    // Core generation parameters - all seed-based, no internal state
    private final TypedGenerator<Integer> paramTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<String> parameterCategories = Generators.fixedValues("page", "size", "sort", "filter");
    private final TypedGenerator<String> searchCategories = Generators.fixedValues("search", "category", "type", "status");
    private final TypedGenerator<String> dataCategories = Generators.fixedValues("id", "limit", "offset", "format");
    private final TypedGenerator<String> localeCategories = Generators.fixedValues("lang", "version", "timestamp");
    private final TypedGenerator<String> booleanValues = Generators.fixedValues("true", "false");
    private final TypedGenerator<String> sortValues = Generators.fixedValues("asc", "desc");
    private final TypedGenerator<String> formatValues = Generators.fixedValues("json", "xml", "csv", "html");
    private final TypedGenerator<String> languageValues = Generators.fixedValues("en", "de", "fr", "es", "ja");
    private final TypedGenerator<String> statusValues = Generators.fixedValues("active", "inactive", "pending", "deleted");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> numberValues = Generators.integers(1, 1000);

    @Override
    public URLParameter next() {
        int type = paramTypeGenerator.next();

        String name = switch (type) {
            case 0 -> generatePaginationParameterName();
            case 1 -> generateSearchParameterName();
            case 2 -> generateDataParameterName();
            case 3 -> generateLocaleParameterName();
            default -> generatePaginationParameterName();
        };

        String value = generateLegitimateValue();

        return new URLParameter(name, value);
    }

    private String generatePaginationParameterName() {
        return parameterCategories.next();
    }

    private String generateSearchParameterName() {
        return searchCategories.next();
    }

    private String generateDataParameterName() {
        return dataCategories.next();
    }

    private String generateLocaleParameterName() {
        return localeCategories.next();
    }

    private String generateLegitimateValue() {
        int valueType = Generators.integers(0, 6).next();
        return switch (valueType) {
            case 0 -> generateNumberValue();
            case 1 -> generateBooleanValue();
            case 2 -> generateSortValue();
            case 3 -> generateFormatValue();
            case 4 -> generateLanguageValue();
            case 5 -> generateStatusValue();
            case 6 -> generateTestValue();
            default -> generateNumberValue();
        };
    }

    private String generateNumberValue() {
        return String.valueOf(numberValues.next());
    }

    private String generateBooleanValue() {
        return booleanValues.next();
    }

    private String generateSortValue() {
        return sortValues.next();
    }

    private String generateFormatValue() {
        return formatValues.next();
    }

    private String generateLanguageValue() {
        return languageValues.next();
    }

    private String generateStatusValue() {
        return statusValues.next();
    }

    private String generateTestValue() {
        int testType = Generators.integers(0, 3).next();
        return switch (testType) {
            case 0 -> "test";
            case 1 -> "example";
            case 2 -> "demo";
            case 3 -> "sample";
            default -> "test";
        };
    }

    @Override
    public Class<URLParameter> getType() {
        return URLParameter.class;
    }
}