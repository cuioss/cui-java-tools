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
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 * 
 * This generator produces only valid, legitimate URL parameter patterns that should be
 * accepted by security validation systems. It complements AttackURLParameterGenerator
 * which generates malicious patterns.
 * 
 * Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining realistic parameter patterns.
 * 
 * FRAMEWORK COMPLIANT: Uses seed-based generation without call-counter anti-pattern.
 * Reproducibility = f(seed), not f(internal_state).
 * 
 * Implements: Task G7 (Valid Cases) from HTTP verification specification
 */
public class ValidURLParameterGenerator implements TypedGenerator<URLParameter> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> paramTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<Integer> paginationParamGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> searchParamGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> dataParamGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> localeParamGen = Generators.integers(1, 3);
    private final TypedGenerator<Integer> booleanValueGen = Generators.integers(1, 2);
    private final TypedGenerator<Integer> sortValueGen = Generators.integers(1, 2);
    private final TypedGenerator<Integer> formatValueGen = Generators.integers(1, 4);
    private final TypedGenerator<Integer> languageValueGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> statusValueGen = Generators.integers(1, 4);
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
        return switch (paginationParamGen.next()) {
            case 1 -> "page";
            case 2 -> "size";
            case 3 -> "sort";
            case 4 -> "filter";
            default -> "page";
        };
    }

    private String generateSearchParameterName() {
        return switch (searchParamGen.next()) {
            case 1 -> "search";
            case 2 -> "category";
            case 3 -> "type";
            case 4 -> "status";
            default -> "search";
        };
    }

    private String generateDataParameterName() {
        return switch (dataParamGen.next()) {
            case 1 -> "id";
            case 2 -> "limit";
            case 3 -> "offset";
            case 4 -> "format";
            default -> "id";
        };
    }

    private String generateLocaleParameterName() {
        return switch (localeParamGen.next()) {
            case 1 -> "lang";
            case 2 -> "version";
            case 3 -> "timestamp";
            default -> "lang";
        };
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
        return switch (booleanValueGen.next()) {
            case 1 -> "true";
            case 2 -> "false";
            default -> "true";
        };
    }

    private String generateSortValue() {
        return switch (sortValueGen.next()) {
            case 1 -> "asc";
            case 2 -> "desc";
            default -> "asc";
        };
    }

    private String generateFormatValue() {
        return switch (formatValueGen.next()) {
            case 1 -> "json";
            case 2 -> "xml";
            case 3 -> "csv";
            case 4 -> "html";
            default -> "json";
        };
    }

    private String generateLanguageValue() {
        return switch (languageValueGen.next()) {
            case 1 -> "en";
            case 2 -> "de";
            case 3 -> "fr";
            case 4 -> "es";
            case 5 -> "ja";
            default -> "en";
        };
    }

    private String generateStatusValue() {
        return switch (statusValueGen.next()) {
            case 1 -> "active";
            case 2 -> "inactive";
            case 3 -> "pending";
            case 4 -> "deleted";
            default -> "active";
        };
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