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
package de.cuioss.http.security.generators.body;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid HTTP body content.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.
 * QI-17: Replaced .repeat(1000) with realistic content length generation.</p>
 *
 * <p>Provides various body content formats for testing validation including:
 * JSON, XML, form data, plain text, UTF-8 content, numbers, and structured data.</p>
 */
public class ValidHTTPBodyContentGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> contentTypeSelector = Generators.integers(1, 8);
    private final TypedGenerator<String> nameGenerator = Generators.letterStrings(3, 12);
    private final TypedGenerator<String> valueGenerator = Generators.letterStrings(5, 20);
    private final TypedGenerator<Integer> ageGenerator = Generators.integers(18, 80);
    private final TypedGenerator<Integer> citySelector = Generators.integers(1, 8);
    private final TypedGenerator<String> numberGenerator = Generators.letterStrings(5, 15);

    // QI-17: Replace .repeat(1000) with realistic long content
    private final TypedGenerator<String> longContentGenerator = Generators.letterStrings(800, 1200);

    @Override
    public String next() {
        return switch (contentTypeSelector.next()) {
            case 1 -> generateJsonContent();
            case 2 -> generateXmlContent();
            case 3 -> generateFormDataContent();
            case 4 -> generatePlainTextContent();
            case 5 -> generateUtf8Content();
            case 6 -> generateNumericContent();
            case 7 -> generateLongContent();
            case 8 -> generateStructuredContent();
            default -> generatePlainTextContent();
        };
    }

    private String generateJsonContent() {
        String name = nameGenerator.next();
        int age = ageGenerator.next();
        return "{\"user\":{\"name\":\"" + name + "\",\"age\":" + age + "}}";
    }

    private String generateXmlContent() {
        String name = nameGenerator.next();
        int age = ageGenerator.next();
        return "<root><user name=\"" + name + "\" age=\"" + age + "\"/></root>";
    }

    private String generateFormDataContent() {
        String name = nameGenerator.next();
        int age = ageGenerator.next();
        String city = generateCity();
        return "name=" + name + "&age=" + age + "&city=" + city.replace(" ", "+");
    }

    private String generateCity() {
        return switch (citySelector.next()) {
            case 1 -> "New York";
            case 2 -> "London";
            case 3 -> "Tokyo";
            case 4 -> "Paris";
            case 5 -> "Berlin";
            case 6 -> "Sydney";
            case 7 -> "Toronto";
            case 8 -> "Moscow";
            default -> "London";
        };
    }

    private String generatePlainTextContent() {
        return "Simple " + valueGenerator.next() + " text content";
    }

    private String generateUtf8Content() {
        String base = valueGenerator.next();
        return "Content with UTF-8: " + base + " café naïve résumé";
    }

    private String generateNumericContent() {
        return numberGenerator.next();
    }

    private String generateLongContent() {
        // QI-17: Dynamic long content instead of .repeat(1000)
        return longContentGenerator.next();
    }

    private String generateStructuredContent() {
        String name = nameGenerator.next();
        int age = ageGenerator.next();
        return "{\"data\": {\"user\": \"" + name + "\", \"age\": " + age + ", \"status\": \"ok\"}}";
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}