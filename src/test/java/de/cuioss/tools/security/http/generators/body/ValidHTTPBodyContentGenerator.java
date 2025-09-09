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
package de.cuioss.tools.security.http.generators.body;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid HTTP body content.
 * Provides various body content formats for testing validation.
 */
public class ValidHTTPBodyContentGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validBodyContent = Generators.fixedValues(
            "{\"user\":{\"name\":\"John\",\"age\":30}}",
            "<root><user name=\"John\" age=\"30\"/></root>",
            "name=John&age=30&city=New+York",
            "Simple plain text content",
            "Content with\nnewlines\tand\ttabs",
            "Content with UTF-8: café naïve résumé",
            "123456789",
            "",
            "a".repeat(1000),
            "Mixed 123 content! @#$%^&*()",
            "{\"data\": {\"items\": [1, 2, 3], \"status\": \"ok\"}}",
            "<xml version=\"1.0\" encoding=\"UTF-8\"><data>test</data></xml>",
            "username=test&password=secret123&remember=true",
            "Multi-line\ncontent\nwith\nseveral\nlines",
            "Extended ASCII: àáâãäåçèéêë ñóôõöøùúûü",
            "0123456789abcdefghijklmnopqrstuvwxyz",
            "Content with 'quotes' and \"double quotes\"",
            "Whitespace    content    with    spaces",
            "JSON array: [{\"id\": 1}, {\"id\": 2}]",
            "Basic CSV: name,age,city\nJohn,30,NYC"
    );

    @Override
    public String next() {
        return validBodyContent.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}