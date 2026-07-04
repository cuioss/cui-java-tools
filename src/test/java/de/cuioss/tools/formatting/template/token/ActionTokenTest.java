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
package de.cuioss.tools.formatting.template.token;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.tools.formatting.template.FormatterSupport;
import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@EnableGeneratorController
class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        // Use letterStrings to avoid regex special characters in token
        var token = Generators.letterStrings(5, 10).next();
        var template = "prefix" + token + "suffix";
        ObjectMethodsAsserts.assertNiceObject(new ActionToken(template, token));
    }

    @Test
    void shouldTreatAttributeNameAsLiteralNotAsRegex() {
        // '[a+b]' as a regex would be a character class, as a literal it is the attribute name
        var actionToken = new ActionToken("<[a+b]>", "[a+b]");
        assertEquals("<value>", actionToken.substituteAttribute(new MapBasedFormatterSupport("[a+b]", "value")));
    }

    @Test
    void shouldFailOnTemplateNotContainingToken() {
        assertThrows(IllegalArgumentException.class, () -> new ActionToken("someTemplate", "missing"));
    }

    private static class MapBasedFormatterSupport implements FormatterSupport {

        private final Map<String, Serializable> values = new HashMap<>();

        MapBasedFormatterSupport(final String attribute, final String value) {
            values.put(attribute, value);
            // second value in order to bypass the single-value special case
            values.put("other", "otherValue");
        }

        @Override
        public Map<String, Serializable> getAvailablePropertyValues() {
            return values;
        }

        @Override
        public List<String> getSupportedPropertyNames() {
            return List.copyOf(values.keySet());
        }
    }

}
