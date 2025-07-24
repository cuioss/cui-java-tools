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
package de.cuioss.tools.formatting.template;

import lombok.Data;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static de.cuioss.tools.string.MoreStrings.isEmpty;

/**
 * Example implementation of FormatterSupport
 */
@Data
public class WrongDataObject implements FormatterSupport {

    private String firstName;

    private String lastName;

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        Map<String, Serializable> map = new HashMap<>();
        addIfNotNull(map, "firstName", firstName);
        addIfNotNull(map, "lastName", lastName);
        return map;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        final List<String> result = new ArrayList<>();
        final var fields = this.getClass().getDeclaredFields();
        for (final Field field : fields) {
            result.add(field.getName());
        }
        return result;
    }

    private static void addIfNotNull(final Map<String, Serializable> map, final String key, final String value) {
        if (!isEmpty(value)) {
            map.put(key, value);
        }
    }
}
