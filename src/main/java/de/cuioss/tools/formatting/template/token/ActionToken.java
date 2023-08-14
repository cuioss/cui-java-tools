/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.formatting.template.token;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import de.cuioss.tools.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * String Action Token store template and attribute name, and replace attribute
 * with his value inside the template on execution of
 * {@linkplain #substituteAttribute(FormatterSupport)}
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
public class ActionToken implements Token {

    private static final long serialVersionUID = -6329721490557755853L;

    private final String before;

    private final String attribute;

    private final String after;

    /**
     * @param template
     * @param token
     */
    public ActionToken(final String template, final String token) {
        checkArgument(template.contains(token), "'" + template + " must contain '" + token + "'");
        final List<String> splitted = Arrays.asList(template.split(token));
        before = extractSurrounding(splitted, 0);
        attribute = token;
        after = extractSurrounding(splitted, 1);
    }

    private static String extractSurrounding(final List<String> splitted, final int index) {
        var result = "";
        if (!splitted.isEmpty() && splitted.size() > index) {
            result = splitted.get(index);
        }
        return result;
    }

    @Override
    public String substituteAttribute(final FormatterSupport content) {
        requireNonNull(content, "Content must not be null. ");
        final Map<String, Serializable> attributeValues = requireNonNull(content.getAvailablePropertyValues(),
                "AvailablePropertyValues must not be null. ");
        final var result = new StringBuilder();
        if (attributeValues.containsKey(attribute)) {
            if (attributeValues.keySet().size() > 1) {
                result.append(before).append(attributeValues.get(attribute)).append(after);
            } else {
                // special case : if only one value exists no stored before + after are needed
                result.append(attributeValues.get(attribute).toString());
            }
        }
        return result.toString();
    }

    @Override
    public boolean isStringToken() {
        return false;
    }

}
