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

import de.cuioss.tools.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

/**
 * Simple String token, this token returns always his value on
 * {@linkplain #substituteAttribute(FormatterSupport)}
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
public class StringToken implements Token {

    private static final long serialVersionUID = 6377388001925442782L;

    @NonNull
    private final String value;

    /**
     * returns always stored string value
     */
    @Override
    public String substituteAttribute(final FormatterSupport content) {
        return value;
    }

    @Override
    public boolean isStringToken() {
        return true;
    }

}
