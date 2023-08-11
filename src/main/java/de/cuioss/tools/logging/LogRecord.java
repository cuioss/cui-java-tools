
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
package de.cuioss.tools.logging;

import java.util.function.Supplier;

/**
 * Provides additional information for simplifying logging
 *
 * @author Oliver Wolff
 *
 */
public interface LogRecord {

    /**
     * @return the prefix for identifying the log-entry, e.g. 'CUI'
     */
    String getPrefix();

    /**
     * @return the identifier for the concrete entry, e.g. '100'
     */
    Integer getIdentifier();

    /**
     * @return The message template for creating the log-message
     */
    String getTemplate();

    /**
     * Returns a {@link Supplier} view on the formatter
     *
     * @param parameter optional, used for filling the template
     * @return a {@link Supplier} view on the formatter
     */
    Supplier<String> supplier(Object... parameter);

    /**
     * Formats the template with the given object. <em>Important:</em> it implicitly
     * prepends the identifier, e.g. "CUI-100: " in front of the created message.
     *
     * @param parameter optional, used for filling the template
     * @return the formated String.
     */
    String format(Object... parameter);

    /**
     * @return the concatenated identifier String, e.g. CUI-100
     */
    String resolveIdentifierString();

}
