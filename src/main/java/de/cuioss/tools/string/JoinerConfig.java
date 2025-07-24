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
package de.cuioss.tools.string;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

/**
 * Configuration class for the {@link Joiner} utility, providing a flexible way to
 * customize string joining behavior. This class uses the builder pattern via Lombok
 * to create immutable configurations.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Configurable separator string</li>
 *   <li>Null value handling options</li>
 *   <li>Empty and blank string filtering</li>
 *   <li>Immutable configuration</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Basic configuration
 * JoinerConfig config1 = JoinerConfig.builder()
 *     .separator(",")
 *     .build();
 *
 * // Advanced configuration
 * JoinerConfig config2 = JoinerConfig.builder()
 *     .separator(" | ")
 *     .skipNulls(true)
 *     .skipEmpty(true)
 *     .skipBlank(true)
 *     .useForNull("N/A")
 *     .build();
 * </pre>
 *
 * @author Oliver Wolff
 * @see Joiner
 */
@EqualsAndHashCode
@ToString
@RequiredArgsConstructor
@Getter
class JoinerConfig {
    private final String separator;
    private final boolean skipNulls;
    private final boolean skipEmpty;
    private final boolean skipBlank;
    private final String useForNull;

    /**
     * Builder for {@link JoinerConfig}.
     * Use the fluent API to configure and call {@link #build()} to create an immutable config.
     */
    static class Builder {
        private String separator;
        private boolean skipNulls = false;
        private boolean skipEmpty = false;
        private boolean skipBlank = false;
        private String useForNull = "null";

        /**
         * Sets the separator string.
         * @param separator the separator to use
         * @return this builder
         */
        Builder separator(String separator) {
            this.separator = separator;
            return this;
        }

        /**
         * Whether to skip null values.
         * @param skipNulls true to skip nulls
         * @return this builder
         */
        Builder skipNulls(boolean skipNulls) {
            this.skipNulls = skipNulls;
            return this;
        }

        /**
         * Whether to skip empty strings.
         * @param skipEmpty true to skip empty strings
         * @return this builder
         */
        Builder skipEmpty(boolean skipEmpty) {
            this.skipEmpty = skipEmpty;
            return this;
        }

        /**
         * Whether to skip blank strings (whitespace only).
         * @param skipBlank true to skip blank strings
         * @return this builder
         */
        Builder skipBlank(boolean skipBlank) {
            this.skipBlank = skipBlank;
            return this;
        }

        /**
         * Sets the string to use for null values.
         * @param useForNull replacement for nulls
         * @return this builder
         */
        Builder useForNull(String useForNull) {
            this.useForNull = useForNull;
            return this;
        }

        /**
         * Builds the immutable {@link JoinerConfig} instance.
         * @return a new config
         */
        JoinerConfig build() {
            return new JoinerConfig(separator, skipNulls, skipEmpty, skipBlank, useForNull);
        }
    }

    /**
     * Creates a new builder for {@link JoinerConfig}.
     * @return a new builder
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a builder pre-populated with this config's values.
     * @return a builder with copied values
     */
    Builder copy() {
        return builder()
                .separator(getSeparator())
                .skipNulls(isSkipNulls())
                .skipEmpty(isSkipEmpty())
                .skipBlank(isSkipBlank())
                .useForNull(getUseForNull());
    }
}
