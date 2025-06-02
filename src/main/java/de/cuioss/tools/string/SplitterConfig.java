/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
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

import java.util.regex.Pattern;

/**
 * Configuration class for the {@link Splitter} utility, providing a flexible way to
 * customize string splitting behavior. This class uses the builder pattern via Lombok
 * to create immutable configurations.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Configurable separator string or pattern</li>
 *   <li>Empty string handling</li>
 *   <li>Result trimming options</li>
 *   <li>Split limit control</li>
 *   <li>Separator string modification control</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Basic configuration
 * SplitterConfig config1 = SplitterConfig.builder()
 *     .separator(",")
 *     .build();
 *
 * // Advanced configuration
 * SplitterConfig config2 = SplitterConfig.builder()
 *     .separator("\\s*,\\s*")  // Split on comma with optional whitespace
 *     .omitEmptyStrings(true)
 *     .trimResults(true)
 *     .maxItems(3)             // Limit to 3 splits
 *     .build();
 *
 * // Raw separator configuration
 * SplitterConfig config3 = SplitterConfig.builder()
 *     .separator("[,.]")       // Split on comma or period
 *     .doNotModifySeparatorString(true)  // Use separator as-is
 *     .build();
 * </pre>
 *
 * @author Oliver Wolff
 * @see Splitter
 * @see Pattern
 */
@RequiredArgsConstructor(staticName = "of")
@Getter
@EqualsAndHashCode
@ToString
class SplitterConfig {
    private final String separator;
    private final Pattern pattern;
    private final boolean omitEmptyStrings;
    private final boolean trimResults;
    private final int maxItems;
    private final boolean doNotModifySeparatorString;

    /**
     * Builder for {@link SplitterConfig}.
     * Use the fluent API to configure and call {@link #build()} to create an immutable config.
     */
    static class Builder {
        private String separator;
        private boolean omitEmptyStrings = false;
        private boolean trimResults = false;
        private int maxItems = 0;
        private boolean doNotModifySeparatorString = false;
        private Pattern pattern;

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
         * Whether to omit empty strings from the result.
         * @param omitEmptyStrings true to omit empty strings
         * @return this builder
         */
        Builder omitEmptyStrings(boolean omitEmptyStrings) {
            this.omitEmptyStrings = omitEmptyStrings;
            return this;
        }

        /**
         * Whether to trim results.
         * @param trimResults true to trim results
         * @return this builder
         */
        Builder trimResults(boolean trimResults) {
            this.trimResults = trimResults;
            return this;
        }

        /**
         * Sets the maximum number of items to split.
         * @param maxItems the split limit
         * @return this builder
         */
        Builder maxItems(int maxItems) {
            this.maxItems = maxItems;
            return this;
        }

        /**
         * Whether to use the separator string as-is.
         * @param doNotModifySeparatorString true to use as-is
         * @return this builder
         */
        Builder doNotModifySeparatorString(boolean doNotModifySeparatorString) {
            this.doNotModifySeparatorString = doNotModifySeparatorString;
            return this;
        }

        /**
         * Sets the pattern to use for splitting.
         * @param pattern the regex pattern
         * @return this builder
         */
        Builder pattern(Pattern pattern) {
            this.pattern = pattern;
            return this;
        }

        /**
         * Builds the immutable {@link SplitterConfig} instance.
         * @return a new config
         */
        SplitterConfig build() {
            return SplitterConfig.of(separator, pattern, omitEmptyStrings, trimResults, maxItems, doNotModifySeparatorString);
        }
    }

    /**
     * Creates a new builder for {@link SplitterConfig}.
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
                .omitEmptyStrings(isOmitEmptyStrings())
                .trimResults(isTrimResults())
                .maxItems(getMaxItems())
                .doNotModifySeparatorString(isDoNotModifySeparatorString())
                .pattern(getPattern());
    }
}
