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

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

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
@Builder
@EqualsAndHashCode
@ToString
@SuppressWarnings("squid:S1170") // Sonar doesn't recognize Lombok's @Builder.Default annotations
class SplitterConfig {

    /**
     * The string or pattern used to split input strings.
     * When {@link #doNotModifySeparatorString} is false (default), special regex characters
     * will be automatically escaped.
     * This is a required field and must be set in the builder.
     */
    @Getter
    private final String separator;

    /**
     * Whether to exclude empty strings from the split results.
     * An empty string is defined as a string of length zero.
     * Default is false.
     */
    @Builder.Default
    @Getter
    private final boolean omitEmptyStrings = false;

    /**
     * Whether to trim whitespace from the beginning and end of each split result.
     * Trimming is performed using {@link String#trim()}.
     * Default is false.
     */
    @Builder.Default
    @Getter
    private final boolean trimResults = false;

    /**
     * Maximum number of splits to perform.
     * After this limit is reached, the remainder of the input string becomes the last element.
     * A value of 0 (default) means no limit.
     */
    @Builder.Default
    @Getter
    private final int maxItems = 0;

    /**
     * Whether to use the separator string as-is without escaping special regex characters.
     * When true, the separator is used directly as a regex pattern.
     * When false (default), special regex characters are escaped.
     */
    @Builder.Default
    @Getter
    private final boolean doNotModifySeparatorString = false;

    /**
     * Empty class required for proper JavaDoc generation with Lombok's @Builder.
     * See <a href="https://stackoverflow.com/questions/51947791">StackOverflow discussion</a>.
     */
    @SuppressWarnings("java:S2094") // Empty class required for JavaDoc
    public static class SplitterConfigBuilder {
    }

    /**
     * Creates a new builder instance with all current configuration values.
     * Useful for creating modified copies of an existing configuration.
     *
     * @return a new builder initialized with this configuration's values
     */
    SplitterConfigBuilder copy() {
        return builder()
                .separator(getSeparator())
                .maxItems(getMaxItems())
                .doNotModifySeparatorString(isDoNotModifySeparatorString())
                .omitEmptyStrings(isOmitEmptyStrings())
                .trimResults(isTrimResults());
    }
}
