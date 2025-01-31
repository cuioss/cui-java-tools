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
@Builder
@EqualsAndHashCode
@ToString
@SuppressWarnings("squid:S1170")
// Sonar doesn't recognize Lombok's @Builder.Default annotations
class JoinerConfig {

    /**
     * The string used to join elements together.
     * This is a required field and must be set in the builder.
     */
    @Getter
    private final String separator;

    /**
     * Whether to skip null values during joining.
     * If true, null values are omitted from the output.
     * If false, null values are replaced with {@link #useForNull}.
     * Default is false.
     */
    @Builder.Default
    @Getter
    private final boolean skipNulls = false;

    /**
     * Whether to skip empty strings (length = 0) during joining.
     * Takes precedence over {@link #useForNull} if the value is null.
     * Default is false.
     */
    @Builder.Default
    @Getter
    private final boolean skipEmpty = false;

    /**
     * Whether to skip blank strings (empty or whitespace-only) during joining.
     * Takes precedence over both {@link #skipEmpty} and {@link #useForNull}.
     * Default is false.
     */
    @Builder.Default
    @Getter
    private final boolean skipBlank = false;

    /**
     * The string to use in place of null values when {@link #skipNulls} is false.
     * Default is "null".
     */
    @Builder.Default
    @Getter
    private final String useForNull = "null";

    /**
     * Empty class required for proper JavaDoc generation with Lombok's @Builder.
     * See <a href="https://stackoverflow.com/questions/51947791">StackOverflow discussion</a>.
     */
    @SuppressWarnings("java:S2094") // Empty class required for JavaDoc
    public static class JoinerConfigBuilder {
    }

    /**
     * Creates a new builder instance with all current configuration values.
     * Useful for creating modified copies of an existing configuration.
     *
     * @return a new builder initialized with this configuration's values
     */
    JoinerConfigBuilder copy() {
        return builder()
                .separator(getSeparator())
                .useForNull(getUseForNull())
                .skipEmpty(isSkipEmpty())
                .skipBlank(isSkipBlank())
                .skipNulls(isSkipNulls());
    }
}
