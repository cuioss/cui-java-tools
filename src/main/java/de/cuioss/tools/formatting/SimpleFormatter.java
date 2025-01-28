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
package de.cuioss.tools.formatting;

import static de.cuioss.tools.collect.MoreCollections.isEmpty;
import static de.cuioss.tools.string.MoreStrings.emptyToNull;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Provide concatenation of strings by using
 * {@linkplain String#join(CharSequence, CharSequence...)}. Furthermore,
 * formatter supports different strategies for values handling. (see
 * {@link ValueHandling})
 *
 * @author Eugen Fischer
 */
@Data
public class SimpleFormatter implements Serializable {

    /**
     *
     */
    public enum ValueHandling {
        /**
         * Format all available data. If some are null or empty skip them silently.
         */
        FORMAT_IF_ANY_AVAILABLE,
        /**
         * Format all available data. If one of them is null or empty skip all silently.
         */
        FORMAT_IF_ALL_AVAILABLE
    }

    /**
     * serial version UID
     */
    @Serial
    private static final long serialVersionUID = -4761082365099064435L;

    private final String separator;

    private final ValueHandling handling;

    /**
     * Concatenate values by separator and return result inside the parentheses.
     * Handle parameter according defined ValueHandling strategy.
     *
     * @param values ellipses of string values
     *
     * @return {@code null} if nothing to put in parentheses
     */
    public String formatParentheses(final String... values) {
        return format(cleanUp(values));
    }

    /**
     * Concatenate values by separator according defined ValueHandling strategy.
     *
     * @param values ellipses of string values
     *
     * @return {@code null} if nothing to concatenate
     */
    public String format(final String... values) {
        return getJoined(cleanUp(values));
    }

    private List<String> cleanUp(final String... values) {
        final List<String> result = new ArrayList<>(0);
        if (null != values) {
            for (final String item : values) {
                final var value = emptyToNull(item);
                if (null == value) {
                    if (ValueHandling.FORMAT_IF_ALL_AVAILABLE.equals(handling)) {
                        result.clear();
                        break;
                    }
                } else {
                    result.add(value);
                }
            }
        }
        return result;
    }

    private String getJoined(final List<String> values) {
        if (isEmpty(values)) {
            return null;
        }
        var filtered = values.stream().filter(element -> !isEmpty(element)).toList();
        if (isEmpty(filtered)) {
            return null;
        }
        return String.join(separator, filtered);
    }

    private String format(final List<String> values) {
        final var joined = getJoined(values);
        if (null != joined) {
            return "(%s)".formatted(joined);
        }
        return null;
    }

    /**
     * @return a newly created instance of {@link SimpleFormatterBuilder}
     */
    public static SimpleFormatterBuilder builder() {
        return new SimpleFormatterBuilder();
    }

    /**
     * Internal Builder representation
     */
    @ToString
    @EqualsAndHashCode
    public static class SimpleFormatterBuilder implements Serializable {

        @Serial
        private static final long serialVersionUID = 6414005370772800008L;

        /**
         * Use {@linkplain ValueHandling#FORMAT_IF_ALL_AVAILABLE} as value handling
         * strategy
         *
         * @return initialized {@link BuilderWithStrategy} with defined value handling
         *         strategy
         */
        public BuilderWithStrategy skipResultIfAnyValueIsMissing() {
            return new BuilderWithStrategy(ValueHandling.FORMAT_IF_ALL_AVAILABLE);
        }

        /**
         * Use {@linkplain ValueHandling#FORMAT_IF_ANY_AVAILABLE} as value handling
         * strategy
         *
         * @return initialized {@link BuilderWithStrategy} with defined value handling
         *         strategy
         */
        public BuilderWithStrategy ignoreMissingValues() {
            return new BuilderWithStrategy(ValueHandling.FORMAT_IF_ANY_AVAILABLE);
        }

        /**
         * Internal Builder representation incorporating a strategy
         */
        @ToString
        @EqualsAndHashCode
        public static class BuilderWithStrategy implements Serializable {

            @Serial
            private static final long serialVersionUID = -1987354973684803562L;

            private final ValueHandling valueHandlingStrategy;

            protected BuilderWithStrategy(final ValueHandling strategy) {
                valueHandlingStrategy = strategy;
            }

            /**
             * Create SimpleFormatter
             *
             * @param separator must not be null
             *
             * @return {@link SimpleFormatter} with defined value handling strategy and
             *         separator
             */
            public SimpleFormatter separatesBy(@NonNull final String separator) {
                return new SimpleFormatter(separator, valueHandlingStrategy);
            }
        }

    }
}
