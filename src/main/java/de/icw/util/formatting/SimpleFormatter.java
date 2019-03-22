package de.icw.util.formatting;

import static com.google.common.base.Strings.emptyToNull;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Joiner;

import lombok.Data;
import lombok.NonNull;

/**
 * Provide concatenation of strings by using {@linkplain Joiner}.<br/>
 * Furthermore formatter supports different strategies for values handling. (see
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

    /** serial version UID */
    private static final long serialVersionUID = -4761082365099064435L;

    private final String separator;

    private final ValueHandling handling;

    /**
     * Concatenate values by separator and return result inside the parentheses. Handle parameter
     * according defined ValueHandling strategy.
     *
     * @param values ellipses of string values
     * @return {@code null} if nothing to put a in parentheses
     */
    public String formatParentheses(final String... values) {
        return format(cleanUp(values));
    }

    /**
     * Concatenate values by separator according defined ValueHandling strategy.
     *
     * @param values ellipses of string values
     * @return {@code null} if nothing to concatenate
     */
    public String format(final String... values) {
        return getJoined(cleanUp(values));
    }

    private List<String> cleanUp(final String... values) {
        final List<String> result = new ArrayList<>();
        if (null != values) {
            for (final String item : values) {
                final String value = emptyToNull(item);
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
        return emptyToNull(Joiner.on(separator).skipNulls().join(values));
    }

    private String format(final List<String> values) {
        final String joined = getJoined(values);
        if (null != joined) {
            return String.format("(%s)", joined);
        }
        return null;
    }

    /**
     * Internal Builder representation
     */
    public static class Builder {

        /**
         * Use {@linkplain ValueHandling#FORMAT_IF_ALL_AVAILABLE} as value handling strategy
         *
         * @return initialized {@link BuilderWithStrategy} with defined value handling strategy
         */
        public BuilderWithStrategy skipResultIfAnyValueIsMissing() {
            return new BuilderWithStrategy(ValueHandling.FORMAT_IF_ALL_AVAILABLE);
        }

        /**
         * Use {@linkplain ValueHandling#FORMAT_IF_ANY_AVAILABLE} as value handling strategy
         *
         * @return initialized {@link BuilderWithStrategy} with defined value handling strategy
         */
        public BuilderWithStrategy ignoreMissingValues() {
            return new BuilderWithStrategy(ValueHandling.FORMAT_IF_ANY_AVAILABLE);
        }

        /**
         * Internal Builder representation incorporating s strategy
         */
        public class BuilderWithStrategy {

            private ValueHandling valueHandlingStrategy;

            protected BuilderWithStrategy(final ValueHandling strategy) {
                valueHandlingStrategy = strategy;
            }

            /**
             * Create SimpleFormatter
             *
             * @param separator must not be null
             * @return {@link SimpleFormatter} with defined value handling strategy and separator
             */
            public SimpleFormatter separatesBy(@NonNull final String separator) {
                return new SimpleFormatter(separator, valueHandlingStrategy);
            }
        }

    }
}
