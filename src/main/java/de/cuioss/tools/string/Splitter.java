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

import de.cuioss.tools.collect.CollectionBuilder;
import de.cuioss.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

/**
 * A string splitting utility inspired by Google Guava's Splitter, providing a more
 * straightforward and efficient implementation based on Java's native {@link String#split(String)}.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>RegEx-based splitting with simple configuration</li>
 *   <li>Options to trim results and omit empty strings</li>
 *   <li>Limit control for split results</li>
 *   <li>Fluent builder-style API</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Basic Splitting</h3>
 * <pre>
 * // Split on a string delimiter
 * List&lt;String&gt; result1 = Splitter.on(", ").splitToList("foo, bar, baz");
 * // result1 = ["foo", "bar", "baz"]
 *
 * // Split on a single character
 * List&lt;String&gt; result2 = Splitter.on(',').splitToList("a,b,c");
 * // result2 = ["a", "b", "c"]
 * </pre>
 *
 * <h3>2. Handling Empty and Null Values</h3>
 * <pre>
 * // Omit empty strings from results
 * List&lt;String&gt; result = Splitter.on(',')
 *     .omitEmptyStrings()
 *     .splitToList("a,,c");
 * // result = ["a", "c"]
 * </pre>
 *
 * <h3>3. Trimming Results</h3>
 * <pre>
 * // Trim whitespace from results
 * List&lt;String&gt; result = Splitter.on(',')
 *     .trimResults()
 *     .splitToList(" a , b , c ");
 * // result = ["a", "b", "c"]
 * </pre>
 *
 * <h2>Implementation Notes</h2>
 * <ul>
 *   <li>Uses Java's {@link String#split(String)} internally for efficient splitting</li>
 *   <li>Processes the entire string at once (eager splitting) unlike Guava's lazy approach</li>
 *   <li>Focuses on RegEx-based splitting, omitting fixed-length and map-based variants</li>
 * </ul>
 *
 * <h2>Migrating from Guava</h2>
 * <ol>
 *   <li>Update imports from {@code com.google.common.base.Splitter} to {@code de.cuioss.tools.string.Splitter}</li>
 *   <li>Replace {@code split()} calls with {@link #splitToList(String)}</li>
 *   <li>Note the different behavior of {@link #limit(int)} when used with {@link #trimResults()} or {@link #omitEmptyStrings()}:
 *     <ul>
 *       <li>This implementation applies limit first, then trim/omit</li>
 *       <li>Guava applies trim/omit first, then limit</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * @author Oliver Wolff
 * @see String#split(String)
 * @see Pattern
 * @see SplitterConfig
 */
@RequiredArgsConstructor(access = AccessLevel.MODULE)
public final class Splitter {

    private static final CuiLogger log = new CuiLogger(Splitter.class);

    @NonNull
    private final SplitterConfig splitterConfig;

    /**
     * Creates a splitter that uses the given character as a separator pattern.
     * The character is automatically escaped if it has special meaning in regex.
     *
     * <pre>
     * Splitter.on(',').splitToList("a,b,c")     = ["a", "b", "c"]
     * Splitter.on('.').splitToList("a.b.c")     = ["a", "b", "c"]  // '.' is escaped
     * </pre>
     *
     * @param separator the character to use as a separator, must not be null
     * @return a new {@link Splitter} instance configured with the given separator
     * @throws NullPointerException if separator is null
     */
    public static Splitter on(final char separator) {
        requireNonNull(separator, "separator must not be null");
        var separatorStr = String.valueOf(separator);
        return new Splitter(SplitterConfig.builder()
                .separator(separatorStr)
                .pattern(Pattern.compile(Pattern.quote(separatorStr)))
                .build());
    }

    /**
     * Creates a splitter that uses the given string as a separator pattern.
     * The string will be treated as a literal pattern, not a regular expression.
     *
     * <pre>
     * // Split on a string
     * Splitter.on(",").splitToList("a,b,c")     = ["a", "b", "c"]
     * Splitter.on(", ").splitToList("a, b, c")  = ["a", "b", "c"]
     * </pre>
     *
     * @param separator the string to use as a separator, must not be null
     * @return a new {@link Splitter} instance configured with the given separator
     * @throws NullPointerException if separator is null
     * @throws IllegalArgumentException if separator is empty
     */
    public static Splitter on(final String separator) {
        requireNonNull(separator, "separator must not be null");
        if (separator.isEmpty()) {
            throw new IllegalArgumentException("separator must not be empty");
        }
        return new Splitter(SplitterConfig.builder()
                .separator(separator)
                .pattern(Pattern.compile(Pattern.quote(separator)))
                .build());
    }

    /**
     * Creates a splitter that uses the given regular expression pattern as a separator.
     * This is useful for more complex splitting requirements.
     *
     * <pre>
     * // Split on whitespace
     * Splitter.on(Pattern.compile("\\s+")).splitToList("a b   c")  = ["a", "b", "c"]
     *
     * // Split on word boundaries
     * Splitter.on(Pattern.compile("\\b")).splitToList("foo:bar")   = ["foo", ":", "bar"]
     * </pre>
     *
     * @param separatorPattern the pattern to use for splitting, must not be null
     * @return a new {@link Splitter} instance configured with the given pattern
     * @throws NullPointerException if separatorPattern is null
     */
    public static Splitter on(final Pattern separatorPattern) {
        requireNonNull(separatorPattern, "separatorPattern must not be null");
        return new Splitter(SplitterConfig.builder()
                .separator(separatorPattern.pattern())
                .pattern(separatorPattern)
                .build());
    }

    /**
     * Sets a limit on the number of splits to be performed.
     * After the limit is reached, the remainder of the string is treated as the final element.
     *
     * <pre>
     * Basic limit usage
     * Splitter.on(',').limit(2).splitToList("a,b,c")      = ["a", "b,c"]
     * Splitter.on(',').limit(3).splitToList("a,b,c,d")    = ["a", "b", "c,d"]
     *
     * Limit with empty strings
     * Splitter.on(',').limit(2).splitToList("a,,c")       = ["a", ",c"]
     * </pre>
     *
     * @param limit the maximum number of splits to perform, must be greater than 0
     * @return this {@link Splitter} instance for method chaining
     * @throws IllegalArgumentException if limit is not positive
     */
    public Splitter limit(final int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than 0");
        }
        var newConfig = splitterConfig.copy()
                .maxItems(limit)
                .pattern(splitterConfig.getPattern())
                .build();
        return new Splitter(newConfig);
    }

    /**
     * Configures this splitter to trim whitespace from the beginning and end of each result.
     * Whitespace is defined by {@link String#trim()}.
     *
     * <pre>
     * Basic trimming
     * Splitter.on(',').trimResults().splitToList(" a , b ")   = ["a", "b"]
     *
     * Trimming with empty strings
     * Splitter.on(',').trimResults().splitToList("a, ,c")     = ["a", "", "c"]
     * </pre>
     *
     * @return this {@link Splitter} instance for method chaining
     * @see String#trim()
     */
    public Splitter trimResults() {
        var newConfig = splitterConfig.copy()
                .trimResults(true)
                .pattern(splitterConfig.getPattern())
                .build();
        return new Splitter(newConfig);
    }

    /**
     * Configures this splitter to skip empty strings in the results.
     * An empty string is defined as a string of length zero.
     *
     * <pre>
     * Basic empty string omission
     * Splitter.on(',').omitEmptyStrings().splitToList("a,,c")     = ["a", "c"]
     *
     * With trimming
     * Splitter.on(',').trimResults().omitEmptyStrings()
     *     .splitToList("a, ,c")                                    = ["a", "c"]
     * </pre>
     *
     * @return this {@link Splitter} instance for method chaining
     */
    public Splitter omitEmptyStrings() {
        var newConfig = splitterConfig.copy()
                .omitEmptyStrings(true)
                .pattern(splitterConfig.getPattern())
                .build();
        return new Splitter(newConfig);
    }

    /**
     * Configures this splitter to use the separator string as a literal pattern without escaping special regex characters.
     * This is useful when you want to split on a regular expression pattern.
     *
     * <pre>
     * Without doNotModifySeparatorString()
     * Splitter.on("[").splitToList("[a][b]")      // Throws IllegalArgumentException
     *
     * With doNotModifySeparatorString()
     * Splitter.on("[").doNotModifySeparatorString().splitToList("[a][b]")  = ["", "a", "[b]"]
     * </pre>
     *
     * @return a new {@link Splitter} instance with the same configuration but with doNotModifySeparatorString set to true
     */
    public Splitter doNotModifySeparatorString() {
        var separator = splitterConfig.getSeparator();
        var newConfig = splitterConfig.copy()
                .doNotModifySeparatorString(true)
                .pattern(Pattern.compile(Pattern.quote(separator)))
                .build();
        return new Splitter(newConfig);
    }

    /**
     * Splits {@code sequence} into string components and returns them as an
     * immutable list.
     *
     * @param sequence the sequence of characters to split
     *
     * @return an immutable list of the segments split from the parameter
     */
    @SuppressWarnings("java:S5852") // owolff:
    // This is a false positive,
    // because the splitter-separator is coded / configured value,
    // no user-payload
    public List<String> splitToList(String sequence) {
        if (null == sequence) {
            return Collections.emptyList();
        }
        if (splitterConfig.isDoNotModifySeparatorString() &&
                splitterConfig.getSeparator().matches(".*[\\[\\]\\{\\}\\(\\)\\*\\+\\?\\^\\$\\|\\\\].*")) {
            throw new IllegalArgumentException("Invalid regex pattern: " + splitterConfig.getSeparator());
        }
        log.trace("Splitting String {} with configuration {}", sequence, splitterConfig);
        if (isEmpty(sequence)) {
            return Collections.emptyList();
        }

        var pattern = splitterConfig.getPattern();
        if (pattern == null) {
            pattern = Pattern.compile(Pattern.quote(splitterConfig.getSeparator()));
        }

        var splitted = sequence.split(pattern.pattern(), splitterConfig.getMaxItems());
        if (0 == splitted.length) {
            log.trace("No content to be returned for input {} and configuration {}", sequence, splitterConfig);
            return Collections.emptyList();
        }

        var builder = new CollectionBuilder<String>();
        for (String element : splitted) {
            addIfApplicable(builder, element);
        }
        return builder.toImmutableList();
    }

    private void addIfApplicable(CollectionBuilder<String> builder, String element) {
        if (null == element) {
            return;
        }
        var toDo = element;
        if (splitterConfig.isTrimResults()) {
            toDo = toDo.trim();
        }
        if (!splitterConfig.isOmitEmptyStrings() || !toDo.isEmpty()) {
            builder.add(toDo);
        }
    }
}
