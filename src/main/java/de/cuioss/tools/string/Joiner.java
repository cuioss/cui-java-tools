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

import de.cuioss.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.stream.Collectors;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.collect.MoreCollections.isEmpty;
import static de.cuioss.tools.string.MoreStrings.isBlank;
import static java.util.Objects.requireNonNull;

/**
 * A flexible string joining utility inspired by Google Guava's Joiner.
 * This implementation builds upon Java's {@link String#join(CharSequence, Iterable)}
 * while providing a more intuitive and feature-rich API.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Configurable separator (string or character)</li>
 *   <li>Flexible null value handling (skip or replace)</li>
 *   <li>Options to skip empty or blank strings</li>
 *   <li>Fluent builder-style API</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Basic Joining</h3>
 * <pre>
 * // Simple key-value joining
 * assertEquals("key=value", Joiner.on('=').join("key", "value"));
 *
 * // Join multiple values
 * assertEquals("a,b,c", Joiner.on(',').join("a", "b", "c"));
 * </pre>
 *
 * <h3>2. Null Handling</h3>
 * <pre>
 * // Replace null with custom value
 * assertEquals("key=no value", Joiner.on('=').useForNull("no value").join("key", null));
 *
 * // Skip null values entirely
 * assertEquals("key", Joiner.on('=').skipNulls().join("key", null));
 * </pre>
 *
 * <h3>3. Empty and Blank String Handling</h3>
 * <pre>
 * // Skip empty strings
 * assertEquals("key", Joiner.on('=').skipEmptyStrings().join("key", ""));
 *
 * // Skip blank strings (empty or whitespace)
 * assertEquals("key", Joiner.on('=').skipBlankStrings().join("key", " "));
 * </pre>
 *
 * <h2>Migrating from Guava</h2>
 * To migrate from Guava's Joiner:
 * <ol>
 *   <li>Update imports from {@code com.google.common.base.Joiner} to {@code de.cuioss.tools.string.Joiner}</li>
 *   <li>Review null handling - this implementation writes "null" by default instead of throwing exceptions</li>
 *   <li>Consider using new features like {@link #skipBlankStrings()} where appropriate</li>
 * </ol>
 *
 * <h2>Key Differences from Guava</h2>
 * <ul>
 *   <li>Null handling: Writes "null" by default instead of throwing {@link NullPointerException}</li>
 *   <li>Additional {@link #skipBlankStrings()} feature</li>
 *   <li>Simplified API focusing on string joining (no map support)</li>
 *   <li>Built on Java's native {@link String#join} implementation for better performance</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see String#join(CharSequence, Iterable)
 * @see JoinerConfig
 */
@RequiredArgsConstructor(access = AccessLevel.MODULE)
public final class Joiner {

    private static final CuiLogger LOGGER = new CuiLogger(Joiner.class);

    @NonNull
    private final JoinerConfig joinerConfig;

    /**
     * Creates a new Joiner that uses the given string as a separator.
     * The separator will be inserted between consecutive elements in the output.
     *
     * <pre>
     * Joiner.on("-").join("foo", "bar")      = "foo-bar"
     * Joiner.on(", ").join("a", "b", "c")    = "a, b, c"
     * </pre>
     *
     * @param separator the string to use as a separator, must not be null
     * @return a new {@link Joiner} instance configured with the given separator
     * @throws NullPointerException if separator is null
     */
    @NonNull
    public static Joiner on(@NonNull final String separator) {
        requireNonNull(separator);
        return new Joiner(JoinerConfig.builder().separator(separator).build());
    }

    /**
     * Returns a Joiner that uses the given fixed string as a separator. For
     * example, {@code
     * Joiner.on('-').join("foo", "bar")} returns a String "foo-bar"
     *
     * @param separator the literal, nonempty string to recognize as a separator
     *
     * @return a {@link Joiner}, with default settings, that uses that separator
     */
    @NonNull
    public static Joiner on(final char separator) {
        return on(String.valueOf(separator));
    }

    /**
     * @param nullText to be used as substitution for {@code null} elements
     * @return a joiner with the same behavior as this one, except automatically
     *         substituting {@code
     * nullText} for any provided null elements.
     */
    public Joiner useForNull(final String nullText) {
        return new Joiner(joinerConfig.copy().useForNull(nullText).build());
    }

    /**
     * @return a joiner with the same behavior as this one, except automatically
     *         skipping null-values
     */
    public Joiner skipNulls() {
        return new Joiner(joinerConfig.copy().skipNulls(true).build());
    }

    /**
     * @return a joiner with the same behavior as this one, except automatically
     *         skipping String-values that evaluate to an empty String
     */
    public Joiner skipEmptyStrings() {
        return new Joiner(joinerConfig.copy().skipEmpty(true).build());
    }

    /**
     * @return a joiner with the same behavior as this one, except automatically
     *         skipping String-values that evaluate to a blank String as defined
     *         within {@link MoreStrings#isBlank(CharSequence)}
     */
    public Joiner skipBlankStrings() {
        return new Joiner(joinerConfig.copy().skipBlank(true).build());
    }

    /**
     * @param parts to be joined
     *
     * @return a string containing the string representation of each of
     *         {@code parts}, using the previously configured separator between
     *         each.
     */
    public String join(Iterable<?> parts) {
        return doJoin(parts);
    }

    /**
     * @param parts to be joined
     *
     * @return a string containing the string representation of each of
     *         {@code parts}, using the previously configured separator between
     *         each.
     */
    public String join(Iterator<?> parts) {
        return doJoin(mutableList(parts));
    }

    /**
     * @param parts to be joined
     * @return a string containing the string representation of each of
     *         {@code parts}, using the previously configured separator between
     *         each.
     */
    public String join(Object... parts) {
        return doJoin(mutableList(parts));
    }

    private String doJoin(Iterable<?> parts) {
        LOGGER.debug("Joining %s elements", parts);
        if (isEmpty(parts)) {
            return "";
        }
        var builder = new ArrayList<CharSequence>();
        for (Object element : parts) {
            if (null == element) {
                if (!joinerConfig.isSkipNulls()) {
                    builder.add(joinerConfig.getUseForNull());
                }
            } else if (element instanceof CharSequence sequence) {
                builder.add(sequence);
            } else {
                builder.add(MoreStrings.lenientToString(element));
            }
        }
        if (joinerConfig.isSkipEmpty()) {
            builder = builder.stream().filter(element -> !MoreStrings.isEmpty(element))
                    .collect(Collectors.toCollection(ArrayList::new));
        }

        if (joinerConfig.isSkipBlank()) {
            builder = builder.stream().filter(element -> !isBlank(element))
                    .collect(Collectors.toCollection(ArrayList::new));
        }
        return String.join(joinerConfig.getSeparator(), builder);
    }

}
