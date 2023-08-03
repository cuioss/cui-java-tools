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
package de.cuioss.tools.string;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.collect.MoreCollections.isEmpty;
import static de.cuioss.tools.string.MoreStrings.isBlank;
import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.stream.Collectors;

import de.cuioss.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Inspired by Googles Joiner.
 * <p>
 * It uses internally the {@link String#join(CharSequence, Iterable)}
 * implementation of java and provides a guava like wrapper. It focuses on the
 * simplified Joining and omits the Map based variants.
 * </p>
 * <h2>Usage</h2>
 *
 * <pre>
 * assertEquals("key=value", Joiner.on('=').join("key", "value"));
 * assertEquals("key=no value", Joiner.on('=').useForNull("no value").join("key", null));
 * assertEquals("key", Joiner.on('=').skipNulls().join("key", null));
 * assertEquals("key", Joiner.on('=').skipEmptyStrings().join("key", ""));
 * assertEquals("key", Joiner.on('=').skipBlankStrings().join("key", " "));
 * </pre>
 *
 * <h2>Migrating from Guava</h2>
 * <p>
 * In order to migrate for most case you only need to replace the package name
 * on the import.
 * </p>
 * <h2>Changes to Guavas-Joiner</h2>
 * <p>
 * In case of content to be joined containing {@code null}-values and not set to
 * skip nulls, {@link #skipNulls()} it does not throw an
 * {@link NullPointerException} but writes "null" for each {@code null} element.
 * You can define a different String by calling {@link #useForNull(String)}
 * </p>
 * <p>
 * In addition to {@link #skipEmptyStrings()} it provides a variant
 * {@link #skipBlankStrings()}
 * </p>
 *
 * @author Oliver Wolff
 *
 */
@RequiredArgsConstructor(access = AccessLevel.MODULE)
public final class Joiner {

    private static final CuiLogger log = new CuiLogger(Joiner.class);

    @NonNull
    private final JoinerConfig joinerConfig;

    /**
     * Returns a Joiner that uses the given fixed string as a separator. For
     * example, {@code
     * Joiner.on("-").join("foo", "bar")} returns a String "foo-bar"
     *
     * @param separator the literal, nonempty string to recognize as a separator
     *
     * @return a {@link Joiner}, with default settings, that uses that separator
     */
    public static Joiner on(final String separator) {
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
    public static Joiner on(final char separator) {
        requireNonNull(separator);
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
        log.trace("Joining elements with configuration {}", joinerConfig);
        if (isEmpty(parts)) {
            return "";
        }
        var builder = new ArrayList<CharSequence>();
        for (Object element : parts) {
            if (null == element) {
                if (!joinerConfig.isSkipNulls()) {
                    builder.add(joinerConfig.getUseForNull());
                }
            } else if (element instanceof CharSequence) {
                builder.add((CharSequence) element);
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
