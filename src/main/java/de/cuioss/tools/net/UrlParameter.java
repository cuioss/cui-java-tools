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
package de.cuioss.tools.net;

import de.cuioss.tools.collect.CollectionBuilder;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Joiner;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.net.URLEncoder.encode;
import static java.util.Objects.requireNonNull;

/**
 * Simple wrapper around an Url Parameter Object.
 * <p>
 * Depending on the constructor arguments the attributes #getName() and
 * #getValue() are implicitly encoded properly using
 * {@link URLEncoder#encode(String, String)}. This is helpful for reliable
 * handling of special characters.
 * </p>
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode(of = {"name", "value"})
@ToString(of = {"name", "value"})
public class UrlParameter implements Serializable, Comparable<UrlParameter> {

    private static final CuiLogger LOGGER = new CuiLogger(UrlParameter.class);

    @Serial
    private static final long serialVersionUID = 634175928228707534L;

    /** The name of the parameter. */
    @Getter
    private final String name;

    /** The value of the parameter. */
    @Getter
    private final String value;

    /**
     * Flag indicating whether name and value are stored in URL-encoded form. Used
     * to prevent double-encoding when creating encoded parameter-strings.
     */
    private final boolean encoded;

    /**
     * Constructor. Name and value are implicitly encoded using UTF-8.
     *
     * @param name  must not be null or empty
     * @param value may be null.
     */
    public UrlParameter(final String name, final String value) {
        this(name, value, true);
    }

    /**
     * Constructor.
     *
     * @param name   must not be null or empty
     * @param value  value may be null.
     * @param encode indicates whether to encode the parameter name and value as
     *               UTF-8
     */
    public UrlParameter(final String name, final String value, final boolean encode) {
        requireNotEmptyTrimmed(name, "Parameter name must not be empty");
        if (encode) {
            this.name = encode(name, StandardCharsets.UTF_8);
            if (MoreStrings.isEmpty(value)) {
                this.value = null;
            } else {
                this.value = encode(value, StandardCharsets.UTF_8);
            }
        } else {
            this.name = name;
            this.value = value;
        }
        encoded = encode;
    }

    /**
     * Returns a boolean indicating whether the {@link UrlParameter} is empty,
     * saying has a null value
     *
     * @return boolean flag whether the {@link UrlParameter} is empty
     */
    public boolean isEmpty() {
        return null == value;
    }

    /**
     * Creates a parameter String for a given number of {@link UrlParameter}.
     * {@code null} elements will be skipped.
     *
     * @param parameters to be appended, may be null
     * @return the concatenated ParameterString in the form
     *         "?parameter1Name=parameter1Value&amp;parameter2Name=parameter2Value"
     */
    public static String createParameterString(final UrlParameter... parameters) {
        return createParameterString(false, parameters);
    }

    /**
     * Create a String-representation of the URL-Parameter. {@code null} elements
     * will be skipped.
     *
     * @param encode indicating whether the string elements should be encoded or not
     * @param parameters to be appended, may be null
     * @return the created parameter String
     */
    public static String createParameterString(final boolean encode, final UrlParameter... parameters) {
        final var builder = new StringBuilder();
        if (null != parameters) {
            var first = true;
            for (final UrlParameter parameter : parameters) {
                if (null == parameter) {
                    continue;
                }
                // The first parameter is prefixed with '?', the others with '&'
                builder.append(first ? '?' : '&').append(parameter.createNameValueString(encode));
                first = false;
            }
        }
        return builder.toString();
    }

    /**
     * Convert a map of raw Url-parameter into a list of {@link UrlParameter}
     *
     * @param map             containing the parameter extracted usually directly
     *                        from servlet request. From the String[] solely the
     *                        first element will be extracted. The others will be
     *                        ignored.
     * @param parameterFilter defines the parameter to be filtered. May be null or
     *                        empty.
     * @param encode          indicates whether to encode the parameter name and
     *                        value as UTF-8
     * @return the found List of {@link UrlParameter} or empty list if the given map
     *         is null or empty. The List is always sorted by #getName()
     */
    // now need to throw exception
    @SuppressWarnings("squid:S1166")
    public static List<UrlParameter> getUrlParameterFromMap(final Map<String, List<String>> map,
            final ParameterFilter parameterFilter, final boolean encode) {
        if (MoreCollections.isEmpty(map)) {
            return Collections.emptyList();
        }
        final List<UrlParameter> extracted = new ArrayList<>();
        for (final Entry<String, List<String>> entry : map.entrySet()) {
            String value = null;
            if (!MoreCollections.isEmpty(entry.getValue())) {
                value = entry.getValue().getFirst();
            }
            final var key = entry.getKey();
            if (null == parameterFilter || !parameterFilter.isExcluded(key)) {
                try {
                    extracted.add(new UrlParameter(key, value, encode));
                } catch (final IllegalArgumentException e) {
                    LOGGER.debug(e, "Unable to read url parameter due to missing parameter name");
                }
            }
        }
        extracted.sort(Comparator.comparing(UrlParameter::getName));
        return extracted;
    }

    /**
     * Filters the given list of {@link UrlParameter}
     *
     * @param toBeFiltered    may be null or empty
     * @param parameterFilter used for filtering, may be null
     * @return the filtered parameter list or empty List if toBeFiltered is null or
     *         empty.
     */
    public static List<UrlParameter> filterParameter(final List<UrlParameter> toBeFiltered,
            final ParameterFilter parameterFilter) {
        if (toBeFiltered == null || toBeFiltered.isEmpty()) {
            return Collections.emptyList();
        }
        final var filtered = new ArrayList<UrlParameter>();
        for (final UrlParameter parameter : toBeFiltered) {
            final var key = parameter.getName();
            if (null == parameterFilter || !parameterFilter.isExcluded(key)) {
                filtered.add(parameter);
            }
        }

        return filtered;
    }

    /**
     * Create a parameterMap for a given list of {@link UrlParameter}
     *
     * @param urlParameters may be null or empty
     * @return parameter Map, may be empty if urlParameters is empty. For a
     *         parameter providing a value, the corresponding list contains solely
     *         that one element. For a parameter without a value ({@code null}) the
     *         corresponding list is empty.
     */
    public static Map<String, List<String>> createParameterMap(final List<UrlParameter> urlParameters) {
        final Map<String, List<String>> result = new HashMap<>();
        if (null != urlParameters && !urlParameters.isEmpty()) {
            for (final UrlParameter urlParameter : urlParameters) {
                result.put(urlParameter.getName(), immutableList(urlParameter.getValue()));
            }
        }
        return result;
    }

    /**
     * Helper class that create a list of {@link UrlParameter} from a given
     * query-String
     *
     * @param queryString if it is null or empty or solely consists of an "?" an
     *                    empty {@link List}
     * @return if queryString is null or empty or solely consists of an "?" an empty
     *         {@link List} will be returned. An immutable {@link List} of
     *         {@link UrlParameter} otherwise
     */
    public static List<UrlParameter> fromQueryString(String queryString) {
        LOGGER.trace("Parsing Query String %s", queryString);
        if (MoreStrings.isEmpty(queryString)) {
            return Collections.emptyList();
        }
        var cleaned = queryString.trim();
        if (cleaned.startsWith("?")) {
            cleaned = cleaned.substring(1);
        }
        if (MoreStrings.isEmpty(cleaned)) {
            LOGGER.debug("Given String solely consists of '?' symbol, ignoring");
            return Collections.emptyList();
        }
        var elements = Splitter.on(Pattern.compile("&")).trimResults().omitEmptyStrings().splitToList(cleaned);
        var builder = new CollectionBuilder<UrlParameter>();
        for (String element : elements) {
            // Split on the first '=' only: values may contain literal '=' characters,
            // e.g. Base64-encoded content
            var separatorIndex = element.indexOf('=');
            if (separatorIndex < 0) {
                builder.add(createDecoded(element, null));
            } else {
                var name = element.substring(0, separatorIndex);
                var value = element.substring(separatorIndex + 1);
                if (MoreStrings.isEmpty(name)) {
                    LOGGER.debug(
                            "Unable to parse queryString '%s' correctly, element '%s' provides no parameter name, skipping",
                            queryString, element);
                } else {
                    builder.add(createDecoded(name, MoreStrings.isEmpty(value) ? null : value));
                }
            }
        }
        return builder.toImmutableList();
    }

    private static UrlParameter createDecoded(final String name, final String value) {
        requireNonNull(name);
        String decodedKey;
        decodedKey = URLDecoder.decode(name, StandardCharsets.UTF_8);

        String decodedValue = null;
        if (null != value) {
            decodedValue = URLDecoder.decode(value, StandardCharsets.UTF_8);
        }

        return new UrlParameter(decodedKey, decodedValue, false);
    }

    /**
     * Create a String representation of a name value pair, saying name=value
     *
     * @return String representation of a name value pair, saying name=value
     */
    public String createNameValueString() {
        return createNameValueString(false);
    }

    /**
     * @param encode flag indicating whether the result needs to be encoded. If the
     *               parameter was already encoded at construction time it will not
     *               be encoded again, ensuring single-encoded output
     * @return string representation of name + value
     */
    public String createNameValueString(final boolean encode) {
        if (encode && !encoded) {
            var encodedName = encode(name, StandardCharsets.UTF_8);
            String encodedValue = null;
            if (null != value) {
                encodedValue = encode(value, StandardCharsets.UTF_8);
            }
            return Joiner.on('=').useForNull("").join(encodedName, encodedValue);
        }
        return Joiner.on('=').useForNull("").join(name, value);
    }

    @Override
    public int compareTo(final UrlParameter compareTo) {
        return getName().compareTo(compareTo.getName());
    }
}
