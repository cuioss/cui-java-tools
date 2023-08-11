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
package de.cuioss.tools.net;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.net.URLEncoder.encode;
import static java.util.Objects.requireNonNull;

import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import de.cuioss.tools.collect.CollectionBuilder;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Joiner;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

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
@EqualsAndHashCode
@ToString
public class UrlParameter implements Serializable, Comparable<UrlParameter> {

    private static final CuiLogger log = new CuiLogger(UrlParameter.class);

    /** Shortcut constant for faces redirect parameter. */
    public static final UrlParameter FACES_REDIRECT = new UrlParameter("faces-redirect", "true");

    /** Shortcut constant parameter for includeViewParams. */
    public static final UrlParameter INCLUDE_VIEW_PARAMETER = new UrlParameter("includeViewParams", "true");

    private static final long serialVersionUID = 634175928228707534L;

    /** The name of the parameter. */
    @Getter
    private final String name;

    /** The value of the parameter. */
    @Getter
    private final String value;

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
        super();
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
     *
     * @param parameters to be appended, must not be null
     * @return the concatenated ParameterString in the form
     *         "?parameter1Name=parameter1Value&amp;parameter2Name=parameter2Value"
     */
    public static String createParameterString(final UrlParameter... parameters) {
        return createParameterString(false, parameters);
    }

    /**
     * Create a String-representation of the URL-Parameter
     *
     * @param encode
     * @param parameters
     * @return the created parameter String
     */
    public static String createParameterString(final boolean encode, final UrlParameter... parameters) {
        final var builder = new StringBuilder();
        // First parameter to be treated specially.
        if (null != parameters && parameters.length > 0 && null != parameters[0]) {
            builder.append('?').append(parameters[0].createNameValueString(encode));
            if (parameters.length > 1) {
                // The other parameters are appended with '&'
                for (var i = 1; i < parameters.length; i++) {
                    builder.append('&').append(parameters[i].createNameValueString(encode));
                }
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
    @SuppressWarnings("squid:S1166") // now need to throw exception
    public static final List<UrlParameter> getUrlParameterFromMap(final Map<String, List<String>> map,
            final ParameterFilter parameterFilter, final boolean encode) {
        if (MoreCollections.isEmpty(map)) {
            return Collections.emptyList();
        }
        final List<UrlParameter> extracted = new ArrayList<>();
        for (final Entry<String, List<String>> entry : map.entrySet()) {
            String value = null;
            if (!MoreCollections.isEmpty(entry.getValue())) {
                value = entry.getValue().get(0);
            }
            final var key = entry.getKey();
            if (null == parameterFilter || !parameterFilter.isExcluded(key)) {
                try {
                    extracted.add(new UrlParameter(key, value, encode));
                } catch (final IllegalArgumentException e) {
                    log.debug("Unable to read url parameter due to missing parameter name", e.getMessage());
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
     * @return parameter Map, may be empty if urlParameters is empty. The list of
     *         String will solely contain one element.
     */
    public static final Map<String, List<String>> createParameterMap(final List<UrlParameter> urlParameters) {
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
        log.trace("Parsing Query String %s", queryString);
        if (MoreStrings.isEmpty(queryString)) {
            return Collections.emptyList();
        }
        var cleaned = queryString.trim();
        if (cleaned.startsWith("?")) {
            cleaned = cleaned.substring(1);
        }
        if (MoreStrings.isEmpty(cleaned)) {
            log.debug("Given String solely consists of '?' symbol, ignoring");
            return Collections.emptyList();
        }
        var elements = Splitter.on("&").omitEmptyStrings().splitToList(cleaned);
        var builder = new CollectionBuilder<UrlParameter>();
        for (String element : elements) {
            if (element.contains("=")) {
                var splitted = Splitter.on("=").omitEmptyStrings().splitToList(element);
                switch (splitted.size()) {
                case 0:
                    log.debug(
                            "Unable to parse queryString '%s' correctly, unable to extract key-value-pair for element '%s'",
                            queryString, element);
                    break;
                case 1:
                    builder.add(createDecoded(splitted.get(0), null));
                    break;
                case 2:
                    builder.add(createDecoded(splitted.get(0), splitted.get(1)));
                    break;
                default:
                    log.debug(
                            "Unable to parse queryString '%s' correctly, multiple '=' symbols found at unexpected locations",
                            queryString);
                    break;
                }
            } else {
                builder.add(createDecoded(element, null));
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
     * @param encode flag indicate if the result need to be encoded
     * @return string representation of name + vale
     */
    public String createNameValueString(final boolean encode) {
        if (encode) {
            return new UrlParameter(name, value).createNameValueString();
        }
        return Joiner.on('=').useForNull("").join(name, value);
    }

    @Override
    public int compareTo(final UrlParameter compareTo) {
        return getName().compareTo(compareTo.getName());
    }
}
