package io.cui.util.net;

import static io.cui.util.collect.CollectionLiterals.immutableList;
import static io.cui.util.string.MoreStrings.requireNotEmptyTrimmed;
import static java.net.URLEncoder.encode;
import static java.util.Objects.requireNonNull;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import io.cui.util.collect.CollectionBuilder;
import io.cui.util.collect.MoreCollections;
import io.cui.util.logging.CuiLogger;
import io.cui.util.string.Joiner;
import io.cui.util.string.MoreStrings;
import io.cui.util.string.Splitter;
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

    /** . */
    private static final String UNSUPPORTED_ENCODING_EXCEPTION = "UnsupportedEncodingException";

    private static final CuiLogger log = new CuiLogger(UrlParameter.class);

    /** Shortcut constant for faces redirect parameter. */
    public static final UrlParameter FACES_REDIRECT = new UrlParameter("faces-redirect", "true");

    /** Shortcut constant parameter for includeViewParams. */
    public static final UrlParameter INCLUDE_VIEW_PARAMETER =
        new UrlParameter("includeViewParams", "true");

    private static final long serialVersionUID = 634175928228707534L;

    private static final String UTF_8 = "UTF-8";

    /** The name of the parameter. */
    @Getter
    private final String name;

    /** The value of the parameter. */
    @Getter
    private final String value;

    /**
     * Constructor. Name and value are implicitly encoded using UTF-8.
     *
     * @param name
     *            must not be null or empty
     * @param value
     *            may be null.
     */
    public UrlParameter(final String name, final String value) {
        this(name, value, true);
    }

    /**
     * Constructor.
     *
     * @param name
     *            must not be null or empty
     * @param value
     *            value may be null.
     * @param encode
     *            indicates whether to encode the parameter name and value as
     *            UTF-8
     */
    public UrlParameter(final String name, final String value, final boolean encode) {
        super();
        requireNotEmptyTrimmed(name, "Parameter name must not be empty");
        if (encode) {
            try {
                this.name = encode(name, UTF_8);
                if (MoreStrings.isEmpty(value)) {
                    this.value = null;
                } else {
                    this.value = encode(value, UTF_8);
                }
            } catch (final UnsupportedEncodingException e) {
                // UTF-8 will always be supported, so this a strange exception.
                throw new IllegalStateException(UNSUPPORTED_ENCODING_EXCEPTION, e);
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
     * @param parameters
     *            to be appended, must not be null
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
    public static String createParameterString(final boolean encode,
            final UrlParameter... parameters) {
        final StringBuilder builder = new StringBuilder();
        // First parameter to be treated specially.
        if (null != parameters && parameters.length > 0 && null != parameters[0]) {
            builder.append('?').append(parameters[0].createNameValueString(encode));
            if (parameters.length > 1) {
                // The other parameters are appended with '&'
                for (int i = 1; i < parameters.length; i++) {
                    builder.append('&').append(parameters[i].createNameValueString(encode));
                }
            }
        }
        return builder.toString();
    }

    /**
     * Convert a map of raw Url-parameter into a list of {@link UrlParameter}
     *
     * @param map
     *            containing the parameter extracted usually directly from
     *            servlet request. From the String[] solely the first element
     *            will be extracted. The others will be ignored.
     * @param parameterFilter
     *            defines the parameter to be filtered. May be null or empty.
     * @param encode
     *            indicates whether to encode the parameter name and value as
     *            UTF-8
     * @return the found List of {@link UrlParameter} or empty list if the given
     *         map is null or empty. The List is always sorted by #getName()
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
            final String key = entry.getKey();
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
     * @param toBeFiltered
     *            may be null or empty
     * @param parameterFilter
     *            used for filtering, may be null
     * @return the filtered parameter list or empty List if toBeFiltered is null
     *         or empty.
     */
    public static List<UrlParameter> filterParameter(final List<UrlParameter> toBeFiltered,
            final ParameterFilter parameterFilter) {
        if (toBeFiltered == null || toBeFiltered.isEmpty()) {
            return Collections.emptyList();
        }
        final ArrayList<UrlParameter> filtered = new ArrayList<>();
        for (final UrlParameter parameter : toBeFiltered) {
            final String key = parameter.getName();
            if (null == parameterFilter || !parameterFilter.isExcluded(key)) {
                filtered.add(parameter);
            }
        }

        return filtered;
    }

    /**
     * Create a parameterMap for a given list of {@link UrlParameter}
     *
     * @param urlParameters
     *            may be null or empty
     * @return parameter Map, may be empty if urlParameters is empty. The list
     *         of String will solely contain one element.
     */
    public static final Map<String, List<String>> createParameterMap(
            final List<UrlParameter> urlParameters) {
        final Map<String, List<String>> result = new HashMap<>();
        if (null != urlParameters && !urlParameters.isEmpty()) {
            for (final UrlParameter urlParameter : urlParameters) {
                result.put(urlParameter.getName(), immutableList(urlParameter.getValue()));
            }
        }
        return result;
    }

    /**
     * Helper class that create a list of {@link UrlParameter} from a given query-String
     *
     * @param queryString if it is null or empty or solely consists of an "?" an empty {@link List}
     * @return if queryString is null or empty or solely consists of an "?" an empty {@link List}
     *         will be returned. An immutable {@link List} of {@link UrlParameter} otherwise
     */
    public static List<UrlParameter> fromQueryString(String queryString) {
        log.trace("Parsing Query String %s", queryString);
        if (MoreStrings.isEmpty(queryString)) {
            return Collections.emptyList();
        }
        String cleaned = queryString.trim();
        if (cleaned.startsWith("?")) {
            cleaned = cleaned.substring(1, cleaned.length());
        }
        if (MoreStrings.isEmpty(cleaned)) {
            log.debug("Given String solely consists of '?' symbol, ignoring");
            return Collections.emptyList();
        }
        List<String> elements = Splitter.on("&").omitEmptyStrings().splitToList(cleaned);
        CollectionBuilder<UrlParameter> builder = new CollectionBuilder<>();
        for (String element : elements) {
            if (element.contains("=")) {
                List<String> splitted = Splitter.on("=").omitEmptyStrings().splitToList(element);
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

    private static final UrlParameter createDecoded(final String name, final String value) {
        requireNonNull(name);
        String decodedKey;
        try {
            decodedKey = URLDecoder.decode(name, UTF_8);
        } catch (final UnsupportedEncodingException e) {
            // UTF-8 will always be supported, so this a strange exception.
            throw new IllegalStateException(UNSUPPORTED_ENCODING_EXCEPTION, e);
        }
        String decodedValue = null;
        if (null != value) {
            try {
                decodedValue = URLDecoder.decode(value, UTF_8);
            } catch (UnsupportedEncodingException e) {
                // UTF-8 will always be supported, so this a strange exception.
                throw new IllegalStateException(UNSUPPORTED_ENCODING_EXCEPTION, e);
            }
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
     * @param encode
     *            flag indicate if the result need to be encoded
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