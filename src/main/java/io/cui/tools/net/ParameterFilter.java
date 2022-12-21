package io.cui.tools.net;

import static java.util.Objects.requireNonNull;

import java.io.Serializable;
import java.util.List;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

/**
 * Defines a filter identifying which parameters are not to be included within
 * url parameter handling. Therefore it filters parameter prefixed with
 * "javax.faces", depending on <code>excludeFacesParameter</code> and
 * additionally a given list of parameter names.
 * <p>
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@EqualsAndHashCode
@ToString
public class ParameterFilter implements Serializable {

    private static final long serialVersionUID = -4780294784318006024L;

    private static final String JAVAX_FACES = "javax.faces";

    /**
     * The list of string to be excluded from the parameter-list. Because the
     * test utilizes toLowerCase() the members of the list must all be
     * lowercase. Otherwise they are not considered.
     */
    @NonNull
    @Getter
    private final List<String> excludes;

    /** Flag indicating whether to exclude technical jsf parameters. */
    private final boolean excludeFacesParameter;

    /**
     * @param value
     *            as key of view parameter. Must not be null
     * @return true if value belongs to excluded values
     */
    public boolean isExcluded(final String value) {
        requireNonNull(value);
        boolean excluded = false;
        if (excludeFacesParameter) {
            excluded = value.startsWith(JAVAX_FACES);
        }
        if (!excluded) {
            excluded = excludes.contains(value.toLowerCase());
        }
        return excluded;
    }

}
