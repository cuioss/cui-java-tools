package de.icw.util.collect;

import java.util.Collection;
import java.util.Iterator;
import java.util.stream.Stream;

import lombok.experimental.UtilityClass;

/**
 * Utility Methods for Collections and some types to be used in the context of Collections
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public final class MoreCollections {

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the given
     * varags-parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} of {@code empty}
     */
    public static boolean isEmpty(Object... elements) {
        return null == elements || 0 == elements.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Iterable<?> elements) {
        return null == elements || isEmpty(elements.iterator());
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Collection<?> elements) {
        return null == elements || elements.isEmpty();
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Iterator<?> elements) {
        return null == elements || !elements.hasNext();
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the given parameter.
     * <em>Caution: </em> In order not to consume the stream only a null check will be performed.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null}. The Stream content will be
     *         untouched
     */
    public static boolean isEmpty(Stream<?> elements) {
        return null == elements;
    }

}
