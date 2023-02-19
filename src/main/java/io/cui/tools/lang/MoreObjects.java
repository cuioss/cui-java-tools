package io.cui.tools.lang;

import static io.cui.tools.base.Preconditions.checkArgument;
import static io.cui.tools.collect.MoreCollections.isEmpty;

import java.util.function.Supplier;

import lombok.experimental.UtilityClass;

/**
 * Provides some utilities in the context of {@link Object}
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class MoreObjects {

    /**
     * Checks and returns the given Object if it is assignable to the given targetType.
     * Otherwise, it throws an {@link IllegalArgumentException}. This will be thrown also if
     * one of the parameters is {@code null}.
     *
     * @param <T> defining the type to be returned.
     *
     * @param underCheck KeyStoreType to be checked / cast. If it is null or is not assignable to
     *            expectedType an {@link IllegalArgumentException} will be thrown.
     * @param expectedType checks the type . If it is null an {@link IllegalArgumentException} will
     *            be thrown
     * @return the cast Objected of type T if applicable.
     * @throws IllegalArgumentException if the given type is either null or not the expected type
     */
    @SuppressWarnings("unchecked") // owolff: It is actually checked before.
    public static <T> T requireType(final Object underCheck, Class<T> expectedType) {
        checkArgument(null != underCheck, "Object to be checked must not be null");
        checkArgument(null != expectedType, "expectedType must not be null");
        checkArgument(expectedType.isAssignableFrom(underCheck.getClass()),
                "KeyStoreType to be checked '%s' is not assignable to '%s'", underCheck.getClass(),
                expectedType.getName());
        return (T) underCheck;
    }

    /**
     * Simple helper checking whether a number of given Objects are not {@code null}
     *
     * @param objects
     * @return {@code true} if there is no {@code null} value given, {@code false} if at least one
     *         null value is given. An empty varags parameter therefore results in {@code true} (no
     *         null object found)
     */
    public static boolean allNonNull(Object... objects) {
        if (isEmpty(objects)) {
            return true;
        }
        for (Object object : objects) {
            if (null == object) {
                return false;
            }
        }
        return true;
    }

    /**
     * Simple helper checking whether a number of given Objects are {@code null}
     *
     * @param objects
     * @return {@code true} if there is no non-{@code null} value given, {@code false} if at least
     *         one non-null value is given. An empty varags parameter therefore results in
     *         {@code true} (no non-null object found)
     */
    public static boolean allNull(Object... objects) {
        if (isEmpty(objects)) {
            return true;
        }
        for (Object object : objects) {
            if (null != object) {
                return false;
            }
        }
        return true;
    }

    /**
     * <p>
     * Returns the first value in the array which is not {@code null}.
     * If all the values are {@code null} or the array is {@code null}
     * or empty then {@code null} is returned.
     * </p>
     *
     * <pre>
     * MoreObjects.firstNonNull(null, null)      = null
     * MoreObjects.firstNonNull(null, "")        = ""
     * MoreObjects.firstNonNull(null, null, "")  = ""
     * MoreObjects.firstNonNull(null, "zz")      = "zz"
     * MoreObjects.firstNonNull("abc", *)        = "abc"
     * MoreObjects.firstNonNull(null, "xyz", *)  = "xyz"
     * MoreObjects.firstNonNull(Boolean.TRUE, *) = Boolean.TRUE
     * MoreObjects.firstNonNull()                = null
     * </pre>
     *
     * @param <T> the component type of the array
     * @param values the values to test, may be {@code null} or empty
     *
     * @return the first value from {@code values} which is not {@code null},
     *         or {@code null} if there are no non-null values
     */
    @SafeVarargs
    public static <T> T firstNonNull(final T... values) {
        if (values != null) {
            for (final T val : values) {
                if (val != null) {
                    return val;
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * Executes the given suppliers in order and returns the first return
     * value where a value other than {@code null} is returned.
     * Once a non-{@code null} value is obtained, all following suppliers are
     * not executed anymore.
     * If all the return values are {@code null} or no suppliers are provided
     * then {@code null} is returned.
     * </p>
     *
     * <pre>
     * MoreObjects.getFirstNonNull(null, () -&gt; null) = null
     * MoreObjects.getFirstNonNull(() -&gt; null, () -&gt; "") = ""
     * MoreObjects.getFirstNonNull(() -&gt; "", () -&gt; throw new IllegalStateException()) = ""
     * MoreObjects.getFirstNonNull(() -&gt; null, () -&gt; "zz) = "zz"
     * MoreObjects.getFirstNonNull() = null
     * </pre>
     *
     * @param <T> the type of the return values
     * @param suppliers the suppliers returning the values to test.
     *            {@code null} values are ignored.
     *            Suppliers may return {@code null} or a value of type @{code T}
     *
     * @return the first return value from {@code suppliers} which is not {@code null},
     *         or {@code null} if there are no non-null values
     */
    @SafeVarargs
    public static <T> T getFirstNonNull(final Supplier<T>... suppliers) {
        if (suppliers != null) {
            for (final Supplier<T> supplier : suppliers) {
                if (supplier != null) {
                    final var value = supplier.get();
                    if (value != null) {
                        return value;
                    }
                }
            }
        }
        return null;
    }
}
