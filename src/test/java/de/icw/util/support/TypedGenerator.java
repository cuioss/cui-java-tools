package de.icw.util.support;

/**
 * A generator creates instances of type T.
 * The method {@link #getType()} provides a default implementation using {@link #next()} and reading
 * the concrete {@link Class} of the returned element.
 *
 * @author Oliver Wolff
 * @param <T> identifying the type of objects to be generated
 */
public interface TypedGenerator<T> {

    /**
     * @return class information; which type this generator is responsible for.
     */
    @SuppressWarnings("unchecked") // the implicit providing of the type is the actual idea
    default Class<T> getType() {
        return (Class<T>) next().getClass();
    }

    /**
     * Generates the next instance.
     *
     * @return a newly created instance
     */
    T next();
}
