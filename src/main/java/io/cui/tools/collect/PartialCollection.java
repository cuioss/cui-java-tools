package io.cui.tools.collect;

import java.io.Serializable;
import java.util.Collection;

/**
 * Represents a partial collection / sub-collection. It extends the {@link java.util.Collection} interface
 * with {@link #isMoreAvailable()} flag. This indicates that the original {@link java.util.Collection}
 * provides more data than the current {@link io.cui.tools.collect.PartialCollection}. It defines the lower bound for the
 * contained types to {@link java.io.Serializable}. Currently, the only implementation is
 * {@link io.cui.tools.collect.PartialArrayList}. It provides convenient methods for instantiation, like
 * {@link io.cui.tools.collect.PartialArrayList#of(java.util.List, int)}
 *
 * @param <T> the type of the entity
 * @author oliver
 */
public interface PartialCollection<T extends Serializable> extends Collection<T>, Serializable {

    /**
     * <p>isMoreAvailable.</p>
     *
     * @return {@code true} if more entities are available and ignored due to the given limit.
     */
    boolean isMoreAvailable();

}
