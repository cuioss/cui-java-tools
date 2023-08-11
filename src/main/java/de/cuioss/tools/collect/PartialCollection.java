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
package de.cuioss.tools.collect;

import java.io.Serializable;
import java.util.Collection;

/**
 * Represents a partial collection / sub-collection. It extends the
 * {@link java.util.Collection} interface with {@link #isMoreAvailable()} flag.
 * This indicates that the original {@link java.util.Collection} provides more
 * data than the current {@link de.cuioss.tools.collect.PartialCollection}. It
 * defines the lower bound for the contained types to
 * {@link java.io.Serializable}. Currently, the only implementation is
 * {@link de.cuioss.tools.collect.PartialArrayList}. It provides convenient
 * methods for instantiation, like
 * {@link de.cuioss.tools.collect.PartialArrayList#of(java.util.List, int)}
 *
 * @param <T> the type of the entity
 * @author oliver
 */
public interface PartialCollection<T extends Serializable> extends Collection<T>, Serializable {

    /**
     * <p>
     * isMoreAvailable.
     * </p>
     *
     * @return {@code true} if more entities are available and ignored due to the
     *         given limit.
     */
    boolean isMoreAvailable();

}
