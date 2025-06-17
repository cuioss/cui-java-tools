/**
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
package de.cuioss.tools.collect;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * <h2>Overview</h2> Default implementation of {@link PartialCollection} based
 * on {@link ArrayList}.
 * <h3>Usage</h3>
 * <p>
 * See {@link PartialArrayList#of(List, int)}
 * </p>
 *
 * @param <T> at least {@link Serializable}
 */
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class PartialArrayList<T extends Serializable> extends ArrayList<T> implements PartialCollection<T> {

    @Serial
    private static final long serialVersionUID = -7548645400982124555L;

    @Getter
    private final boolean moreAvailable;

    /**
     * Default constructor.
     *
     * @param list          the list of entities to store.
     * @param moreAvailable the flag to store.
     */
    public PartialArrayList(Collection<T> list, boolean moreAvailable) {
        super(list);
        this.moreAvailable = moreAvailable;
    }

    /**
     * Static constructor for an empty instance.
     *
     * @param <T>
     * @return an empty {@link PartialArrayList}.
     */
    public static <T extends Serializable> PartialArrayList<T> emptyList() {
        return new PartialArrayList<>(Collections.emptyList(), false);
    }

    /**
     * Convenience method for creating a {@link PartialArrayList} as sublist for the
     * given collection with setting the {@link PartialCollection#isMoreAvailable()}
     * automatically
     *
     * @param full  the complete List to be wrapped, may be larger than the limit.
     *              If so, a sublist will be used.
     * @param limit to be checked against
     *
     * @param <T>   identifying the type of contained elements
     * @return a newly created {@link PartialArrayList}.
     */
    public static <T extends Serializable> PartialArrayList<T> of(List<T> full, int limit) {
        if (MoreCollections.isEmpty(full)) {
            return emptyList();
        }
        var actualSize = full.size();
        if (actualSize <= limit) {
            return new PartialArrayList<>(full, false);
        }
        return new PartialArrayList<>(full.subList(0, limit), true);
    }

}
