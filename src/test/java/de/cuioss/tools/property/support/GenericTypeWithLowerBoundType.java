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
package de.cuioss.tools.property.support;

import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map.Entry;

@ToString(doNotUseGetters = true)
@EqualsAndHashCode(doNotUseGetters = true)
public class GenericTypeWithLowerBoundType<K extends Serializable, V extends Serializable>
        implements Entry<K, V>, Serializable {

    @Serial
    private static final long serialVersionUID = -6403178000941411123L;

    private final K key;

    private V value;

    /**
     * @param key must not be {@code null}
     */
    public GenericTypeWithLowerBoundType(@NonNull final K key) {
        this.key = key;
    }

    /**
     * @param key   must not be {@code null}
     * @param value
     */
    public GenericTypeWithLowerBoundType(final K key, final V value) {
        this(key);
        setValue(value);
    }

    @Override
    public K getKey() {
        return this.key;
    }

    @Override
    public V getValue() {
        return this.value;
    }

    @Override
    public V setValue(V value) {
        V oldValue = this.value;
        this.value = value;
        return oldValue;
    }

}
