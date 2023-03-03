package de.cuioss.tools.property.support;

import java.io.Serializable;
import java.util.Map.Entry;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

@SuppressWarnings("javadoc")
@ToString(doNotUseGetters = true)
@EqualsAndHashCode(doNotUseGetters = true)
public class GenericTypeWithLowerBoundType<K extends Serializable, V extends Serializable>
        implements Entry<K, V>, Serializable {

    private static final long serialVersionUID = -6403178000941411123L;

    @Getter
    private final K key;

    @Getter
    private V value;

    /**
     * @param key must not be {@code null}
     */
    public GenericTypeWithLowerBoundType(@NonNull final K key) {
        super();
        this.key = key;
    }

    /**
     * @param key must not be {@code null}
     * @param value
     */
    public GenericTypeWithLowerBoundType(final K key, final V value) {
        this(key);
        setValue(value);
    }

    @Override
    public V setValue(V value) {
        this.value = value;
        return this.value;
    }

}
