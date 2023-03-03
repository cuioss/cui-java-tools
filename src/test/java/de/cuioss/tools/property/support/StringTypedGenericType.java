package de.cuioss.tools.property.support;

import lombok.NonNull;

@SuppressWarnings("javadoc")
public class StringTypedGenericType extends GenericTypeWithLowerBoundType<String, String> {

    private static final long serialVersionUID = 7501705815919447469L;

    public StringTypedGenericType(@NonNull String key) {
        super(key);
    }

}
