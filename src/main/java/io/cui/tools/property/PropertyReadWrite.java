package io.cui.tools.property;

import static java.util.Objects.requireNonNull;

import java.beans.PropertyDescriptor;

import io.cui.tools.lang.MoreObjects;
import io.cui.tools.logging.CuiLogger;
import io.cui.tools.reflect.MoreReflection;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Defines the read write permissions for a given property. It is defined for properties java Bean
 * properties.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
public enum PropertyReadWrite {

    /** The corresponding property is read only. */
    READ_ONLY(true, false),
    /** The property can be read and written to. */
    READ_WRITE(true, true),
    /** The property can only be written to. */
    WRITE_ONLY(false, true),
    /** The property can neither be read nor written to. */
    NONE(false, false);

    private static final CuiLogger log = new CuiLogger(PropertyReadWrite.class);

    @Getter
    private final boolean readable;

    @Getter
    private final boolean writeable;

    /**
     * Resolves {@link PropertyReadWrite} for a given property with {@link MoreReflection}
     *
     * @param beanType to be checked, must not be null
     * @param propertyName to be checked, must not be null
     * @return the corresponding {@link PropertyReadWrite} for a given property
     */
    public static PropertyReadWrite resolveForBean(final Class<?> beanType, final String propertyName) {
        final var readable = MoreReflection.retrieveAccessMethod(beanType, propertyName).isPresent();
        final var writeable = !MoreReflection.retrieveWriteMethodCandidates(beanType, propertyName).isEmpty();
        if (readable && writeable) {
            return READ_WRITE;
        }
        if (readable) {
            return READ_ONLY;
        }
        if (writeable) {
            return WRITE_ONLY;
        }
        return NONE;
    }

    /**
     * Resolves {@link PropertyReadWrite} form the given {@link PropertyDescriptor}. If this
     * provides unclear result it will call {@link #resolveForBean(Class, String)}
     *
     * @param descriptor to be read from
     * @param beanType to be checked, must not be null
     * @param propertyName to be checked, must not be null
     * @return the corresponding {@link PropertyReadWrite} for a given property
     */
    public static PropertyReadWrite fromPropertyDescriptor(PropertyDescriptor descriptor, final Class<?> beanType,
            final String propertyName) {
        requireNonNull(descriptor);
        if (MoreObjects.allNonNull(descriptor.getReadMethod(), descriptor.getWriteMethod())) {
            return READ_WRITE;
        }
        log.debug(
                "PropertyDescriptor '%s' does not describe a standard bean-structure for property '%s' on type '%s', switching to reflection",
                descriptor, propertyName, beanType);
        return resolveForBean(beanType, propertyName);
    }
}
