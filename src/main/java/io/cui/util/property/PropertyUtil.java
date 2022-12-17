package io.cui.util.property;

import static io.cui.util.string.MoreStrings.requireNotEmptyTrimmed;
import static java.util.Objects.requireNonNull;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Optional;

import io.cui.util.base.Preconditions;
import io.cui.util.logging.CuiLogger;
import io.cui.util.reflect.MoreReflection;
import io.cui.util.string.MoreStrings;
import lombok.experimental.UtilityClass;

/**
 * Helper class providing convenient methods for reading from / writing to java beans.
 * <h2>Caution:</h2>
 * <p>
 * Use reflection only if there is no other way. Even if some of the problems are
 * minimized by using this type. It should be used either in test-code, what is we actually do, and
 * not production code. An other reason could be framework code. as for that you should exactly know
 * what you do.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class PropertyUtil {

    private static final CuiLogger log = new CuiLogger(PropertyUtil.class);

    static final String UNABLE_TO_WRITE_PROPERTY =
        "Unable to write property '%s' to beanType '%s': no suitable write method found. Needed property-type '%s'";

    static final String UNABLE_TO_WRITE_PROPERTY_RUNTIME =
        "Unable to write property '%s' to beanType '%s'. Needed property-type '%s'";

    static final String UNABLE_TO_READ_PROPERTY =
        "Unable to read property '%s' from beanType '%s'.";

    /**
     * @param bean instance to be read from, must not be null
     * @param propertyName to be read, must not be null nor empty nor blank
     * @return the object read from the property
     * @throws IllegalArgumentException in case the property does not exist (determined by a read
     *             method)
     * @throws IllegalStateException in case some Exception occurred while reading
     */
    @SuppressWarnings("squid:S3655") // owolff: False Positive, Optional#isPresent is checked
    public static final Object readProperty(Object bean, String propertyName) {
        log.debug("Reading property '%s' from %s", propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        Optional<Method> reader = MoreReflection.retrieveAccessMethod(bean.getClass(), propertyName);
        Preconditions.checkArgument(reader.isPresent(), UNABLE_TO_READ_PROPERTY, propertyName,
                bean.getClass());
        try {
            return reader.get().invoke(bean);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            throw new IllegalStateException(MoreStrings.lenientFormat(UNABLE_TO_READ_PROPERTY, propertyName,
                    bean.getClass()), e);
        }
    }

    /**
     * @param bean instance to be read from, must not be null
     * @param propertyName to be read, must not be null nor empty nor blank
     * @param propertyValue to be set
     * @return In case the property set method is void the given bean will be returned. Otherwise
     *         the return value of the method invocation, assuming the setMethods is a builder type.
     * @throws IllegalArgumentException in case the property does not exist (determined by a write
     *             method)
     * @throws IllegalStateException in case some Exception occurred while writing
     */
    public static final Object writeProperty(Object bean, String propertyName, Object propertyValue) {
        log.debug("Writing '%s' to property '%s' on '%s'", propertyValue, propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        Method writeMethod = determineWriteMethod(bean, propertyName, propertyValue);
        try {
            Object result = writeMethod.invoke(bean, propertyValue);
            if (null == result) {
                return bean;
            } else {
                return result;
            }
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            String target = (propertyValue != null) ? propertyValue.getClass().getName() : "Undefined";
            throw new IllegalStateException(
                    MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY_RUNTIME, propertyName, bean.getClass(), target),
                    e);
        }
    }

    /**
     * Tries to determine the type of a given property
     *
     * @param beanType to be checked, must not be null
     * @param propertyName to be checked, must not be null
     * @return an {@link Optional} on the actual type of the property. First it checks an
     *         access-methods, then it tries to directly access the field, and if that fails it uses
     *         the first read method found, {@link Optional#empty()} otherwise.
     */
    public static final Optional<Class<?>> resolvePropertyType(Class<?> beanType, String propertyName) {
        Optional<Method> retrieveAccessMethod = MoreReflection.retrieveAccessMethod(beanType, propertyName);
        if (retrieveAccessMethod.isPresent()) {
            log.trace("Found read-method on class '%s' for property-name '%s'", beanType, propertyName);
            return Optional.of(retrieveAccessMethod.get().getReturnType());
        }
        Optional<Field> field = MoreReflection.accessField(beanType, propertyName);
        if (field.isPresent()) {
            log.trace("Found field on class '%s' with name '%s'", beanType, propertyName);
            return Optional.of(field.get().getType());
        }
        log.debug(
                "Neither read-method nor field found on class '%s' for property-name '%s', checking write methods, returning first type found",
                beanType, propertyName);
        Collection<Method> candidates = MoreReflection.retrieveWriteMethodCandidates(beanType, propertyName);
        if (!candidates.isEmpty()) {
            return Optional.of(candidates.iterator().next().getParameterTypes()[0]);
        }
        log.debug(
                "Unable to detect property-type on class '%s' for property-name '%s'",
                beanType, propertyName);
        return Optional.empty();
    }

    static Method determineWriteMethod(Object bean, String propertyName, Object propertyValue) {
        Collection<Method> candidates = MoreReflection.retrieveWriteMethodCandidates(bean.getClass(), propertyName);
        String target = (propertyValue != null) ? propertyValue.getClass().getName() : "Undefined";
        Preconditions.checkArgument(!candidates.isEmpty(),
                UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(), target);
        if (null == propertyValue) {
            log.trace("No / Null propertyValue given, so any method should suffice to write property '%s' to %s",
                    propertyName, bean);
            return candidates.iterator().next();
        } else {
            for (Method candidate : candidates) {
                if (MoreReflection.checkWhetherParameterIsAssignable(candidate.getParameterTypes()[0],
                        propertyValue.getClass())) {
                    log.trace("Found method %s to write property '%s' to %s", candidate,
                            propertyName, bean);
                    return candidate;
                }
            }
        }
        throw new IllegalArgumentException(
                MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(),
                        target));
    }
}
