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
package de.cuioss.tools.property;

import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.util.Objects.requireNonNull;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.reflect.MoreReflection;
import de.cuioss.tools.string.MoreStrings;
import lombok.experimental.UtilityClass;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;

/**
 * Helper class providing convenient methods for reading from / writing to java
 * beans.
 * <h2>Caution:</h2>
 * <p>
 * Use reflection only if there is no other way. Even if some of the problems
 * are minimized by using this type. It should be used either in test-code, what
 * is we actually do, and not production code. An other reason could be
 * framework code. as for that you should exactly know what you do.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class PropertyUtil {

    private static final CuiLogger log = new CuiLogger(PropertyUtil.class);

    static final String UNABLE_TO_WRITE_PROPERTY = "Unable to write property '%s' to beanType '%s': no suitable write method found. Needed property-type '%s'";

    static final String UNABLE_TO_WRITE_PROPERTY_RUNTIME = "Unable to write property '%s' to beanType '%s'. Needed property-type '%s'";

    static final String UNABLE_TO_READ_PROPERTY = "Unable to read property '%s' from beanType '%s'.";

    /**
     * @param bean         instance to be read from, must not be null
     * @param propertyName to be read, must not be null nor empty nor blank
     * @return the object read from the property
     * @throws IllegalArgumentException in case the property does not exist
     *                                  (determined by a read method)
     * @throws IllegalStateException    in case some Exception occurred while
     *                                  reading
     */
    @SuppressWarnings("squid:S3655") // owolff: False Positive, Optional#isPresent is checked
    public static Object readProperty(Object bean, String propertyName) {
        log.debug("Reading property '%s' from %s", propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        var reader = MoreReflection.retrieveAccessMethod(bean.getClass(), propertyName);
        Preconditions.checkArgument(reader.isPresent(), UNABLE_TO_READ_PROPERTY, propertyName, bean.getClass());
        try {
            return reader.get().invoke(bean);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            throw new IllegalStateException(
                    MoreStrings.lenientFormat(UNABLE_TO_READ_PROPERTY, propertyName, bean.getClass()), e);
        }
    }

    /**
     * @param bean          instance to be read from, must not be null
     * @param propertyName  to be read, must not be null nor empty nor blank
     * @param propertyValue to be set
     * @return In case the property set method is void the given bean will be
     *         returned. Otherwise, the return value of the method invocation,
     *         assuming the setMethods is a builder type.
     * @throws IllegalArgumentException in case the property does not exist
     *                                  (determined by a write method)
     * @throws IllegalStateException    in case some Exception occurred while
     *                                  writing
     */
    public static Object writeProperty(Object bean, String propertyName, Object propertyValue) {
        log.debug("Writing '%s' to property '%s' on '%s'", propertyValue, propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        var writeMethod = determineWriteMethod(bean, propertyName, propertyValue);
        try {
            var result = writeMethod.invoke(bean, propertyValue);
            return Objects.requireNonNullElse(result, bean);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            var target = propertyValue != null ? propertyValue.getClass().getName() : "Undefined";
            throw new IllegalStateException(
                    MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY_RUNTIME, propertyName, bean.getClass(), target),
                    e);
        }
    }

    /**
     * Tries to determine the type of given property
     *
     * @param beanType     to be checked, must not be null
     * @param propertyName to be checked, must not be null
     * @return an {@link Optional} on the actual type of the property. First it
     *         checks an access-methods, then it tries to directly access the field,
     *         and if that fails it uses the first read method found,
     *         {@link Optional#empty()} otherwise.
     */
    public static Optional<Class<?>> resolvePropertyType(Class<?> beanType, String propertyName) {
        var retrieveAccessMethod = MoreReflection.retrieveAccessMethod(beanType, propertyName);
        if (retrieveAccessMethod.isPresent()) {
            log.trace("Found read-method on class '%s' for property-name '%s'", beanType, propertyName);
            return Optional.of(retrieveAccessMethod.get().getReturnType());
        }
        var field = MoreReflection.accessField(beanType, propertyName);
        if (field.isPresent()) {
            log.trace("Found field on class '%s' with name '%s'", beanType, propertyName);
            return Optional.of(field.get().getType());
        }
        log.debug(
                "Neither read-method nor field found on class '%s' for property-name '%s', checking write methods, returning first type found",
                beanType, propertyName);
        var candidates = MoreReflection.retrieveWriteMethodCandidates(beanType, propertyName);
        if (!candidates.isEmpty()) {
            return Optional.of(candidates.iterator().next().getParameterTypes()[0]);
        }
        log.debug("Unable to detect property-type on class '%s' for property-name '%s'", beanType, propertyName);
        return Optional.empty();
    }

    static Method determineWriteMethod(Object bean, String propertyName, Object propertyValue) {
        var candidates = MoreReflection.retrieveWriteMethodCandidates(bean.getClass(), propertyName);
        var target = propertyValue != null ? propertyValue.getClass().getName() : "Undefined";
        Preconditions.checkArgument(!candidates.isEmpty(), UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(),
                target);
        if (null == propertyValue) {
            log.trace("No / Null propertyValue given, so any method should suffice to write property '%s' to %s",
                    propertyName, bean);
            return candidates.iterator().next();
        }
        for (Method candidate : candidates) {
            if (MoreReflection.checkWhetherParameterIsAssignable(candidate.getParameterTypes()[0],
                    propertyValue.getClass())) {
                log.trace("Found method %s to write property '%s' to %s", candidate, propertyName, bean);
                return candidate;
            }
        }
        throw new IllegalArgumentException(
                MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(), target));
    }
}
