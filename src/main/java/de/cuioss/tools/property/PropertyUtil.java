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
package de.cuioss.tools.property;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.reflect.MoreReflection;
import de.cuioss.tools.string.MoreStrings;
import lombok.experimental.UtilityClass;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;

import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.util.Objects.requireNonNull;

/**
 * Helper class providing convenient methods for reading from and writing to Java beans.
 * <p>
 * <strong>Caution:</strong> Use reflection only if there is no other way.
 * While this class minimizes some reflection-related issues, it should primarily be used in:
 * </p>
 * <ul>
 *   <li>Test code</li>
 *   <li>Framework code where reflection is necessary</li>
 *   <li>This type is for low-level operations.
 *   On a higher level, use {@link de.cuioss.tools.reflect.FieldWrapper} instead</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Setup - define bean and property
 * MyBean bean = new MyBean();
 * String propertyName = "firstName";
 *
 * // Read property value
 * Object value = PropertyUtil.readProperty(bean, propertyName);
 *
 * // Write property value with type checking
 * PropertyUtil.setProperty(bean, propertyName, "John");
 *
 * // Handle potential exceptions
 * try {
 *     PropertyUtil.setProperty(bean, propertyName, value);
 * } catch (IllegalArgumentException e) {
 *     // Handle invalid property name or type
 * } catch (IllegalStateException e) {
 *     // Handle inaccessible property
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>This type is for low-level operations.
 *   On a higher level, use {@link de.cuioss.tools.reflect.FieldWrapper} instead</li>
 *   <li>Always validate bean and property names before access</li>
 *   <li>Use {@link PropertyHolder} for type-safe property access</li>
 *   <li>Handle exceptions appropriately</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.reflect.FieldWrapper
 * @see PropertyHolder
 * @see PropertyMemberInfo
 * @since 2.0
 */
@UtilityClass
public class PropertyUtil {

    private static final CuiLogger LOGGER = new CuiLogger(PropertyUtil.class);

    /**
     * Error message template for property read failures
     */
    public static final String UNABLE_TO_READ_PROPERTY =
            "Unable to read property '%s' from type '%s'";

    /**
     * Error message template for property write failures
     */
    public static final String UNABLE_TO_WRITE_PROPERTY =
            "Unable to write property '%s' to type '%s', expected type was '%s'";

    /**
     * Error message template for runtime property write failures
     */
    public static final String UNABLE_TO_WRITE_PROPERTY_RUNTIME =
            "Unable to write property '%s' to type '%s'";

    /**
     * Reads a property value from a bean using reflection.
     *
     * @param bean         the bean to read from, must not be null
     * @param propertyName the name of the property to read, must not be null or empty
     * @return the value of the property
     * @throws IllegalArgumentException if the property cannot be read or does not exist
     * @since 2.0
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive, isPresent is checked
    public static Object readProperty(Object bean, String propertyName) {
        LOGGER.debug("Reading property '%s' from %s", propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        var reader = MoreReflection.retrieveAccessMethod(bean.getClass(), propertyName);
        Preconditions.checkArgument(reader.isPresent(), UNABLE_TO_READ_PROPERTY, propertyName, bean.getClass());
        try {
            return reader.get().invoke(bean);
        } catch (IllegalAccessException | IllegalArgumentException e) {
            LOGGER.debug("Property read failed due to access restrictions", e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(
                    MoreStrings.lenientFormat(UNABLE_TO_READ_PROPERTY, propertyName, bean.getClass()), e);
        }
        return null;
    }

    /**
     * Writes a value to a property of a bean using reflection.
     * This is a pure command operation with no return value, following Command-Query Separation.
     *
     * @param bean          the bean to write to, must not be null
     * @param propertyName  the name of the property to write, must not be null or empty
     * @param propertyValue the value to write to the property
     * @throws IllegalArgumentException if the property cannot be written or does not exist
     * @since 2.4.1
     */
    public static void setProperty(Object bean, String propertyName, Object propertyValue) {
        writePropertyWithChaining(bean, propertyName, propertyValue);
    }

    /**
     * Writes a value to a property of a bean using reflection and returns the bean for method chaining.
     * This method violates Command-Query Separation by both modifying state and returning a value.
     * Consider using {@link #setProperty(Object, String, Object)} for pure command operations.
     *
     * @param bean          the bean to write to, must not be null
     * @param propertyName  the name of the property to write, must not be null or empty
     * @param propertyValue the value to write to the property
     * @return the bean instance (for method chaining)
     * @throws IllegalArgumentException if the property cannot be written or does not exist
     * @since 2.0
     * @deprecated Use {@link #setProperty(Object, String, Object)} for pure command operations
     */
    @Deprecated(since = "2.4.1")
    public static Object writeProperty(Object bean, String propertyName, Object propertyValue) {
        return writePropertyWithChaining(bean, propertyName, propertyValue);
    }

    /**
     * Internal method for property writing with return value support.
     * Used by PropertyHolder and other internal components that need the return value.
     *
     * @param bean          the bean to write to, must not be null
     * @param propertyName  the name of the property to write, must not be null or empty
     * @param propertyValue the value to write to the property
     * @return the bean instance (for method chaining)
     * @throws IllegalArgumentException if the property cannot be written or does not exist
     */
    static Object writePropertyWithChaining(Object bean, String propertyName, Object propertyValue) {
        LOGGER.debug("Writing '%s' to property '%s' on '%s'", propertyValue, propertyName, bean);
        requireNonNull(bean);
        requireNotEmptyTrimmed(propertyName);
        var writeMethod = determineWriteMethod(bean, propertyName, propertyValue);
        try {
            var result = writeMethod.invoke(bean, propertyValue);
            return Objects.requireNonNullElse(result, bean);
        } catch (IllegalAccessException | IllegalArgumentException e) {
            LOGGER.debug("Property write failed due to access restrictions", e);
        } catch (InvocationTargetException e) {
            var target = propertyValue != null ? propertyValue.getClass().getName() : "Undefined";
            throw new IllegalStateException(
                    MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY_RUNTIME, propertyName, bean.getClass(), target),
                    e);
        }
        return bean;
    }

    /**
     * Resolves the type of property on a given bean class.
     *
     * @param beanClass    the class to inspect, must not be null
     * @param propertyName the name of the property to resolve, must not be null or empty
     * @return an Optional containing the property type if found
     * @since 2.0
     */
    public static Optional<Class<?>> resolvePropertyType(Class<?> beanClass, String propertyName) {
        var retrieveAccessMethod = MoreReflection.retrieveAccessMethod(beanClass, propertyName);
        if (retrieveAccessMethod.isPresent()) {
            LOGGER.trace("Found read-method on class '%s' for property-name '%s'", beanClass, propertyName);
            return Optional.of(retrieveAccessMethod.get().getReturnType());
        }
        var field = MoreReflection.accessField(beanClass, propertyName);
        if (field.isPresent()) {
            LOGGER.trace("Found field on class '%s' with name '%s'", beanClass, propertyName);
            return Optional.of(field.get().getType());
        }
        LOGGER.debug(
                "Neither read-method nor field found on class '%s' for property-name '%s', checking write methods, returning first type found",
                beanClass, propertyName);
        var candidates = MoreReflection.retrieveWriteMethodCandidates(beanClass, propertyName);
        if (!candidates.isEmpty()) {
            return Optional.of(candidates.iterator().next().getParameterTypes()[0]);
        }
        LOGGER.debug("Unable to detect property-type on class '%s' for property-name '%s'", beanClass, propertyName);
        return Optional.empty();
    }

    /**
     * Determines the write method for a property on a bean.
     *
     * @param bean          the bean instance, must not be null
     * @param propertyName  the name of the property, must not be null or empty
     * @param propertyValue the value to be written (used for type checking)
     * @return the write method
     * @throws IllegalArgumentException if no suitable write method is found
     * @since 2.0
     */
    private static Method determineWriteMethod(Object bean, String propertyName, Object propertyValue) {
        var candidates = MoreReflection.retrieveWriteMethodCandidates(bean.getClass(), propertyName);
        var target = propertyValue != null ? propertyValue.getClass().getName() : "Undefined";
        Preconditions.checkArgument(!candidates.isEmpty(), UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(),
                target);
        if (null == propertyValue) {
            LOGGER.trace("No / Null propertyValue given, so any method should suffice to write property '%s' to %s",
                    propertyName, bean);
            return candidates.iterator().next();
        }
        for (Method candidate : candidates) {
            if (MoreReflection.checkWhetherParameterIsAssignable(candidate.getParameterTypes()[0],
                    propertyValue.getClass())) {
                LOGGER.trace("Found method %s to write property '%s' to %s", candidate, propertyName, bean);
                return candidate;
            }
        }
        throw new IllegalArgumentException(
                MoreStrings.lenientFormat(UNABLE_TO_WRITE_PROPERTY, propertyName, bean.getClass(), target));
    }
}
