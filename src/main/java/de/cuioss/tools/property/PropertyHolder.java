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
package de.cuioss.tools.property;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.reflect.MoreReflection;
import de.cuioss.tools.string.MoreStrings;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.util.Objects.requireNonNull;

/**
 * Represents a property of a class, providing type-safe access to its value.
 * This class wraps a property (field or method) and provides type-safe access
 * to read and write operations.
 *
 * <h2>Usage</h2>
 * <pre>
 * // Create a property holder for a field
 * PropertyHolder holder = PropertyHolder.builder()
 *     .name("fieldName")
 *     .type(String.class)
 *     .memberInfo(PropertyMemberInfo.FIELD)
 *     .readWrite(PropertyReadWrite.READ_WRITE)
 *     .build();
 *
 * // Read value
 * String value = holder.readFrom(bean);
 *
 * // Write value
 * holder.writeTo(bean, "newValue");
 * </pre>
 *
 * <h2>Error Handling</h2>
 * <ul>
 *   <li>All builder properties marked with {@code @NonNull} must be provided</li>
 *   <li>Property name must not be empty or blank</li>
 *   <li>Type must match the actual property type for type-safe operations</li>
 *   <li>Read/write operations will throw {@code IllegalStateException} if the corresponding method is not available</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 2.0
 */
@Value
@Builder
public class PropertyHolder {

    private static final String UNABLE_TO_LOAD_PROPERTY_DESCRIPTOR = "Unable to load property-descriptor for attribute '%s' on type '%s'";
    private static final String NO_READ_METHOD = "No read method available for property '%s'";
    private static final String NO_WRITE_METHOD = "No write method available for property '%s'. Check if the property has a setter method or a builder-style method.";
    private static final String TYPE_MISMATCH = "Value type mismatch for property '%s'. Expected: %s, Got: %s";

    private static final CuiLogger LOGGER = new CuiLogger(PropertyHolder.class);

    /**
     * The name of the property. Must not be empty or blank.
     */
    @NonNull
    String name;

    /**
     * The actual type of the property. Must not be null.
     */
    @NonNull
    Class<?> type;

    /**
     * Provides additional runtime information for the property.
     * See {@link PropertyMemberInfo} for details.
     */
    @NonNull
    PropertyMemberInfo memberInfo;

    /**
     * Defines the read/write capabilities of this property.
     * See {@link PropertyReadWrite} for details.
     */
    @NonNull
    PropertyReadWrite readWrite;

    /**
     * Method for reading the property value, derived from {@link PropertyDescriptor}.
     * May be null if the property is write-only.
     */
    Method readMethod;

    /**
     * Method for writing the property value, derived from {@link PropertyDescriptor}.
     * May be null if the property is read-only.
     */
    Method writeMethod;

    /**
     * Reads the property value from the given bean.
     *
     * @param source the bean to read from, must not be null
     * @return the property value, may be null
     * @throws IllegalStateException if no read method is available
     * @throws IllegalArgumentException if the bean is null
     */
    public Object readFrom(Object source) {
        LOGGER.debug("Reading property '%s' from %s", name, source);
        requireNonNull(source, "Bean must not be null");
        Preconditions.checkState(readWrite.isReadable(), "Property '%s' on bean '%s' can not be read", name, source);
        if (null == readMethod) {
            throw new IllegalStateException(NO_READ_METHOD.formatted(name));
        }
        try {
            return readMethod.invoke(source);
        } catch (IllegalAccessException | InvocationTargetException e) {
            LOGGER.error("Failed to read property '{}' from bean of type '{}'", name, source.getClass().getName(), e);
            throw new IllegalStateException("Failed to read property: " + name, e);
        }
    }

    /**
     * Writes the given value to the property of the bean.
     * This method supports both traditional setters and builder-style methods.
     *
     * <h2>Builder-Style Support</h2>
     * For builder-style methods (methods that return the bean instance), the method
     * will return the builder instance. This enables fluent method chaining.
     *
     * @param target the bean to write to, must not be null
     * @param value the value to write, may be null if the property type allows it
     * @return In case the property set method is void the given bean will be returned.
     *         Otherwise, the return value of the method invocation, assuming the setMethod
     *         is a builder / fluent-api type.
     * @throws IllegalArgumentException if the bean is null or if the property is not
     *                                  writeable according to the property's write permissions
     * @throws IllegalStateException if no write method is available or if the write operation fails
     * @since 2.0
     */
    public Object writeTo(Object target, Object value) {
        LOGGER.debug("Writing %s to property '%s' on %s", value, name, target);
        requireNonNull(target, "Bean must not be null");
        Preconditions.checkState(readWrite.isWriteable(), "Property '%s' on bean '%s' can not be written", name, target);

        if (writeMethod != null) {
            if (value != null && !type.isInstance(value)) {
                throw new IllegalArgumentException(TYPE_MISMATCH.formatted(name, type.getName(), value.getClass().getName()));
            }
            try {
                var result = writeMethod.invoke(target, value);
                return Objects.requireNonNullElse(result, target);
            } catch (IllegalAccessException | InvocationTargetException e) {
                LOGGER.error("Failed to write property '{}' to bean of type '{}'", name, target.getClass().getName(), e);
                throw new IllegalStateException("Failed to write property: " + name, e);
            }
        }

        // Fallback to PropertyUtil for builder-style methods
        return PropertyUtil.writeProperty(target, name, value);
    }

    /**
     * Factory Method for creating a concrete {@link PropertyHolder}.
     * This method supports both traditional Java Bean properties and builder-style
     * properties.
     *
     * <h2>Property Resolution</h2>
     * <ul>
     *   <li>First attempts to resolve using standard Java Bean conventions</li>
     *   <li>Falls back to builder-style methods if standard resolution fails</li>
     *   <li>Supports generics with proper type resolution</li>
     * </ul>
     *
     * @param beanType      the type to create the holder for, must not be null
     * @param attributeName the name of the property to access, must not be null nor empty
     * @return an {@link Optional} containing the concrete {@link PropertyHolder} if
     *         applicable
     * @throws IllegalArgumentException if {@link Introspector} is not capable of resolving
     *                                  a {@link PropertyDescriptor}.
     *                                  This usually occurs with invalid Java beans.
     * @since 2.0
     */
    public static Optional<PropertyHolder> from(Class<?> beanType, String attributeName) {
        requireNonNull(beanType);
        requireNotEmptyTrimmed(attributeName);
        try {
            var info = Introspector.getBeanInfo(beanType);
            var descriptor = mutableList(info.getPropertyDescriptors()).stream()
                    .filter(desc -> attributeName.equalsIgnoreCase(desc.getName())).findFirst();
            if (descriptor.isEmpty()) {
                LOGGER.debug("Property '%s' not found within %s", attributeName, beanType);
                return buildByReflection(beanType, attributeName);
            }
            return doBuild(descriptor.get(), beanType, attributeName);
        } catch (IntrospectionException e) {
            throw new IllegalArgumentException(
                    MoreStrings.lenientFormat(UNABLE_TO_LOAD_PROPERTY_DESCRIPTOR, attributeName, beanType), e);
        }
    }

    private static Optional<PropertyHolder> doBuild(PropertyDescriptor propertyDescriptor, Class<?> type,
            String attributeName) {
        var builder = builder();
        builder.name(attributeName);
        builder.readWrite(PropertyReadWrite.fromPropertyDescriptor(propertyDescriptor, type, attributeName));
        builder.readMethod(propertyDescriptor.getReadMethod());
        builder.writeMethod(propertyDescriptor.getWriteMethod());
        builder.memberInfo(PropertyMemberInfo.resolveForBean(type, attributeName));
        builder.type(propertyDescriptor.getPropertyType());
        return Optional.of(builder.build());
    }

    static Optional<PropertyHolder> buildByReflection(Class<?> beanType, String attributeName) {
        LOGGER.trace("Trying reflection for determining attribute '%s' on type '%s'", attributeName, beanType);
        var field = MoreReflection.accessField(beanType, attributeName);
        if (field.isEmpty()) {
            LOGGER.debug("Property '%s' not found within %s", attributeName, beanType);
            return Optional.empty();
        }
        var builder = builder();
        builder.name(attributeName);
        builder.readWrite(PropertyReadWrite.resolveForBean(beanType, attributeName));
        builder.memberInfo(PropertyMemberInfo.resolveForBean(beanType, attributeName));
        builder.type(PropertyUtil.resolvePropertyType(beanType, attributeName).orElse(Object.class));
        return Optional.of(builder.build());
    }

    public PropertyHolder build() {
        requireNonNull(name, "name must not be null");
        requireNonNull(type, "type must not be null");
        requireNonNull(memberInfo, "memberInfo must not be null");
        requireNonNull(readWrite, "readWrite must not be null");
        return new PropertyHolder(name, type, memberInfo, readWrite, readMethod, writeMethod);
    }
}
