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
 * <p>
 * To create a new instance, use {@code PropertyHolder.builder().build()}.
 * </p>
 * <p>
 * The holder provides access to property metadata through its accessor methods:
 * {@code getMemberInfo()}, {@code getName()}, {@code getType()},
 * {@code getReadMethod()}, and {@code getWriteMethod()}.
 * </p>
 * <p>
 * For type-safe access, use {@code readFrom(Object)} and {@code writeTo(Object, Object)}.
 * Direct method access is more error-prone and less versatile.
 * </p>
 *
 * @author Oliver Wolff
 */
@Value
@Builder
public class PropertyHolder {

    private static final String UNABLE_TO_LOAD_PROPERTY_DESCRIPTOR = "Unable to load property-descriptor for attribute '%s' on type '%s'";

    private static final CuiLogger log = new CuiLogger(PropertyHolder.class);

    /**
     * The name of the property.
     */
    @NonNull
    String name;

    /**
     * The actual type of the property.
     */
    @NonNull
    Class<?> type;

    /**
     * Provides additional runtime information for the property, see
     * {@link PropertyMemberInfo}
     */
    @NonNull
    PropertyMemberInfo memberInfo;

    /**
     * Provides additional Runtime-information, see {@link PropertyReadWrite}
     */
    @NonNull
    PropertyReadWrite readWrite;

    /**
     * Derived by {@link PropertyDescriptor}, may be null
     */
    Method readMethod;

    /**
     * Derived by {@link PropertyDescriptor}, may be null
     */
    Method writeMethod;

    /**
     * Reads the property on the given bean identified by the concrete
     * {@link PropertyHolder} and the given bean. First it tries to access the
     * readMethod derived by the {@link PropertyDescriptor}. If this can not be
     * achieved, e.g. for types that do not match exactly Java-Bean-Specification it
     * tries to read the property by using
     * {@link PropertyUtil#readProperty(Object, String)}
     *
     * @param source instance to be read from, must not be null
     * @return the object read from the property
     * @throws IllegalArgumentException if the source is null or if the property is not
     *                                  readable according to {@code isReadable()}
     */
    public Object readFrom(Object source) {
        log.debug("Reading property '%s' from %s", name, source);
        requireNonNull(source);
        Preconditions.checkState(readWrite.isReadable(), "Property '%s' on bean '%s' can not be read", name, source);
        if (null != readMethod) {
            try {
                return readMethod.invoke(source);
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                throw new IllegalStateException(
                        MoreStrings.lenientFormat(PropertyUtil.UNABLE_TO_READ_PROPERTY, name, source.getClass()), e);
            }
        }
        return PropertyUtil.readProperty(source, name);
    }

    /**
     * @param target must not be null
     * @param value  to be written
     * @return In case the property set method is void the given bean will be
     * returned. Otherwise, the return value of the method invocation,
     * assuming the setMethods is a builder / fluent-api type.
     * @throws IllegalArgumentException if the target is null or if the property is not
     *                                  writeable according to {@code isWriteable()}
     */
    public Object writeTo(Object target, Object value) {
        log.debug("Writing %s to property '%s' on %s", value, name, target);
        requireNonNull(target);
        Preconditions.checkState(readWrite.isWriteable(), "Property '%s' on bean '%s' can not be written", name, target);
        if (null != writeMethod) {
            try {
                var result = writeMethod.invoke(target, value);
                return Objects.requireNonNullElse(result, target);
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                throw new IllegalStateException(
                        MoreStrings.lenientFormat(PropertyUtil.UNABLE_TO_WRITE_PROPERTY_RUNTIME, name, target.getClass()),
                        e);
            }
        }
        return PropertyUtil.writeProperty(target, name, value);
    }

    /**
     * Factory Method for creating a concrete {@link PropertyHolder}
     *
     * @param beanType      must not be null
     * @param attributeName must not be null nor empty
     * @return the concrete {@link PropertyHolder} for the given parameter if
     * applicable
     * @throws IllegalArgumentException for cases where {@link Introspector} is not
     *                                  capable of resolving a
     *                                  {@link PropertyDescriptor}. This is usually
     *                                  the case if it is not a valid bean.
     */
    public static Optional<PropertyHolder> from(Class<?> beanType, String attributeName) {
        requireNonNull(beanType);
        requireNotEmptyTrimmed(attributeName);
        try {
            var info = Introspector.getBeanInfo(beanType);
            var descriptor = mutableList(info.getPropertyDescriptors()).stream()
                    .filter(desc -> attributeName.equalsIgnoreCase(desc.getName())).findFirst();
            if (descriptor.isEmpty()) {
                log.debug(UNABLE_TO_LOAD_PROPERTY_DESCRIPTOR, attributeName, beanType);
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
        log.trace("Trying reflection for determining attribute '%s' on type '%s'", attributeName, beanType);
        var field = MoreReflection.accessField(beanType, attributeName);
        if (field.isEmpty()) {
            return Optional.empty();
        }
        var builder = builder();
        builder.name(attributeName);
        builder.readWrite(PropertyReadWrite.resolveForBean(beanType, attributeName));
        builder.memberInfo(PropertyMemberInfo.resolveForBean(beanType, attributeName));
        builder.type(PropertyUtil.resolvePropertyType(beanType, attributeName).orElse(Object.class));
        return Optional.of(builder.build());
    }

}
