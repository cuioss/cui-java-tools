package de.cuioss.tools.property;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.string.MoreStrings.requireNotEmptyTrimmed;
import static java.util.Objects.requireNonNull;

import java.beans.Beans;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.reflect.MoreReflection;
import de.cuioss.tools.string.MoreStrings;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * <h2>Overview</h2> An instance of {@link PropertyHolder} provides runtime
 * information for a specific BeanProperty. Under the hood it uses {@link Beans}
 * tooling provided by the JDK and the utilities {@link PropertyUtil} an and
 * {@link MoreReflection}. Compared to the standard tooling it is more flexible
 * regarding fluent api style of bean / DTOs.
 * <h3>Usage</h3>
 * <p>
 * The usual entry-point is {@link #from(Class, String)}. In case you want to
 * create your own instance you can use the contained builder directly using
 * {@link #builder()}
 * </p>
 * <p>
 * Now you can access the metadata for that property, see
 * {@link #getMemberInfo()}, {@link #getName()}, {@link #getType()},
 * {@link #getReadMethod()}
 * </p>
 * <p>
 * Reading and writing of properties should be done by {@link #readFrom(Object)}
 * and {@link #writeTo(Object, Object)}. Directly using {@link #getReadMethod()}
 * and {@link #getWriteMethod()} is more error-prone and less versatile.
 * </p>
 *
 * <h2>Caution:</h2>
 * <p>
 * Use reflection only if there is no other way. Even if some of the problems
 * are minimized by using this type. It should be used either in test-code, what
 * we actually do, and not production code. An other reason could be framework
 * code. as for that you should exactly know what you do.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
@Value
@Builder
public class PropertyHolder {

    private static final String UNABLE_TO_LOAD_PROPERTY_DESCRIPTOR = "Unable to load property-descriptor for attribute '%s' on type '%s'";

    private static final CuiLogger log = new CuiLogger(PropertyHolder.class);

    /** The name of the property. */
    @NonNull
    private final String name;

    /** The actual type of the property. */
    @NonNull
    private final Class<?> type;

    /**
     * Provides additional runtime information for the property, see
     * {@link PropertyMemberInfo}
     */
    @NonNull
    private final PropertyMemberInfo memberInfo;

    /** Provides additional Runtime-information, see {@link PropertyReadWrite} */
    @NonNull
    private final PropertyReadWrite readWrite;

    /** Derived by {@link PropertyDescriptor}, may be null */
    private final Method readMethod;

    /** Derived by {@link PropertyDescriptor}, may be null */
    private final Method writeMethod;

    /**
     * Reads the property on the given bean identified by the concrete
     * {@link PropertyHolder} and the given bean. First it tries to access the
     * readMethod derived by the {@link PropertyDescriptor}. If this can not be
     * achieved, e.g. for types that do not match exactly Java-Bean-Specification it
     * tries to read the property by using
     * {@link PropertyUtil#readProperty(Object, String)}
     *
     * @param bean instance to be read from, must not be null
     * @return the object read from the property
     * @throws IllegalStateException in case the property can not be read, see
     *                               {@link PropertyReadWrite#isReadable()}
     * @throws IllegalStateException in case some Exception occurred while reading
     */
    public Object readFrom(Object bean) {
        log.debug("Reading property '%s' from %s", name, bean);
        requireNonNull(bean);
        Preconditions.checkState(readWrite.isReadable(), "Property '%s' on bean '%s' can not be read", name, bean);
        if (null != readMethod) {
            try {
                return readMethod.invoke(bean);
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                throw new IllegalStateException(
                        MoreStrings.lenientFormat(PropertyUtil.UNABLE_TO_READ_PROPERTY, name, bean.getClass()), e);
            }
        }
        return PropertyUtil.readProperty(bean, name);
    }

    /**
     * @param bean          instance to be read from, must not be null
     * @param propertyValue to be set
     * @return In case the property set method is void the given bean will be
     *         returned. Otherwise, the return value of the method invocation,
     *         assuming the setMethods is a builder / fluent-api type.
     * @throws IllegalStateException in case the property can not be read, see
     *                               {@link PropertyReadWrite#isWriteable()}
     * @throws IllegalStateException in case some Exception occurred while writing
     */
    public Object writeTo(Object bean, Object propertyValue) {
        log.debug("Writing %s to property '%s' on %s", propertyValue, name, bean);
        requireNonNull(bean);
        Preconditions.checkState(readWrite.isWriteable(), "Property '%s' on bean '%s' can not be written", name, bean);
        if (null != writeMethod) {
            try {
                var result = writeMethod.invoke(bean, propertyValue);
                return Objects.requireNonNullElse(result, bean);
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                throw new IllegalStateException(
                        MoreStrings.lenientFormat(PropertyUtil.UNABLE_TO_WRITE_PROPERTY_RUNTIME, name, bean.getClass()),
                        e);
            }
        }
        return PropertyUtil.writeProperty(bean, name, propertyValue);
    }

    /**
     * Factory Method for creating a concrete {@link PropertyHolder}
     *
     * @param beanType      must not be null
     * @param attributeName must not be null nor empty
     * @return the concrete {@link PropertyHolder} for the given parameter if
     *         applicable
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
