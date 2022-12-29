package io.cui.tools.reflect;

import static io.cui.tools.collect.MoreCollections.requireNotEmpty;
import static java.util.Objects.requireNonNull;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.WeakHashMap;

import io.cui.tools.base.Preconditions;
import io.cui.tools.collect.CollectionBuilder;
import io.cui.tools.logging.CuiLogger;
import lombok.Synchronized;
import lombok.experimental.UtilityClass;

/**
 * Provides a number of methods simplifying the usage of Reflection-based access.
 * <h2>Caution</h2>
 * <p>
 * Use reflection only if there is no other way. Even if some of the problems are
 * minimized by using this type. It should be used either in test-code, what is we actually do, and
 * not production code. An other reason could be framework code. as for that you should exactly know
 * what you do.
 * </p>
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class MoreReflection {

    private static final String IGNORING_METHOD_ON_CLASS = "Ignoring method '{}' on class '{}'";

    private static final CuiLogger log = new CuiLogger(MoreReflection.class);

    /** We use {@link WeakHashMap} in order to allow the garbage collector to do its job */
    private static final Map<Class<?>, List<Method>> publicObjectMethodCache = new WeakHashMap<>();

    private static final Map<Class<?>, Map<String, Field>> fieldCache = new WeakHashMap<>();

    /**
     * Tries to access a field on a given type. If none can be found it recursively calls itself
     * with the corresponding parent until {@link Object}.
     * <em>Caution:</em>
     * <p>
     * The field elements are shared between requests (cached), therefore you must
     * ensure that changes to the instance, like {@link Field#setAccessible(boolean)} are reseted
     * by the client. This can be simplified by using {@link FieldWrapper}
     * </p>
     *
     * @param type to be checked, must not be null
     * @param fieldName to be checked, must not be null
     * @return an {@link Optional} {@link Field} if it can be found
     */
    @Synchronized
    @SuppressWarnings("java:S3824") // owolff: computeIfAbsent is not an option because we add null
                                    // to the field
    public static Optional<Field> accessField(final Class<?> type, final String fieldName) {
        requireNonNull(type);
        requireNonNull(fieldName);
        if (!fieldCache.containsKey(type)) {
            fieldCache.put(type, new HashMap<>());
        }
        final Map<String, Field> typeMap = fieldCache.get(type);
        if (!typeMap.containsKey(fieldName)) {
            typeMap.put(fieldName, resolveField(type, fieldName).orElse(null));
        }
        return Optional.ofNullable(typeMap.get(fieldName));
    }

    private static Optional<Field> resolveField(final Class<?> type, final String fieldName) {
        try {
            return Optional.of(type.getDeclaredField(fieldName));
        } catch (final NoSuchFieldException | SecurityException e) {
            log.trace(
                    "Error while trying to read field {} on type {}",
                    type, fieldName, e);
            if (Object.class.equals(type.getClass()) || null == type.getSuperclass()) {
                return Optional.empty();
            }
            return resolveField(type.getSuperclass(), fieldName);
        }
    }

    /**
     * Determines the public not static methods of a given {@link Class}. {@link Object#getClass()}
     * will implicitly ignore
     *
     * @param clazz to be checked
     * @return the found public-methods.
     */
    @Synchronized
    public static List<Method> retrievePublicObjectMethods(final Class<?> clazz) {
        requireNonNull(clazz);

        if (!publicObjectMethodCache.containsKey(clazz)) {
            final List<Method> found = new ArrayList<>();
            for (final Method method : clazz.getMethods()) {
                final int modifiers = method.getModifiers();
                if (Modifier.isPublic(modifiers) && !Modifier.isStatic(modifiers)
                        && !"getClass".equals(method.getName())) {
                    found.add(method);
                }
            }
            publicObjectMethodCache.put(clazz, found);
            return found;
        }
        return publicObjectMethodCache.get(clazz);
    }

    /**
     * Determines the access methods of a given class. An access method is defined as being a public
     * not static zero-argument method that is prefixed with either "get" or "is". The Method
     * "getClass" is explicitly filtered
     *
     * @param clazz to be checked
     * @return the found access-methods.
     */
    public static List<Method> retrieveAccessMethods(final Class<?> clazz) {
        final List<Method> found = new ArrayList<>();
        for (final Method method : retrievePublicObjectMethods(clazz)) {
            if (0 == method.getParameterCount()) {
                final String name = method.getName();
                if (name.startsWith("get") || name.startsWith("is")) {
                    log.debug("Adding found method '{}' on class '{}'", name, clazz);
                    found.add(method);
                }
            } else {
                log.trace(IGNORING_METHOD_ON_CLASS, method.getName(), clazz);
            }
        }
        return found;
    }

    /**
     * Determines the access methods of a given class. An access method is defined as being a public
     * not static zero-argument method that is prefixed with either "get" or "is". The Method
     * "getClass" is explicitly filtered
     *
     * @param clazz to be checked
     * @param ignoreProperties identifies the property by name that must be filtered from the result
     * @return the found access-methods.
     */
    public static List<Method> retrieveAccessMethods(final Class<?> clazz, final Collection<String> ignoreProperties) {
        final List<Method> found = new ArrayList<>();
        for (final Method method : retrieveAccessMethods(clazz)) {
            final String propertyName = computePropertyNameFromMethodName(method.getName());
            if (!ignoreProperties.contains(propertyName)) {
                found.add(method);
            }
        }
        return found;
    }

    /**
     * Determines the modifier methods of a given class. A modifier method is defined as being a
     * public not static single-argument method that is prefixed with either "set" or consists of
     * the propertyName only.
     *
     * @param clazz to be checked
     * @param propertyName to be checked, must not be null
     * @param parameterType identifying the parameter to be passed to the given method, must not be
     *            null
     * @return the found modifier-method or {@link Optional#empty()} if none could be found
     */
    public static Optional<Method> retrieveWriteMethod(final Class<?> clazz, final String propertyName,
            final Class<?> parameterType) {
        requireNonNull(parameterType);

        for (final Method method : retrieveWriteMethodCandidates(clazz, propertyName)) {
            if (checkWhetherParameterIsAssignable(method.getParameterTypes()[0], parameterType)) {
                return Optional.of(method);
            } else {
                log.trace(IGNORING_METHOD_ON_CLASS, method.getName(), clazz);
            }
        }
        return Optional.empty();
    }

    /**
     * @param assignableSource the type to be checked
     * @param queryType to be checked for
     * @return boolean indicating whether the given parameter, identified by their class attributes
     *         match
     */
    public static boolean checkWhetherParameterIsAssignable(final Class<?> assignableSource, final Class<?> queryType) {
        requireNonNull(assignableSource);
        requireNonNull(queryType);
        if (assignableSource.equals(queryType)) {
            log.trace("Parameter-type matches exactly '%s'", assignableSource);
            return true;
        }
        if (assignableSource.isAssignableFrom(queryType)) {
            log.trace("Parameter '%s' is assignable from '%s'", assignableSource, queryType);
            return true;
        }
        final Class<?> boxedSource = resolveWrapperTypeForPrimitive(assignableSource);
        final Class<?> boxedQuery = resolveWrapperTypeForPrimitive(queryType);
        if (boxedSource.equals(boxedQuery)) {
            log.trace("Parameter-type matches exactly after autoboxing '%s'", assignableSource);
            return true;
        }
        return boxedSource.isAssignableFrom(boxedQuery);
    }

    /**
     * Helper class for converting a primitive to a wrapper type.
     *
     * @param check must not be null
     * @return the wrapper type if the given type represents a primitive, the given type otherwise.
     */
    static Class<?> resolveWrapperTypeForPrimitive(final Class<?> check) {
        if (!check.isPrimitive()) {
            return check;
        }
        switch (check.getName()) {
            case "boolean":
                return Boolean.class;
            case "byte":
                return Byte.class;
            case "char":
                return Character.class;
            case "short":
                return Short.class;
            case "int":
                return Integer.class;
            case "long":
                return Long.class;
            case "double":
                return Double.class;
            case "float":
                return Float.class;
            default:
                log.warn("Unable to determine wrapper type for '{}', ", check);
                return check;
        }
    }

    /**
     * Determines the modifier methods of a given class for a property. A modifier method is defined
     * as being a public not static single-argument method that is prefixed with either "set" or
     * consists of the ropertyName only. This
     * will implicitly return all possible setter or builder methods, e.g.
     * {@code setPropertyName(String name)}, {@code propertyName(String name)} and
     * {@code setPropertyName(Collection<String> name)} will all be part of
     * the result.
     *
     * @param clazz to be checked
     * @param propertyName to be checked, must not be null
     * @return the found modifier-methods or an empty {@link Collection} if none could be found
     */
    public static Collection<Method> retrieveWriteMethodCandidates(final Class<?> clazz, final String propertyName) {
        requireNotEmpty(propertyName);
        final CollectionBuilder<Method> builder = new CollectionBuilder<>();
        for (final Method method : retrievePublicObjectMethods(clazz)) {
            if (1 == method.getParameterCount()) {
                final String name = method.getName();
                if (propertyName.equals(name)) {
                    log.debug("Returning found method '{}' on class '{}'", name, clazz);
                    builder.add(method);
                }
                if (name.startsWith("set") && computePropertyNameFromMethodName(name).equalsIgnoreCase(propertyName)) {
                    log.debug("Returning found method '{}' on class '{}'", name, clazz);
                    builder.add(method);
                }
            } else {
                log.trace(IGNORING_METHOD_ON_CLASS, method.getName(), clazz);
            }
        }
        return builder.toImmutableList();
    }

    /**
     * Retrieves the access-method for a given property Name. See
     * {@link #retrieveAccessMethods(Class)} for the
     * definition of an access-method
     *
     * @param clazz must not be null
     * @param propertyName to be accessed
     * @return {@link Optional#empty()} in case no method could be found, an {@link Optional} with
     *         the found method
     *         otherwise.
     */
    public static Optional<Method> retrieveAccessMethod(final Class<?> clazz, final String propertyName) {
        requireNotEmpty(propertyName);
        for (final Method method : retrieveAccessMethods(clazz)) {
            if (computePropertyNameFromMethodName(method.getName()).equalsIgnoreCase(propertyName)) {
                return Optional.of(method);
            }
        }
        return Optional.empty();
    }

    /**
     * Helper method that extract the property-name from a given accessor-method name.
     *
     * @param methodName must not be null nor empty
     * @return the possible attribute name of a given method-name, e.g. it return 'name' for
     *         getName/setName/isName. If
     *         none of the prefixes 'get', 'set', 'is' is found it returns the passed String.
     */
    public static String computePropertyNameFromMethodName(final String methodName) {
        requireNotEmpty(methodName);

        if (methodName.startsWith("get") || methodName.startsWith("set")) {
            if (methodName.length() > 3) {
                return methodName.substring(3, 4).toLowerCase() + methodName.substring(4);
            } else {
                log.debug("Name to short for extracting attributeName '{}'", methodName);
            }
        }
        if (methodName.startsWith("is")) {
            if (methodName.length() > 2) {
                return methodName.substring(2, 3).toLowerCase() + methodName.substring(3);
            } else {
                log.debug("Name to short for extracting attributeName '{}'", methodName);
            }
        }
        return methodName;
    }

    /**
     * Helper class for extracting <em>all</em> annotations of a given class including from their
     * ancestors.
     *
     * @param <A> the concrete annotation type
     * @param annotatedType the (possibly) annotated type. If it is null or
     *            {@link Object#getClass()} it will return an
     *            empty list
     * @param annotation the annotation to be extracted, must not be null
     * @return an immutable List with all annotations found at the given object or one of its
     *         ancestors. May be empty
     *         but never null
     */
    public static <A extends Annotation> List<A> extractAllAnnotations(
            final Class<?> annotatedType,
            final Class<A> annotation) {
        if (null == annotatedType || Object.class.equals(annotatedType.getClass())) {
            return Collections.emptyList();
        }

        final CollectionBuilder<A> builder = new CollectionBuilder<>();
        builder.add(annotatedType.getAnnotationsByType(annotation));
        builder.add(extractAllAnnotations(annotatedType.getSuperclass(), annotation));
        return builder.toImmutableList();
    }

    /**
     * Helper class for extracting an annotation of a given class including from their ancestors.
     *
     * @param <A> the concrete annotation type
     * @param annotatedType the (possibly) annotated type. If it is null or
     *            {@link Object#getClass()} {@link
     *            Optional#empty()}
     * @param annotation the annotation to be extracted, must not be null
     * @return an {@link Optional} on the annotated Object if the annotation can be found. In case
     *         the annotation is found multiple times the first element will be returned.
     */
    public static <A extends Annotation> Optional<A> extractAnnotation(
            final Class<?> annotatedType, final Class<A> annotation) {
        requireNonNull(annotation);
        final List<A> extracted = extractAllAnnotations(annotatedType, annotation);
        if (extracted.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(extracted.iterator().next());
    }

    /**
     * Extracts the first generic type argument for the given type.
     *
     * @param <T> identifying the type to be looked for
     * @param typeToBeExtractedFrom must not be null
     * @return an {@link Optional} of the KeyStoreType-Argument of the given class.
     * @throws IllegalArgumentException in case the given type does not represent a generic.
     */
    @SuppressWarnings("unchecked") // owolff: The unchecked casting is necessary
    public static <T> Class<T> extractFirstGenericTypeArgument(final Class<?> typeToBeExtractedFrom) {
        final ParameterizedType parameterizedType = extractParameterizedType(typeToBeExtractedFrom).orElseThrow(
                () -> new IllegalArgumentException(
                        "Given type defines no generic KeyStoreType: " + typeToBeExtractedFrom));

        requireNotEmpty(parameterizedType.getActualTypeArguments(),
                "No type argument found for " + typeToBeExtractedFrom.getName());

        final Class<?> firstType =
            extractGenericTypeCovariantly(parameterizedType.getActualTypeArguments()[0]).orElseThrow(
                    () -> new IllegalArgumentException("Unable to determine genric type for " + typeToBeExtractedFrom));

        try {
            return (Class<T>) firstType;
        } catch (final ClassCastException e) {
            throw new IllegalArgumentException(
                    "No type argument can be extracted from " + typeToBeExtractedFrom.getName(), e);
        }
    }

    /**
     * @param type to be extracted from
     * @return if applicable the actual type argument for the given type. If the type represents
     *         already a {@link Class}
     *         it will be returned directly. Otherwise, the super-type will be checked by calling
     *         the superclass
     */
    @SuppressWarnings("rawtypes")
    public static Optional<Class<?>> extractGenericTypeCovariantly(final Type type) {
        if (null == type) {
            log.trace("No KeyStoreType given, returning empty");
            return Optional.empty();
        }
        if (type instanceof Class) {
            log.debug("Found actual class returning as result {}", type);
            return Optional.of((Class) type);
        }
        if (type instanceof ParameterizedType) {
            log.debug("found Parameterized type, for {}, calling recursively", type);
            return extractGenericTypeCovariantly(((ParameterizedType) type).getRawType());
        }
        log.warn("Unable to determines generic-type for {}", type);
        return Optional.empty();
    }

    /**
     * Extracts a {@link ParameterizedType} view for the given type
     *
     * @param typeToBeExtractedFrom must not be null
     * @return an {@link Optional} of the {@link ParameterizedType} view of the given class.
     */
    public static Optional<ParameterizedType> extractParameterizedType(final Class<?> typeToBeExtractedFrom) {
        log.debug("Extracting ParameterizedType from {}", typeToBeExtractedFrom);
        if (null == typeToBeExtractedFrom) {
            return Optional.empty();
        }
        if (Object.class.equals(typeToBeExtractedFrom)) {
            log.debug("java.lang.Object is not a ParameterizedType");
            return Optional.empty();
        }
        final Type genericSuperclass = typeToBeExtractedFrom.getGenericSuperclass();
        if (genericSuperclass instanceof ParameterizedType) {
            return Optional.of((ParameterizedType) genericSuperclass);
        }
        // Check the tree
        return extractParameterizedType(typeToBeExtractedFrom.getSuperclass());
    }

    /**
     * Returns a proxy instance that implements {@code interfaceType} by dispatching method
     * invocations to {@code handler}. The class loader of {@code interfaceType} will be used to
     * define the proxy class. To implement multiple
     * interfaces or specify a class loader, use Proxy#newProxyInstance(Class, Constructor,
     * InvocationHandler).
     *
     * @param interfaceType must not be null
     * @param handler the invocation handler
     * @param <T> the target type of the proxy
     * @return the created Proxy-instance
     * @throws IllegalArgumentException if {@code interfaceType} does not specify the type of Java
     *             interface
     * @author https://github.com/google/guava/blob/master/guava/src/com/google/common/reflect/Reflection.java
     */
    public static <T> T newProxy(final Class<T> interfaceType, final InvocationHandler handler) {
        requireNonNull(handler);
        Preconditions.checkArgument(interfaceType.isInterface(), "%s is not an interface", interfaceType);
        final Object object =
            Proxy.newProxyInstance(
                    interfaceType.getClassLoader(), new Class<?>[] { interfaceType }, handler);
        return interfaceType.cast(object);
    }

    /**
     * Try to detect class from call stack which was the previous, before the marker class name
     *
     * @param markerClasses class names which could be used as marker before the real caller name.
     *            Collection must not
     *            be {@code null}.
     * @return option of detected caller class name
     */
    public static Optional<String> findCaller(final Collection<String> markerClasses) {
        final Optional<StackTraceElement> callerElement = findCallerElement(null, markerClasses);
        return callerElement.map(StackTraceElement::getClassName);
    }

    /**
     * Tries to detect class from call stack which was the previous, before the marker class name
     *
     * @param throwable is an optional parameter, will be used to access the stack
     * @param markerClasses class names which could be used as marker before the real caller name.
     *            Collection must not be {@code null}.
     * @return option of detected caller class name
     */
    public static Optional<StackTraceElement> findCallerElement(final Throwable throwable,
            final Collection<String> markerClasses) {

        Objects.requireNonNull(markerClasses, "Marker class names are missing");

        final StackTraceElement[] stackTraceElements;
        if (null == throwable) {
            stackTraceElements = Thread.currentThread().getStackTrace();
        } else {
            stackTraceElements = throwable.getStackTrace();
        }
        if (null == stackTraceElements || stackTraceElements.length < 5) {
            return Optional.empty();
        }
        for (int index = 2; index < stackTraceElements.length; index++) {
            final StackTraceElement element = stackTraceElements[index];
            if (markerClasses.contains(element.getClassName())) {
                if (stackTraceElements.length > index + 1) {
                    return Optional.of(stackTraceElements[index + 1]);
                } else {
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

}
