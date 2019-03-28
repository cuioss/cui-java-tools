package de.icw.util.reflect;

import static com.google.common.base.Strings.emptyToNull;
import static java.util.Objects.requireNonNull;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableList.Builder;

import de.icw.util.logging.Logger;
import lombok.experimental.UtilityClass;

/**
 * Provides a number of methods simplifying the usage of Reflection-based access
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public final class MoreReflection {

    private static final Logger LOG = new Logger(MoreReflection.class);

    /**
     * Tries to access a field on a given type. If none can be found id recursively calls itself
     * with the corresponding parent until {@link Object}
     *
     * @param type to be checked, must not be null
     * @param fieldName to be checked, must not be null
     * @return an {@link Optional} {@link Field} if it can be found
     */
    public static Optional<Field> accessField(final Class<?> type, final String fieldName) {
        requireNonNull(type);
        requireNonNull(fieldName);
        try {
            return Optional.of(type.getDeclaredField(fieldName));
        } catch (final NoSuchFieldException | SecurityException e) {
            LOG.trace(
                    "Error while trying to read field {} on type {}",
                    type, fieldName, e);
            if (Object.class.equals(type.getClass()) || null == type.getSuperclass()) {
                return Optional.empty();
            }
            return accessField(type.getSuperclass(), fieldName);
        }
    }

    /**
     * Determines the public not static methods of a given {@link Class}. {@link Object#getClass()}
     * will implicitly ignored
     *
     * @param clazz to be checked
     * @return the found public-methods.
     */
    public static List<Method> retrievePublicObjectMethods(Class<?> clazz) {
        requireNonNull(clazz);
        List<Method> found = new ArrayList<>();
        for (Method method : clazz.getMethods()) {
            int modifiers = method.getModifiers();
            if (Modifier.isPublic(modifiers) && !Modifier.isStatic(modifiers) && !"getClass".equals(method.getName())) {
                found.add(method);
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
     * @return the found access-methods.
     */
    public static List<Method> retrieveAccessMethods(Class<?> clazz) {
        List<Method> found = new ArrayList<>();
        for (Method method : retrievePublicObjectMethods(clazz)) {
            if (0 == method.getParameterCount()) {
                String name = method.getName();
                if (name.startsWith("get") || name.startsWith("is")) {
                    LOG.debug("Adding found method '{}' on class '{}'", name, clazz);
                    found.add(method);
                }
            } else {
                LOG.trace("Ignoring method '{}' on class '{}'", method.getName(), clazz);
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
    public static List<Method> retrieveAccessMethods(Class<?> clazz, Collection<String> ignoreProperties) {
        List<Method> found = new ArrayList<>();
        for (Method method : retrieveAccessMethods(clazz)) {
            String propertyName = computePropertyNameFromMethodName(method.getName());
            if (!ignoreProperties.contains(propertyName)) {
                found.add(method);
            }
        }
        return found;
    }

    /**
     * Determines the modifier methods of a given class. A modifier method is defined as being a
     * public not static single-argument method that is prefixed with either "set" or consists of
     * the propertyName only
     *
     * @param clazz to be checked
     * @param propertyName to be checked, must not be null
     * @param parameterType identifying the parameter to be passed to the given method, must not be
     *            null
     * @return the found modifier-method or {@link Optional#empty()} if none could be found
     */
    public static Optional<Method> retrieveWriteMethod(Class<?> clazz, String propertyName, Class<?> parameterType) {
        requireNonNull(emptyToNull(propertyName));
        requireNonNull(parameterType);

        for (Method method : retrievePublicObjectMethods(clazz)) {
            if (1 == method.getParameterCount() && method.getParameterTypes()[0].isAssignableFrom(parameterType)) {
                String name = method.getName();
                if (propertyName.equals(name)) {
                    LOG.debug("Returning found method '{}' on class '{}'", name, clazz);
                    return Optional.of(method);
                }
                if (name.startsWith("set") && computePropertyNameFromMethodName(name).equals(propertyName)) {
                    LOG.debug("Returning found method '{}' on class '{}'", name, clazz);
                    return Optional.of(method);
                }
            } else {
                LOG.trace("Ignoring method '{}' on class '{}'", method.getName(), clazz);
            }
        }
        return Optional.empty();
    }

    /**
     * Retrieves the access-method for a given property Name. See
     * {@link #retrieveAccessMethods(Class)} for the definition of an access-method
     *
     * @param clazz
     * @param propertyName
     * @return {@link Optional#empty()} in case no thod could be found, an {@link Optional} with the
     *         found method otherwise.
     */
    public static Optional<Method> retrieveAccessMethod(Class<?> clazz, String propertyName) {
        requireNonNull(emptyToNull(propertyName));
        for (Method method : retrieveAccessMethods(clazz)) {
            if (computePropertyNameFromMethodName(method.getName()).equals(propertyName)) {
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
     *         getName/setName/isName. If none of the prefixes 'get', 'set', 'is' is found it
     *         returns the passed String.
     */
    public static String computePropertyNameFromMethodName(String methodName) {
        requireNonNull(emptyToNull(methodName));

        if (methodName.startsWith("get") || methodName.startsWith("set")) {
            if (methodName.length() > 3) {
                return methodName.substring(3, 4).toLowerCase() + methodName.substring(4);
            } else {
                LOG.debug("Name to short for extracting attributeName '{}'", methodName);
            }
        }
        if (methodName.startsWith("is")) {
            if (methodName.length() > 2) {
                return methodName.substring(2, 3).toLowerCase() + methodName.substring(3);
            } else {
                LOG.debug("Name to short for extracting attributeName '{}'", methodName);
            }
        }
        return methodName;
    }

    /**
     * Helper class for extracting <em>all</em> annotations of a given class including from their
     * ancestors.
     *
     * @param annotatedType the (possibly) annotated type. If it is null or
     *            {@link Object#getClass()} it will return an empty list
     * @param annotation the annotation to be extracted, must not be null
     * @return an immutable List with all annotations found at the given object or one of its
     *         ancestors. May be empty but never null
     */
    public static <A extends Annotation> List<A> extractAllAnnotations(
            final Class<?> annotatedType,
            final Class<A> annotation) {
        if (null == annotatedType || Object.class.equals(annotatedType.getClass())) {
            return Collections.emptyList();
        }
        final Builder<A> builder = ImmutableList.builder();
        builder.addAll(Arrays.asList(annotatedType.getAnnotationsByType(annotation)));
        builder.addAll(extractAllAnnotations(annotatedType.getSuperclass(), annotation));
        return builder.build();
    }

    /**
     * Helper class for extracting an annotation of a given class including from their
     * ancestors.
     *
     * @param annotatedType the (possibly) annotated type. If it is null or
     *            {@link Object#getClass()} {@link Optional#empty()}
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

}
