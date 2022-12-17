package io.cui.util.support;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Method;

import lombok.experimental.UtilityClass;

/**
 * Simple Helper for reflection-api.
 * Like many other methods of this test-framework, the methods use rather asserts /
 * {@link AssertionError} to check preconditions and states than {@link Exception}
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class ReflectionUtil {

    static final String METHOD_NAME_OBJECT_EQUALS = "equals";
    static final String METHOD_NAME_OBJECT_HASH_CODE = "hashCode";
    static final String METHOD_NAME_OBJECT_TO_STRING = "toString";

    /**
     * Verify the class implements {@link Object#equals(Object)}
     *
     * @param clazz
     *            class to be checked, msut not be null
     */
    public static void assertEqualsMethodIsOverriden(final Class<?> clazz) {
        // equals method need an object as parameter
        final Class<?>[] args1 = new Class[1];
        args1[0] = Object.class;

        // get equals method of the class
        final Method method = getMethodFromClass(clazz, METHOD_NAME_OBJECT_EQUALS, args1);
        final String assertText =
            "Method 'equals' not implemented in the class : " + clazz.getName();
        assertJavaLangObjectMethodWasOverridden(assertText, method);
    }

    /**
     * Verify the class implements {@link Object#hashCode()}
     *
     * @param clazz
     *            class to be checked, must not be null
     */
    public static void assertHashCodeMethodIsOverriden(final Class<?> clazz) {
        final Method method = getMethodFromClass(clazz, METHOD_NAME_OBJECT_HASH_CODE, null);
        final String assertText =
            "Method 'hashCode' not implemented in the class : " + clazz.getName();
        assertJavaLangObjectMethodWasOverridden(assertText, method);
    }

    /**
     * Verify the class implements {@link Object#hashCode()}
     *
     * @param clazz
     *            class to be checked, must not be null
     */
    public static void assertToStringMethodIsOverriden(final Class<?> clazz) {
        final Method method = getMethodFromClass(clazz, METHOD_NAME_OBJECT_TO_STRING, null);
        final String assertText =
            "Method 'toString' not implemented in the class : " + clazz.getName();
        assertJavaLangObjectMethodWasOverridden(assertText, method);
    }

    /**
     * Check if the method is not a {@link Object} implementation
     *
     * @param assertText
     *            text to display on fail
     * @param method
     *            {@linkplain Method} to verify
     */
    private static void assertJavaLangObjectMethodWasOverridden(final String assertText,
            final Method method) {

        assertNotNull(method, assertText);
        // does java.lang.Object provide the method?
        assertNotEquals(Object.class, method.getDeclaringClass(), assertText);
    }

    /**
     * Retrieve method from class according parameters
     *
     * @param clazz
     *            class object under test
     * @param methodName
     *            string name of method
     * @param args1
     *            parameter object for method
     * @return {@link Method} if exists. if not an assertionError will be thrown.
     */
    private static Method getMethodFromClass(final Class<?> clazz, final String methodName,
            final Class<?>[] args1) {
        assertNotNull(clazz, "Target for test is null");
        Method result = null;
        try {
            if (null != args1) {
                result = clazz.getMethod(methodName, args1);
            } else {
                result = clazz.getMethod(methodName);
            }
        } catch (final SecurityException | NoSuchMethodException e) {
            throw new AssertionError(e);
        }
        assertNotNull(result, "Method " + methodName + " does not exist on " + clazz);
        return result;
    }
}
