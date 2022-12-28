package io.cui.tools.lang;

import static io.cui.tools.string.MoreStrings.isEmpty;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import io.cui.tools.logging.CuiLogger;
import lombok.experimental.UtilityClass;

/**
 * Helper class providing some convenience method for interacting with {@link SecurityManager}
 * related stuff. In essence, it uses {@link AccessController#doPrivileged(PrivilegedAction)} for
 * its
 * method in case a {@link SecurityManager} is set.
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
@SuppressWarnings("java:S1905") // owolff: The casts are necessary for the return type
public class SecuritySupport {

    private static final String SECURITY_MANAGER_CONFIGURED = "A SecurityManager is configured, using PrivilegedAction";
    private static final CuiLogger LOGGER = new CuiLogger(SecuritySupport.class);

    /**
     * @return the context-classloader if obtainable, {@link Optional#empty()} otherwise
     */
    public static Optional<ClassLoader> getContextClassLoader() {
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, accessing context-class-loader");
            return Optional.ofNullable(Thread.currentThread().getContextClassLoader());
        } else {
            LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
            return AccessController.doPrivileged((PrivilegedAction<Optional<ClassLoader>>) () -> {
                try {
                    return Optional.ofNullable(Thread.currentThread().getContextClassLoader());
                } catch (SecurityException e) {
                    LOGGER.warn("Unable to access context-class-loader due to SecurityException", e);
                    return Optional.empty();
                }
            });
        }
    }

    /**
     * @param object to be set accessible
     * @param accessible value
     */
    public static void setAccessible(AccessibleObject object, boolean accessible) {
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, setting accessible directly");
            object.setAccessible(accessible);
        } else {
            LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {

                try {
                    object.setAccessible(accessible);
                } catch (SecurityException e) {
                    LOGGER.warn("Unable to call 'setAccessible' due to SecurityException", e);
                }
                return null;
            });
        }
    }

    /**
     * @param propertyName If is null or empty the method will return {@link Optional#empty()}
     * @return an {@link Optional} on the requested property
     */
    public static Optional<String> accessSystemProperty(String propertyName) {
        if (isEmpty(propertyName)) {
            return Optional.empty();
        }
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, accessing System-Property directly");
            return Optional.ofNullable(System.getProperty(propertyName));
        } else {
            LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
            return AccessController.doPrivileged((PrivilegedAction<Optional<String>>) () -> {

                try {
                    return Optional.ofNullable(System.getProperty(propertyName));
                } catch (SecurityException e) {
                    LOGGER.warn("Unable to call 'System.getProperty' due to SecurityException", e);
                }
                return Optional.empty();
            });
        }
    }

    /**
     * @return the {@link Properties} derived by {@link System#getProperties()}. If this can not be
     *         achieved it returns an empty {@link Properties} object.
     */
    public static Properties accessSystemProperties() {
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, accessing System.getProperties directly");
            return System.getProperties();
        } else {
            LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
            return AccessController.doPrivileged((PrivilegedAction<Properties>) () -> {
                try {
                    return System.getProperties();
                } catch (SecurityException e) {
                    LOGGER.warn("Unable to call 'System.getProperties' due to SecurityException", e);
                }
                return new Properties();
            });
        }
    }

    /**
     * @return the map derived by {@link System#getenv()}. If this can not be achieved it returns an
     *         empty map.
     */
    public static Map<String, String> accessSystemEnv() {
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, accessing System.getenv directly");
            return System.getenv();
        } else {
            LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
            return AccessController.doPrivileged((PrivilegedAction<Map<String, String>>) () -> {
                try {
                    return System.getenv();
                } catch (SecurityException e) {
                    LOGGER.warn("Unable to call 'System.getenv' due to SecurityException", e);
                }
                return Collections.emptyMap();
            });
        }
    }

    /**
     * @param <T>
     * @param clazz The type of the object
     * @param paramTypes to be used for identifying the constructor
     * @return the found constructor.
     * @throws NoSuchMethodException to be thrown, if there is no corresponding constructor
     * @throws IllegalStateException for cases where the {@link PrivilegedAction} fails but is not a
     *             {@link NoSuchMethodException}
     */
    @SuppressWarnings("squid:S1452") // owolff: using wildcards here is the only sensible thing to
                                     // do
    public static <T> Constructor<? extends T> getDeclaredConstructor(Class<T> clazz, Class<?>... paramTypes)
        throws NoSuchMethodException {
        if (null == System.getSecurityManager()) {
            LOGGER.trace("No SecurityManager configured, accessing declared constructors directly");
            return clazz.getDeclaredConstructor(paramTypes);
        } else {
            try {
                LOGGER.trace(SECURITY_MANAGER_CONFIGURED);
                return AccessController.doPrivileged((PrivilegedExceptionAction<Constructor<? extends T>>) () -> {
                    Constructor<? extends T> constructor = null;
                    try {
                        constructor = clazz.getDeclaredConstructor(paramTypes);

                    } catch (SecurityException e) {
                        LOGGER.warn(e,
                                "Unable to call 'getDeclaredConstructor' due to SecurityException, class='{}', paramTypes='{}'",
                                clazz.toString(),
                                Arrays.toString(paramTypes));
                    }
                    return constructor;
                });
            } catch (PrivilegedActionException e) {
                Exception e2 = e.getException();
                if (e2 instanceof NoSuchMethodException) {
                    throw (NoSuchMethodException) e2;
                } else {
                    throw new IllegalStateException(e2);
                }
            }
        }
    }
}
