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
package de.cuioss.tools.lang;

import static de.cuioss.tools.string.MoreStrings.isEmpty;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import lombok.experimental.UtilityClass;

/**
 * Helper class providing some convenience method for interacting with
 * {@link SecurityManager} related stuff. In essence, it uses
 * {@link AccessController#doPrivileged(PrivilegedAction)} for its method in
 * case a {@link SecurityManager} is set.
 *
 * @deprecated SecurityManager hard deprecated by Java 18+
 * @author Oliver Wolff
 *
 */
@UtilityClass
@SuppressWarnings("java:S1905") // owolff: The casts are necessary for the return type
@Deprecated(forRemoval = true, since = "1.2")
public class SecuritySupport {

    /**
     * @return the context-classloader if obtainable, {@link Optional#empty()}
     *         otherwise
     */
    public static Optional<ClassLoader> getContextClassLoader() {
        return Optional.ofNullable(Thread.currentThread().getContextClassLoader());
    }

    /**
     * @param object     to be set accessible
     * @param accessible value
     */
    public static void setAccessible(AccessibleObject object, boolean accessible) {
        object.setAccessible(accessible);
    }

    /**
     * @param propertyName If is null or empty the method will return
     *                     {@link Optional#empty()}
     * @return an {@link Optional} on the requested property
     */
    public static Optional<String> accessSystemProperty(String propertyName) {
        if (isEmpty(propertyName)) {
            return Optional.empty();
        }
        return Optional.ofNullable(System.getProperty(propertyName));
    }

    /**
     * @return the {@link Properties} derived by {@link System#getProperties()}. If
     *         this can not be achieved it returns an empty {@link Properties}
     *         object.
     */
    public static Properties accessSystemProperties() {
        return System.getProperties();
    }

    /**
     * @return the map derived by {@link System#getenv()}. If this can not be
     *         achieved it returns an empty map.
     */
    public static Map<String, String> accessSystemEnv() {
        return System.getenv();
    }

    /**
     * @param <T>
     * @param clazz      The type of the object
     * @param paramTypes to be used for identifying the constructor
     * @return the found constructor.
     * @throws NoSuchMethodException to be thrown, if there is no corresponding
     *                               constructor
     * @throws IllegalStateException for cases where the {@link PrivilegedAction}
     *                               fails but is not a
     *                               {@link NoSuchMethodException}
     */
    @SuppressWarnings("squid:S1452") // owolff: using wildcards here is the only sensible thing to
                                     // do
    public static <T> Constructor<? extends T> getDeclaredConstructor(Class<T> clazz, Class<?>... paramTypes)
            throws NoSuchMethodException {
        return clazz.getDeclaredConstructor(paramTypes);
    }
}
