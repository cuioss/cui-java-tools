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
package de.cuioss.tools.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Simple helper providing an assert for {@link Object#equals(Object)}
 * {@link Object#hashCode()} {@link Object#toString()} and {@link Serializable}
 * contract
 *
 * @author Oliver Wolff
 *
 */
@SuppressWarnings("java:S5785") // owolff THe fine-grained equals test is by design and not a bug
public class ObjectMethodsAsserts {

    private static final Integer DEFAULT_INT_VALUE = 0;

    /**
     * Convenience method for executing all asserts:
     * {@link #assertEqualsAndHashCode(Object)}, {@link #assertToString(Object)},
     * {@link #assertSerializableContract(Object)}
     *
     * @param underTest to be checked must not be {@code null}
     */
    public static void assertNiceObject(Object underTest) {
        assertEqualsAndHashCode(underTest);
        assertToString(underTest);
        assertSerializableContract(underTest);
    }

    /**
     * Minimal assert on {@link Object#equals(Object)} and {@link Object#hashCode()}
     * checking the basic contract
     *
     * @param underTest to be checked must not be {@code null}
     */
    public static void assertEqualsAndHashCode(Object underTest) {
        assertNotNull(underTest);

        assertBasicContractOnEquals(underTest);
        assertBasicContractOnHashCode(underTest);
    }

    /**
     * Minimal assert on {@link Object#toString()}
     *
     * @param underTest to be checked must not be {@code null}
     */
    public static void assertToString(Object underTest) {
        assertNotNull(underTest);

        ReflectionUtil.assertToStringMethodIsOverriden(underTest.getClass());
        assertNotNull(underTest.toString(), "toString must not return 'null'");
    }

    /**
     * Minimal assert on {@link Object#toString()}
     *
     * @param underTest to be checked must not be {@code null}
     */
    public static void assertSerializableContract(Object underTest) {
        assertNotNull(underTest);

        assertTrue(underTest instanceof Serializable,
                underTest.getClass().getName() + " does not implement java.io.Serializable");

        final var serializationFailedMessage = underTest.getClass().getName() + " is not equal after serialization";
        var serializeAndDeserialize = serializeAndDeserialize(underTest);

        assertEquals(underTest, serializeAndDeserialize, serializationFailedMessage);
    }

    private static void assertBasicContractOnEquals(final Object underTest) {

        ReflectionUtil.assertEqualsMethodIsOverriden(underTest.getClass());

        // basic checks to equals implementation
        final var msgNotEqualsNull = "Expected result for equals(null) will be 'false'. Class was : "
                + underTest.getClass();

        assertNotEquals(null, underTest, msgNotEqualsNull);

        final var msgNotEqualsObject = "Expected result for equals(new Object()) will be 'false'. Class was : "
                + underTest.getClass();

        assertNotEquals(underTest, new Object(), msgNotEqualsObject);

        final var msgEqualsToSelf = "Expected result for equals(underTest) will be 'true'. Class was : "
                + underTest.getClass();

        assertEquals(underTest, underTest, msgEqualsToSelf);

    }

    /**
     * Verify object has implemented {@link Object#hashCode()} method.
     *
     * @param underTest object under test
     */
    private static void assertBasicContractOnHashCode(final Object underTest) {
        ReflectionUtil.assertHashCodeMethodIsOverriden(underTest.getClass());

        // basic checks to hashCode implementation
        assertNotEquals(DEFAULT_INT_VALUE, underTest.hashCode(),
                "Expected result of hashCode method is not '0'. Class was : " + underTest.getClass());
    }

    /**
     * Shorthand combining the calls {@link #serializeObject(Object)}
     * {@link #deserializeObject(byte[])}
     *
     * @param object to be serialized, must not be null
     * @return the deserialized object.
     */
    public static final Object serializeAndDeserialize(final Object object) {
        assertNotNull(object, "Given Object must not be null");
        final var serialized = serializeObject(object);
        return deserializeObject(serialized);
    }

    /**
     * Serializes an object into a newly created byteArray
     *
     * @param object to be serialized
     * @return the resulting byte array
     */
    public static final byte[] serializeObject(final Object object) {
        assertNotNull(object, "Given Object must not be null");
        final var baos = new ByteArrayOutputStream(1024);
        try (var oas = new ObjectOutputStream(baos)) {
            oas.writeObject(object);
            oas.flush();
        } catch (final Exception e) {
            throw new AssertionError(
                    "Unable to serialize, due to " + ExceptionHelper.extractCauseMessageFromThrowable(e));
        }
        return baos.toByteArray();
    }

    /**
     * Deserializes an object from a given byte-array
     *
     * @param bytes to be deserialized
     * @return the deserialized object
     */
    public static final Object deserializeObject(final byte[] bytes) {
        assertNotNull(bytes, "Given byte-array must not be null");
        final var bais = new ByteArrayInputStream(bytes);
        try (var ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        } catch (final Exception e) {
            throw new AssertionError(
                    "Unable to deserialize, due to " + ExceptionHelper.extractCauseMessageFromThrowable(e));
        }
    }
}
