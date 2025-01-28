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
package de.cuioss.tools.reflect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.cuioss.tools.reflect.support.FieldNameClass;
import de.cuioss.tools.support.Generators;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

class FieldWrapperTest {

    @Test
    void factoryShouldDetermineWrapper() {
        assertTrue(FieldWrapper.from(FieldNameClass.class, "myField").isPresent());
        assertFalse(FieldWrapper.from(FieldNameClass.class, "notThere").isPresent());
    }

    @Test
    void shouldReadWrapperFieldHappyCase() {
        var nameClass = new FieldNameClass();
        var wrapper = getMyFieldFieldWrapper();
        assertFalse(wrapper.readValue(nameClass).isPresent());
        var test = Generators.randomString();
        nameClass.setMyField(test);
        var read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());
    }

    @Test
    void readShouldGracefullyHandleInvalidParameter() {
        var nameClass = new FieldNameClass();
        var wrapper = getMyFieldFieldWrapper();
        assertFalse(wrapper.readValue(nameClass).isPresent());
        assertFalse(wrapper.readValue(null).isPresent());
        assertFalse(wrapper.readValue(Integer.valueOf(2)).isPresent());
        // afterException accessible Flag should be reset correctly
        assertFalse(wrapper.getField().canAccess(nameClass));
    }

    @Test
    void shouldReadWrapperWithAccessibleFlagSet() {
        var nameClass = new FieldNameClass();
        var field = getMyFieldField();
        field.setAccessible(true);
        var wrapper = new FieldWrapper(field);
        assertFalse(wrapper.readValue(nameClass).isPresent());
        var test = Generators.randomString();
        nameClass.setMyField(test);
        var read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());

        field.setAccessible(false);
    }

    @Test
    void shouldWriteWrapperFieldHappyCase() {
        var nameClass = new FieldNameClass();
        var wrapper = getMyFieldFieldWrapper();

        assertFalse(wrapper.readValue(nameClass).isPresent());

        var test = Generators.randomString();
        wrapper.writeValue(nameClass, test);

        var read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());
    }

    @Test
    void shouldWriteWrapperWithAccessibleFlagSet() {
        var nameClass = new FieldNameClass();
        var field = getMyFieldField();
        field.setAccessible(true);
        var wrapper = new FieldWrapper(field);

        assertFalse(wrapper.readValue(nameClass).isPresent());

        var test = Generators.randomString();
        wrapper.writeValue(nameClass, test);

        var read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());

        field.setAccessible(false);
    }

    @Test
    void writeShouldHandleInvalidParameter() {
        var nameClass = new FieldNameClass();
        var wrapper = getMyFieldFieldWrapper();

        var test = Generators.randomString();

        assertThrows(NullPointerException.class, () -> wrapper.writeValue(null, null));

        assertThrows(NullPointerException.class, () -> wrapper.writeValue(null, test));

        Integer value = 2;
        assertThrows(IllegalArgumentException.class, () -> wrapper.writeValue(nameClass, value));

        // afterException accessible Flag should be resetted correctly
        assertFalse(wrapper.getField().canAccess(nameClass));
    }

    @Test
    void readValue() {
        final var nameClass = new FieldNameClass();
        final var test = Generators.randomString();
        nameClass.setMyField(test);
        var field = getMyFieldField();
        var wrapper = new FieldWrapper(field);
        assertFalse(field.canAccess(nameClass));
        var fieldValue = wrapper.readValue(nameClass);
        assertFalse(field.canAccess(nameClass));
        assertNotNull(fieldValue);
        assertTrue(fieldValue.isPresent());
        assertEquals(test, fieldValue.get());
    }

    private FieldWrapper getMyFieldFieldWrapper() {
        var optionalFieldWrapper = FieldWrapper.from(FieldNameClass.class, "myField");
        assertTrue(optionalFieldWrapper.isPresent(), "myField should be accessible");
        return optionalFieldWrapper.get();
    }

    private Field getMyFieldField() {
        var optionalField = MoreReflection.accessField(FieldNameClass.class, "myField");
        assertTrue(optionalField.isPresent(), "myField should be accessible");
        return optionalField.get();
    }
}
