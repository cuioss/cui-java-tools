package io.cui.tools.reflect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Optional;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.cui.tools.reflect.support.FieldNameClass;
import io.cui.tools.support.Generators;

class FieldWrapperTest {

    @Test
    void factoryShouldDetermineWrapper() {
        assertTrue(FieldWrapper.from(FieldNameClass.class, "myField").isPresent());
        assertFalse(FieldWrapper.from(FieldNameClass.class, "notThere").isPresent());
    }

    @Test
    void shouldReadWrapperFieldHappyCase() {
        FieldNameClass nameClass = new FieldNameClass();
        FieldWrapper wrapper = getMyFieldFieldWrapper();
        assertFalse(wrapper.readValue(nameClass).isPresent());
        String test = Generators.randomString();
        nameClass.setMyField(test);
        Optional<Object> read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());
    }

    @Test
    void readShouldGracefullyHandleInvalidParameter() {
        FieldNameClass nameClass = new FieldNameClass();
        FieldWrapper wrapper = getMyFieldFieldWrapper();
        assertFalse(wrapper.readValue(nameClass).isPresent());
        assertFalse(wrapper.readValue(null).isPresent());
        assertFalse(wrapper.readValue(Integer.valueOf(2)).isPresent());
        // afterException accessible Flag should be reset correctly
        assertFalse(wrapper.getField().isAccessible());
    }

    @Test
    void shouldReadWrapperWithAccessibleFlagSet() {
        FieldNameClass nameClass = new FieldNameClass();
        Field field = getMyFieldField();
        field.setAccessible(true);
        FieldWrapper wrapper = new FieldWrapper(field);
        assertFalse(wrapper.readValue(nameClass).isPresent());
        String test = Generators.randomString();
        nameClass.setMyField(test);
        Optional<Object> read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());

        field.setAccessible(false);
    }

    @Test
    void shouldWriteWrapperFieldHappyCase() {
        FieldNameClass nameClass = new FieldNameClass();
        FieldWrapper wrapper = getMyFieldFieldWrapper();

        assertFalse(wrapper.readValue(nameClass).isPresent());

        String test = Generators.randomString();
        wrapper.writeValue(nameClass, test);

        Optional<Object> read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());
    }

    @Test
    void shouldWriteWrapperWithAccessibleFlagSet() {
        FieldNameClass nameClass = new FieldNameClass();
        Field field = getMyFieldField();
        field.setAccessible(true);
        FieldWrapper wrapper = new FieldWrapper(field);

        assertFalse(wrapper.readValue(nameClass).isPresent());

        String test = Generators.randomString();
        wrapper.writeValue(nameClass, test);

        Optional<Object> read = wrapper.readValue(nameClass);
        assertTrue(read.isPresent());
        assertEquals(test, wrapper.readValue(nameClass).get());

        field.setAccessible(false);
    }

    @Test
    void writeShouldHandleInvalidParameter() {
        FieldNameClass nameClass = new FieldNameClass();
        FieldWrapper wrapper = getMyFieldFieldWrapper();

        String test = Generators.randomString();

        assertThrows(NullPointerException.class, () -> wrapper.writeValue(null, null));

        assertThrows(NullPointerException.class, () -> wrapper.writeValue(null, test));

        Integer value = 2;
        assertThrows(IllegalArgumentException.class, () -> wrapper.writeValue(nameClass, value));

        // afterException accessible Flag should be resetted correctly
        assertFalse(wrapper.getField().isAccessible());
    }

    @Test
    @Disabled("Test need to be reviewed")
    void writeShouldHandleInvalidAccess() {
        FieldNameClass nameClass = new FieldNameClass();
        Field field = getMyFieldField();
        field.setAccessible(true);
        FieldWrapper wrapper = new FieldWrapper(field);
        field.setAccessible(false);

        String test = Generators.randomString();
        // TODO : review test access is allowed
        assertThrows(IllegalStateException.class, () -> wrapper.writeValue(nameClass, test));

        field.setAccessible(false);
    }

    @Test
    void readValue() {
        final FieldNameClass nameClass = new FieldNameClass();
        final String test = Generators.randomString();
        nameClass.setMyField(test);
        Field field = getMyFieldField();
        FieldWrapper wrapper = new FieldWrapper(field);
        assertFalse(field.isAccessible());
        Optional<Object> fieldValue = wrapper.readValue(nameClass);
        assertFalse(field.isAccessible());
        assertNotNull(fieldValue);
        assertTrue(fieldValue.isPresent());
        assertEquals(test, fieldValue.get());
    }

    private FieldWrapper getMyFieldFieldWrapper() {
        Optional<FieldWrapper> optionalFieldWrapper = FieldWrapper.from(FieldNameClass.class, "myField");
        assertTrue(optionalFieldWrapper.isPresent(), "myField should be accessible");
        return optionalFieldWrapper.get();
    }

    private Field getMyFieldField() {
        Optional<Field> optionalField = MoreReflection.accessField(FieldNameClass.class, "myField");
        assertTrue(optionalField.isPresent(), "myField should be accessible");
        return optionalField.get();
    }
}
