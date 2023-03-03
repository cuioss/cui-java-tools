package de.cuioss.tools.reflect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import de.cuioss.tools.reflect.support.FieldNameClass;
import de.cuioss.tools.support.Generators;

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
        assertFalse(wrapper.getField().isAccessible());
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
        assertFalse(wrapper.getField().isAccessible());
    }

    @Test
    @Disabled("Test need to be reviewed")
    void writeShouldHandleInvalidAccess() {
        var nameClass = new FieldNameClass();
        var field = getMyFieldField();
        field.setAccessible(true);
        var wrapper = new FieldWrapper(field);
        field.setAccessible(false);

        var test = Generators.randomString();
        // TODO : review test access is allowed
        assertThrows(IllegalStateException.class, () -> wrapper.writeValue(nameClass, test));

        field.setAccessible(false);
    }

    @Test
    void readValue() {
        final var nameClass = new FieldNameClass();
        final var test = Generators.randomString();
        nameClass.setMyField(test);
        var field = getMyFieldField();
        var wrapper = new FieldWrapper(field);
        assertFalse(field.isAccessible());
        var fieldValue = wrapper.readValue(nameClass);
        assertFalse(field.isAccessible());
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
