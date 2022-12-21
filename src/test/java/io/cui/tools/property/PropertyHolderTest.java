package io.cui.tools.property;

import static io.cui.tools.property.PropertyHolder.from;
import static io.cui.tools.property.PropertyReadWrite.READ_ONLY;
import static io.cui.tools.property.PropertyReadWrite.READ_WRITE;
import static io.cui.tools.property.PropertyReadWrite.WRITE_ONLY;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_NOT_ACCESSIBLE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_ONLY;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE_WITH_BUILDER;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_WRITE_ONLY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Serializable;

import org.junit.jupiter.api.Test;

import io.cui.tools.property.support.BeanWithBuilderStyleAccessor;
import io.cui.tools.property.support.BeanWithMethodOverload;
import io.cui.tools.property.support.BeanWithReadWriteProperties;
import io.cui.tools.property.support.ExplodingBean;
import io.cui.tools.property.support.GenericTypeWithLowerBoundType;
import io.cui.tools.property.support.StringTypedGenericType;
import io.cui.tools.support.Generators;

class PropertyHolderTest {

    static final String PROPERTY_NAME = "property";

    @Test
    void shouldResolvePropertyReadWrite() {
        assertEquals(READ_WRITE, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get().getReadWrite());
        assertEquals(READ_WRITE,
                from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER).get().getReadWrite());
        assertEquals(READ_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY).get().getReadWrite());
        assertEquals(WRITE_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY).get().getReadWrite());
        assertFalse(from(BeanWithReadWriteProperties.class, ATTRIBUTE_NOT_ACCESSIBLE).isPresent());
    }

    @Test
    void shouldHandlePropertyMemberInfo() {
        assertEquals(PropertyMemberInfo.DEFAULT, from(BeanWithReadWriteProperties.class,
                BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE).get().getMemberInfo());
        assertEquals(PropertyMemberInfo.TRANSIENT, from(BeanWithReadWriteProperties.class,
                BeanWithReadWriteProperties.ATTRIBUTE_TRANSIENT_VALUE).get().getMemberInfo());
    }

    @Test
    void shouldHandleHappyCase() {
        PropertyHolder underTest = from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get();
        assertEquals(READ_WRITE, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(ATTRIBUTE_READ_WRITE, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNotNull(underTest.getReadMethod());
        assertNotNull(underTest.getWriteMethod());
        BeanWithReadWriteProperties bean = new BeanWithReadWriteProperties();
        assertNull(underTest.readFrom(bean));
        Integer number = Generators.randomInt(0, 1024);
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithReadWriteProperties.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
        assertEquals(number, underTest.readFrom(bean));
    }

    @Test
    void shouldHandleBuilderLikeAccess() {
        PropertyHolder underTest =
                from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER)
                .get();
        assertEquals(READ_WRITE, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(ATTRIBUTE_READ_WRITE_WITH_BUILDER, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNotNull(underTest.getReadMethod());
        assertNotNull(underTest.getWriteMethod());
        BeanWithReadWriteProperties bean = new BeanWithReadWriteProperties();
        assertNull(underTest.readFrom(bean));
        Integer number = Generators.randomInt(0, 1024);
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithReadWriteProperties.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
        assertEquals(number, underTest.readFrom(bean));

    }

    @Test
    void shouldFailOnOnRuntimeExceptionProperty() {
        ExplodingBean underTest = new ExplodingBean();
        PropertyHolder holder = from(ExplodingBean.class, PROPERTY_NAME).get();

        underTest.illegalArgumentException();
        assertThrows(IllegalStateException.class, () -> {
            holder.readFrom(underTest);
        });
        assertThrows(IllegalStateException.class, () -> {
            holder.writeTo(underTest, "");
        });
    }

    @Test
    void shouldSupportBuilderLikeAccess() {
        BeanWithBuilderStyleAccessor bean = new BeanWithBuilderStyleAccessor();
        assertTrue(from(BeanWithBuilderStyleAccessor.class, PROPERTY_NAME).isPresent());
        PropertyHolder underTest = from(BeanWithBuilderStyleAccessor.class, PROPERTY_NAME).get();

        assertEquals(WRITE_ONLY, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(PROPERTY_NAME, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNull(underTest.getWriteMethod());
        Integer number = Generators.randomInt(0, 1024);
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithBuilderStyleAccessor.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
    }

    @Test
    void shouldHandleOverloadedMethods() {
        PropertyHolder holder = from(BeanWithMethodOverload.class, PROPERTY_NAME).get();
        assertEquals(Integer.class, holder.getType());
    }

    @Test
    void shouldHandleLowerBoundGenerics() {
        PropertyHolder holder = from(GenericTypeWithLowerBoundType.class, "key").get();
        assertEquals(Serializable.class, holder.getType());
    }

    @Test
    void shouldHandleBoundGenerics() {
        PropertyHolder holder = from(StringTypedGenericType.class, "key").get();
        assertEquals(String.class, holder.getType());
    }
}
