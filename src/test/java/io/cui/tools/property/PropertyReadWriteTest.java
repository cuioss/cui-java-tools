package io.cui.tools.property;

import static io.cui.tools.collect.CollectionLiterals.mutableList;
import static io.cui.tools.property.PropertyReadWrite.NONE;
import static io.cui.tools.property.PropertyReadWrite.READ_ONLY;
import static io.cui.tools.property.PropertyReadWrite.READ_WRITE;
import static io.cui.tools.property.PropertyReadWrite.WRITE_ONLY;
import static io.cui.tools.property.PropertyReadWrite.fromPropertyDescriptor;
import static io.cui.tools.property.PropertyReadWrite.resolveForBean;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_NOT_ACCESSIBLE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_ONLY;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE_WITH_BUILDER;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_WRITE_ONLY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.cui.tools.property.support.BeanWithReadWriteProperties;

class PropertyReadWriteTest {

    @Test
    void shouldResolveReflectionBases() {
        assertEquals(READ_WRITE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE));
        assertEquals(READ_WRITE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER));
        assertEquals(READ_ONLY, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY));
        assertEquals(WRITE_ONLY, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY));
        assertEquals(NONE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_NOT_ACCESSIBLE));
    }

    @Test
    void shouldResolvePropertyDescriptor() throws IntrospectionException {
        assertEquals(READ_WRITE,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE));
        assertEquals(READ_WRITE,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER));
        assertEquals(READ_ONLY, resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY));
        assertEquals(WRITE_ONLY,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY));
    }

    private PropertyReadWrite resolveWithPropertyDescriptor(Class<?> type, String attributeName)
        throws IntrospectionException {
        BeanInfo info = Introspector.getBeanInfo(type);
        Optional<PropertyDescriptor> descriptor = mutableList(info.getPropertyDescriptors()).stream()
                .filter(desc -> attributeName.equalsIgnoreCase(desc.getName())).findFirst();
        assertTrue(descriptor.isPresent());

        return fromPropertyDescriptor(descriptor.get(), type, attributeName);
    }

    @Test
    void shouldPovideCorrectData() {
        assertTrue(READ_ONLY.isReadable());
        assertFalse(READ_ONLY.isWriteable());

        assertFalse(WRITE_ONLY.isReadable());
        assertTrue(WRITE_ONLY.isWriteable());

        assertTrue(READ_WRITE.isReadable());
        assertTrue(WRITE_ONLY.isWriteable());

        assertFalse(NONE.isReadable());
        assertFalse(NONE.isWriteable());
    }

}
