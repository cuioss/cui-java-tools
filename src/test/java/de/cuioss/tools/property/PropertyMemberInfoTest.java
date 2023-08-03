package de.cuioss.tools.property;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.property.support.BeanWithReadWriteProperties;

class PropertyMemberInfoTest {

    @Test
    void test() {
        assertEquals(PropertyMemberInfo.DEFAULT, PropertyMemberInfo.resolveForBean(BeanWithReadWriteProperties.class,
                BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE));
        assertEquals(PropertyMemberInfo.TRANSIENT, PropertyMemberInfo.resolveForBean(BeanWithReadWriteProperties.class,
                BeanWithReadWriteProperties.ATTRIBUTE_TRANSIENT_VALUE));
        assertEquals(PropertyMemberInfo.UNDEFINED,
                PropertyMemberInfo.resolveForBean(BeanWithReadWriteProperties.class, "notThere"));
    }

}
