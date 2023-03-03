package de.cuioss.tools.property.support;

import lombok.Getter;
import lombok.Setter;

@SuppressWarnings("javadoc")
public class BeanWithPrimitives {

    @Getter
    private Integer property;

    @Getter
    @Setter
    private int propertyPrimitive;

    public void setProperty(Number property) {
        property = Integer.valueOf(property.intValue());
    }

    public void setProperty(Integer property) {
        this.property = property;
    }

    public void setProperty(int property) {
        this.property = property;
    }

    public void setProperty(String property) {
        this.property = Integer.valueOf(property);
    }

    public BeanWithPrimitives property(Integer property) {
        this.property = property;
        return this;
    }
}
