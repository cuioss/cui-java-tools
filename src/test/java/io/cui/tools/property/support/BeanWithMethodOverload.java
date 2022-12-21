package io.cui.tools.property.support;

import lombok.Getter;

@SuppressWarnings("javadoc")
public class BeanWithMethodOverload {

    @Getter
    private Integer property;

    public void setProperty(Number property) {
        this.property = Integer.valueOf(property.intValue());
    }

    public void setProperty(Integer property) {
        this.property = property;
    }

    public void setProperty(String property) {
        this.property = Integer.valueOf(property);
    }

    public BeanWithMethodOverload property(Integer property) {
        this.property = property;
        return this;
    }
}
