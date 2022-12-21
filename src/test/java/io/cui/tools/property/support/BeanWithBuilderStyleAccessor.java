package io.cui.tools.property.support;

@SuppressWarnings("javadoc")
public class BeanWithBuilderStyleAccessor {

    @SuppressWarnings("unused")
    private Integer property;

    public BeanWithBuilderStyleAccessor property(Integer value) {
        property = value;
        return this;
    }
}
