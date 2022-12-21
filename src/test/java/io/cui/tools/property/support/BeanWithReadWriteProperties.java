package io.cui.tools.property.support;

import lombok.Getter;
import lombok.Setter;

@SuppressWarnings("javadoc")
public class BeanWithReadWriteProperties {

    public static final String ATTRIBUTE_READ_WRITE = "readWriteProperty";
    public static final String ATTRIBUTE_READ_WRITE_WITH_BUILDER = "readWriteWithBuilder";
    public static final String ATTRIBUTE_READ_ONLY = "readOnlyProperty";
    public static final String ATTRIBUTE_WRITE_ONLY = "writeOnlyProperty";
    public static final String ATTRIBUTE_NOT_ACCESSIBLE = "notAccesibleProperty";
    public static final String ATTRIBUTE_TRANSIENT_VALUE = "transientProperty";
    public static final String ATTRIBUTE_DEFAULT_VALUE = "defaultValueProperty";
    public static final String ATTRIBUTE_DEFAULT_VALUE_VALUE = "defaultValue";

    @Getter
    @Setter
    private Integer readWriteProperty;

    @Getter
    @Setter
    private Integer readWriteWithBuilder;

    @Getter
    private String readOnlyProperty;

    @Setter
    private Boolean writeOnlyProperty;

    @SuppressWarnings("unused")
    private String notAccessibleProperty;

    @Getter
    @Setter
    private transient String transientProperty;

    @Getter
    @Setter
    private String defaultValueProperty = ATTRIBUTE_DEFAULT_VALUE_VALUE;

    public BeanWithReadWriteProperties readWriteWithBuilder(Integer element) {
        readWriteWithBuilder = element;
        return this;
    }
}
