package io.cui.util.reflect.support;

import lombok.Getter;
import lombok.Setter;

@SuppressWarnings({ "javadoc", "unused" })
public class MethodNameClass {

    private String name;

    private boolean flag;

    @Getter
    @Setter
    private Boolean flagObject;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isFlag() {
        return flag;
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }

    protected String getProtected() {
        return "protected";
    }

    private String getPrivate() {
        return "private";
    }

    String getModule() {
        return "module";
    }

    public String wrongName() {
        return "wrongName";
    }

    public String getWrongParameter(String param) {
        return "wrongParameter";
    }

    public MethodNameClass builderWriteMethod(String param) {
        return this;
    }

    public void setWrongParameterCount(String param, String parameter) {
    }

    public static String getStatic() {
        return "static";
    }

    public static void setStatic(String staticString) {

    }
}
