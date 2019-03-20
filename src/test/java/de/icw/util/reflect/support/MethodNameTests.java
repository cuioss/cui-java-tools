package de.icw.util.reflect.support;

@SuppressWarnings({ "javadoc", "unused" })
public class MethodNameTests {

    private String name;

    private boolean flag;

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

    public MethodNameTests builderWriteMethod(String param) {
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
