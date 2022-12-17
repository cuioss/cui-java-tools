package io.cui.util.property.support;

import java.lang.reflect.InvocationTargetException;

@SuppressWarnings("javadoc")
public class ExplodingBean {

    private Throwable throwable = new IllegalArgumentException();

    public void setProperty(@SuppressWarnings("unused") String property) throws Throwable {
        throw throwable;
    }

    public String getProperty() throws Throwable {
        throw throwable;
    }

    public void illegalArgumentException() {
        throwable = new IllegalArgumentException();
    }

    public void illegalAccessException() {
        throwable = new IllegalAccessException();
    }

    public void invocationTargetException() {
        throwable = new InvocationTargetException(new IllegalAccessError());
    }
}
