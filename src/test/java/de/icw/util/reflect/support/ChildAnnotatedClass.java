package de.icw.util.reflect.support;

import java.util.function.Function;

import javax.annotation.Resource;

@SuppressWarnings("javadoc")
@Resource
@Deprecated
public class ChildAnnotatedClass extends BaseAnnotatedClass implements Function<String, String> {

    @Override
    public String apply(String t) {
        return t;
    }
}
