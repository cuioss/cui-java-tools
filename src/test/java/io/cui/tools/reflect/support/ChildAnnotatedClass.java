package io.cui.tools.reflect.support;

import java.util.function.Function;

import jakarta.annotation.Resource;

@Resource
@Deprecated
public class ChildAnnotatedClass extends BaseAnnotatedClass implements Function<String, String> {

    @Override
    public String apply(String t) {
        return t;
    }
}
