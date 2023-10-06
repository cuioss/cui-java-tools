/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.reflect.support;

import lombok.Getter;
import lombok.Setter;

@SuppressWarnings({ "unused" })
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
