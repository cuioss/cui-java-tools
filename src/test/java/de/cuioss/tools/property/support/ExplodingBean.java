/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.property.support;

import java.lang.reflect.InvocationTargetException;

public class ExplodingBean {

    private Throwable throwable = new IllegalArgumentException();

    public void setProperty(String property) throws Throwable {
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
