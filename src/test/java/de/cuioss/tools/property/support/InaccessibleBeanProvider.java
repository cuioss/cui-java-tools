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

/**
 * Provides a bean whose accessors are public but whose class is not accessible
 * from outside this compilation unit. Invoking the accessors reflectively from
 * another package fails with {@link IllegalAccessException}.
 */
public final class InaccessibleBeanProvider {

    private InaccessibleBeanProvider() {
    }

    /**
     * @return a bean with public accessors on a class that is not reflectively
     * accessible from other packages
     */
    public static Object createInaccessibleBean() {
        return new InaccessibleBean();
    }

    @SuppressWarnings("unused")
    private static class InaccessibleBean {

        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
