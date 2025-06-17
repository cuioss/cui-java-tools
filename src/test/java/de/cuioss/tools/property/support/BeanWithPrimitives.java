/**
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

import lombok.Getter;
import lombok.Setter;

public class BeanWithPrimitives {

    @Getter
    private Integer property;

    @Getter
    @Setter
    private int propertyPrimitive;

    public void setProperty(Number property) {
        this.property = property.intValue();
    }

    public void setProperty(Integer property) {
        this.property = property;
    }

    public void setProperty(int property) {
        this.property = property;
    }

    public void setProperty(String property) {
        this.property = Integer.valueOf(property);
    }

    public BeanWithPrimitives property(Integer property) {
        this.property = property;
        return this;
    }
}
