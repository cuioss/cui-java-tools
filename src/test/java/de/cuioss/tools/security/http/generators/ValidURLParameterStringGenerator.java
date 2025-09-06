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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid URL parameter strings in format "name=value".
 * Provides common valid parameter examples for testing.
 */
public class ValidURLParameterStringGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validParameters = Generators.fixedValues(
            "user_id=123",
            "search=java%20programming",
            "category=electronics",
            "page=1",
            "limit=50",
            "sort=name",
            "filter=active",
            "lang=en",
            "status=enabled",
            "type=product",
            "format=json",
            "version=v2",
            "order=asc",
            "size=10",
            "timestamp=1640995200",
            "id=abc123",
            "name=john%2Bdoe",
            "email=test%40example.com",
            "phone=555%2D1234",
            "color=red"
    );

    @Override
    public String next() {
        return validParameters.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}