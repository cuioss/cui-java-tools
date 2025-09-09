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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid URL paths.
 * Provides common valid URL path examples for testing.
 */
public class ValidURLPathGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validPaths = Generators.fixedValues(
            "/api/users",
            "/api/v1/users/123",
            "/api/users/search",
            "/health",
            "/metrics",
            "/api/users/123/profile",
            "/api/orders/456/items",
            "/api/v2/products",
            "/api/auth/login",
            "/api/auth/logout",
            "/api/config/settings",
            "/api/reports/daily",
            "/status",
            "/info",
            "/api/v1/documents/123",
            "/api/customers/456/orders",
            "/api/notifications/unread",
            "/api/admin/dashboard",
            "/api/stats/summary",
            "/api/backup/status"
    );

    @Override
    public String next() {
        return validPaths.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}