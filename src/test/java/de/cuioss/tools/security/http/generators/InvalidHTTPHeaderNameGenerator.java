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
 * Generator for invalid HTTP header names containing control characters.
 * Provides header names with various injection and control character patterns.
 */
public class InvalidHTTPHeaderNameGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> invalidHeaderNames = Generators.fixedValues(
            "Header\rName",         // CR in header name
            "Header\nName",         // LF in header name
            "Header\r\nName",       // CRLF in header name
            "Header\u0000Name",     // Null byte in header name
            "Header\tName",         // Tab in header name
            "Header\bName",         // Backspace in header name
            "Header\fName",         // Form feed in header name
            "Header\u000BName",     // Vertical tab in header name
            "Header Name",          // Space in header name
            "Header:Name",          // Colon in header name
            "Header;Name",          // Semicolon in header name
            "Header,Name",          // Comma in header name
            "Header\"Name",         // Quote in header name
            "Header'Name",          // Single quote in header name
            "Header\\Name",         // Backslash in header name
            "Header[Name]",         // Brackets in header name
            "Header{Name}",         // Braces in header name
            "Header(Name)",         // Parentheses in header name
            "Header<Name>",         // Angle brackets in header name
            "Header/Name"           // Slash in header name
    );

    @Override
    public String next() {
        return invalidHeaderNames.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}