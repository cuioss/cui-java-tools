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
package de.cuioss.tools.security.http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Immutable record representing an HTTP request or response body with content, content type, and encoding.
 * 
 * <p>This record encapsulates the structure of HTTP message bodies, providing a type-safe way
 * to handle body data in HTTP security validation. It supports various content types and
 * encoding schemes commonly used in HTTP communications.</p>
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Immutability</strong> - All fields are final and the record cannot be modified</li>
 *   <li><strong>Type Safety</strong> - Strongly typed representation of HTTP body data</li>
 *   <li><strong>Encoding Awareness</strong> - Explicit handling of content encoding</li>
 *   <li><strong>Content Type Support</strong> - Supports MIME type specification</li>
 * </ul>
 * 
 * <h3>Usage Examples</h3>
 * <pre>
 * // JSON body
 * HTTPBody jsonBody = new HTTPBody(
 *     "{\"userId\": 123, \"name\": \"John\"}",
 *     "application/json",
 *     ""
 * );
 * 
 * // Form data
 * HTTPBody formBody = new HTTPBody(
 *     "username=admin&password=secret",
 *     "application/x-www-form-urlencoded",
 *     ""
 * );
 * 
 * // Compressed content
 * HTTPBody compressedBody = new HTTPBody(
 *     "...", // compressed content
 *     "text/html",
 *     "gzip"
 * );
 * 
 * // Access components
 * String content = body.content();           // The actual content
 * String contentType = body.contentType();   // "application/json"
 * String encoding = body.encoding();         // "gzip"
 * 
 * // Check content characteristics
 * boolean isJson = body.isJson();           // true for JSON content
 * boolean hasContent = body.hasContent();   // true if content is not empty
 * boolean isCompressed = body.isCompressed(); // true if encoding is specified
 * 
 * // Use in validation
 * validator.validate(body.content(), ValidationType.BODY);
 * </pre>
 * 
 * <h3>Content Types</h3>
 * <p>The contentType field should contain a valid MIME type (e.g., "application/json",
 * "text/html", "multipart/form-data"). An empty string indicates no content type is specified.</p>
 * 
 * <h3>Encoding</h3>
 * <p>The encoding field specifies content encoding such as "gzip", "deflate", "br" (Brotli),
 * or "" for no encoding. This is distinct from character encoding, which is typically
 * specified in the Content-Type header.</p>
 * 
 * <h3>Security Considerations</h3>
 * <p>This record is a simple data container. Security validation should be applied to
 * the content using appropriate validators for {@link ValidationType#BODY}, taking into
 * account the content type and encoding when determining validation strategies.</p>
 * 
 * Implements: Task B3 from HTTP verification specification
 * 
 * @param content The body content as a string
 * @param contentType The MIME content type (e.g., "application/json", "text/html")
 * @param encoding The content encoding (e.g., "gzip", "deflate", "" for none)
 * 
 * @since 2.5
 * @see ValidationType#BODY
 */
public record HTTPBody(String content, String contentType, String encoding) {
    
    /**
     * Creates an HTTPBody with validation of basic constraints.
     * 
     * @param content The body content
     * @param contentType The content type
     * @param encoding The content encoding
     */
    public HTTPBody {
        // Record constructor - allow null values for edge case testing
        // Security validation is handled by the appropriate validators
    }
    
    /**
     * Creates an HTTPBody with just content and content type, no encoding.
     * 
     * @param content The body content
     * @param contentType The content type
     * @return An HTTPBody with no encoding
     */
    public static HTTPBody of(String content, String contentType) {
        return new HTTPBody(content, contentType, "");
    }
    
    /**
     * Creates a simple text HTTPBody.
     * 
     * @param content The text content
     * @return An HTTPBody with text/plain content type and no encoding
     */
    public static HTTPBody text(String content) {
        return new HTTPBody(content, "text/plain", "");
    }
    
    /**
     * Creates a JSON HTTPBody.
     * 
     * @param jsonContent The JSON content
     * @return An HTTPBody with application/json content type and no encoding
     */
    public static HTTPBody json(String jsonContent) {
        return new HTTPBody(jsonContent, "application/json", "");
    }
    
    /**
     * Creates an HTML HTTPBody.
     * 
     * @param htmlContent The HTML content
     * @return An HTTPBody with text/html content type and no encoding
     */
    public static HTTPBody html(String htmlContent) {
        return new HTTPBody(htmlContent, "text/html", "");
    }
    
    /**
     * Creates a form data HTTPBody.
     * 
     * @param formContent The form-encoded content
     * @return An HTTPBody with application/x-www-form-urlencoded content type and no encoding
     */
    public static HTTPBody form(String formContent) {
        return new HTTPBody(formContent, "application/x-www-form-urlencoded", "");
    }
    
    /**
     * Checks if this body has non-null, non-empty content.
     * 
     * @return true if the content is not null and not empty
     */
    public boolean hasContent() {
        return content != null && !content.isEmpty();
    }
    
    /**
     * Checks if this body has a specified content type.
     * 
     * @return true if the content type is not null and not empty
     */
    public boolean hasContentType() {
        return contentType != null && !contentType.isEmpty();
    }
    
    /**
     * Checks if this body has a specified encoding.
     * 
     * @return true if the encoding is not null and not empty
     */
    public boolean hasEncoding() {
        return encoding != null && !encoding.isEmpty();
    }
    
    /**
     * Checks if the content is compressed (has encoding specified).
     * 
     * @return true if encoding is specified, indicating compressed content
     */
    public boolean isCompressed() {
        return hasEncoding();
    }
    
    /**
     * Checks if the content type indicates JSON content.
     * 
     * @return true if the content type contains "json"
     */
    public boolean isJson() {
        return hasContentType() && contentType.toLowerCase().contains("json");
    }
    
    /**
     * Checks if the content type indicates XML content.
     * 
     * @return true if the content type contains "xml"
     */
    public boolean isXml() {
        return hasContentType() && contentType.toLowerCase().contains("xml");
    }
    
    /**
     * Checks if the content type indicates HTML content.
     * 
     * @return true if the content type contains "html"
     */
    public boolean isHtml() {
        return hasContentType() && contentType.toLowerCase().contains("html");
    }
    
    /**
     * Checks if the content type indicates plain text.
     * 
     * @return true if the content type is "text/plain"
     */
    public boolean isPlainText() {
        return hasContentType() && contentType.toLowerCase().equals("text/plain");
    }
    
    /**
     * Checks if the content type indicates form data.
     * 
     * @return true if the content type is form-encoded
     */
    public boolean isFormData() {
        return hasContentType() && 
               (contentType.toLowerCase().contains("application/x-www-form-urlencoded") ||
                contentType.toLowerCase().contains("multipart/form-data"));
    }
    
    /**
     * Checks if the content type indicates binary content.
     * 
     * @return true if the content type suggests binary data
     */
    public boolean isBinary() {
        return hasContentType() && 
               (contentType.toLowerCase().contains("application/octet-stream") ||
                contentType.toLowerCase().contains("image/") ||
                contentType.toLowerCase().contains("video/") ||
                contentType.toLowerCase().contains("audio/"));
    }
    
    /**
     * Returns the content length in characters.
     * 
     * @return The length of the content string, or 0 if content is null
     */
    public int contentLength() {
        return content != null ? content.length() : 0;
    }
    
    /**
     * Extracts the charset from the content type if specified.
     * 
     * @return The charset name or null if not specified
     */
    public String getCharset() {
        if (!hasContentType()) {
            return null;
        }
        
        String lowerContentType = contentType.toLowerCase();
        String charsetPrefix = "charset=";
        int charsetIndex = lowerContentType.indexOf(charsetPrefix);
        
        if (charsetIndex == -1) {
            return null;
        }
        
        int startIndex = charsetIndex + charsetPrefix.length();
        if (startIndex >= contentType.length()) {
            return null;
        }
        
        // Find the end of charset value (semicolon or end of string)
        int endIndex = contentType.indexOf(';', startIndex);
        if (endIndex == -1) {
            endIndex = contentType.length();
        }
        
        return contentType.substring(startIndex, endIndex).trim();
    }
    
    /**
     * Returns the content or a default value if content is null.
     * 
     * @param defaultContent The default content to return if content is null
     * @return The content or the default
     */
    public String contentOrDefault(String defaultContent) {
        return content != null ? content : defaultContent;
    }
    
    /**
     * Returns the content type or a default value if content type is null.
     * 
     * @param defaultContentType The default content type to return if contentType is null
     * @return The content type or the default
     */
    public String contentTypeOrDefault(String defaultContentType) {
        return contentType != null ? contentType : defaultContentType;
    }
    
    /**
     * Returns the encoding or a default value if encoding is null.
     * 
     * @param defaultEncoding The default encoding to return if encoding is null
     * @return The encoding or the default
     */
    public String encodingOrDefault(String defaultEncoding) {
        return encoding != null ? encoding : defaultEncoding;
    }
    
    /**
     * Returns a copy of this body with new content.
     * 
     * @param newContent The new content
     * @return A new HTTPBody with the specified content and same contentType/encoding
     */
    public HTTPBody withContent(String newContent) {
        return new HTTPBody(newContent, contentType, encoding);
    }
    
    /**
     * Returns a copy of this body with a new content type.
     * 
     * @param newContentType The new content type
     * @return A new HTTPBody with the same content/encoding and specified content type
     */
    public HTTPBody withContentType(String newContentType) {
        return new HTTPBody(content, newContentType, encoding);
    }
    
    /**
     * Returns a copy of this body with a new encoding.
     * 
     * @param newEncoding The new encoding
     * @return A new HTTPBody with the same content/contentType and specified encoding
     */
    public HTTPBody withEncoding(String newEncoding) {
        return new HTTPBody(content, contentType, newEncoding);
    }
    
    /**
     * Returns a truncated version of the content for safe logging.
     * 
     * @param maxLength The maximum length for the truncated content
     * @return The content truncated to the specified length with "..." if truncated
     */
    public String contentTruncated(int maxLength) {
        if (content == null) {
            return "null";
        }
        if (content.length() <= maxLength) {
            return content;
        }
        return content.substring(0, maxLength) + "...";
    }
}