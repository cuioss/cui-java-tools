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
package de.cuioss.http.client.handler;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enum representing HTTP status code families as defined in RFC 7231.
 * <p>
 * The HTTP status codes are grouped into five classes:
 * <ul>
 *   <li>1xx: Informational - Request received, continuing process</li>
 *   <li>2xx: Success - The action was successfully received, understood, and accepted</li>
 *   <li>3xx: Redirection - Further action needs to be taken in order to complete the request</li>
 *   <li>4xx: Client Error - The request contains bad syntax or cannot be fulfilled</li>
 *   <li>5xx: Server Error - The server failed to fulfill an apparently valid request</li>
 * </ul>
 * <p>
 * This enum provides methods to check if a status code belongs to a particular family
 * and to get the family for a given status code.
 */
@RequiredArgsConstructor
public enum HttpStatusFamily {

    /**
     * 1xx: Informational - Request received, a continuing process.
     */
    INFORMATIONAL(100, 199, "Informational"),

    /**
     * 2xx: Success - The action was successfully received, understood, and accepted.
     */
    SUCCESS(200, 299, "Success"),

    /**
     * 3xx: Redirection - Further action needs to be taken to complete the request.
     */
    REDIRECTION(300, 399, "Redirection"),

    /**
     * 4xx: Client Error - The request contains bad syntax or cannot be fulfilled.
     */
    CLIENT_ERROR(400, 499, "Client Error"),

    /**
     * 5xx: Server Error - The server failed to fulfill an apparently valid request.
     */
    SERVER_ERROR(500, 599, "Server Error"),

    /**
     * Unknown - Used for status codes outside the standard ranges or for error conditions.
     */
    UNKNOWN(-1, -1, "Unknown");

    @Getter
    private final int minCode;

    @Getter
    private final int maxCode;

    @Getter
    private final String description;

    /**
     * Checks if the given status code belongs to this family.
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code belongs to this family, false otherwise
     */
    public boolean contains(int statusCode) {
        if (this == UNKNOWN) {
            return statusCode < 100 || statusCode > 599;
        }
        return statusCode >= minCode && statusCode <= maxCode;
    }

    /**
     * Gets the HTTP status code family for the given status code.
     *
     * @param statusCode the HTTP status code
     * @return the corresponding HttpStatusFamily family
     */
    public static HttpStatusFamily fromStatusCode(int statusCode) {
        for (HttpStatusFamily family : values()) {
            if (family.contains(statusCode)) {
                return family;
            }
        }
        return UNKNOWN;
    }

    /**
     * Checks if the given status code indicates a successful response (2xx).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code indicates success, false otherwise
     */
    public static boolean isSuccess(int statusCode) {
        return SUCCESS.contains(statusCode);
    }

    /**
     * Checks if the given status code indicates a client error (4xx).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code indicates a client error, false otherwise
     */
    public static boolean isClientError(int statusCode) {
        return CLIENT_ERROR.contains(statusCode);
    }

    /**
     * Checks if the given status code indicates a server error (5xx).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code indicates a server error, false otherwise
     */
    public static boolean isServerError(int statusCode) {
        return SERVER_ERROR.contains(statusCode);
    }

    /**
     * Checks if the given status code indicates a redirection (3xx).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code indicates a redirection, false otherwise
     */
    public static boolean isRedirection(int statusCode) {
        return REDIRECTION.contains(statusCode);
    }

    /**
     * Checks if the given status code indicates an informational response (1xx).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code indicates an informational response, false otherwise
     */
    public static boolean isInformational(int statusCode) {
        return INFORMATIONAL.contains(statusCode);
    }

    /**
     * Checks if the given status code is a valid HTTP status code (100-599).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code is valid, false otherwise
     */
    public static boolean isValid(int statusCode) {
        return statusCode >= 100 && statusCode <= 599;
    }

    @Override
    public String toString() {
        if (this == UNKNOWN) {
            return description;
        }
        return "%s (%d-%d)".formatted(description, minCode, maxCode);
    }
}