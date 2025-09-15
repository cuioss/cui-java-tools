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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link HttpStatusFamily}.
 */
class HttpStatusFamilyTest {

    @Nested
    @DisplayName("fromStatusCode Tests")
    class FromStatusCodeTests {

        @Test
        @DisplayName("Should return INFORMATIONAL for 1xx codes")
        void shouldReturnInformationalFor1xxCodes() {
            assertEquals(HttpStatusFamily.INFORMATIONAL, HttpStatusFamily.fromStatusCode(100));
            assertEquals(HttpStatusFamily.INFORMATIONAL, HttpStatusFamily.fromStatusCode(101));
            assertEquals(HttpStatusFamily.INFORMATIONAL, HttpStatusFamily.fromStatusCode(199));
        }

        @Test
        @DisplayName("Should return SUCCESS for 2xx codes")
        void shouldReturnSuccessFor2xxCodes() {
            assertEquals(HttpStatusFamily.SUCCESS, HttpStatusFamily.fromStatusCode(200));
            assertEquals(HttpStatusFamily.SUCCESS, HttpStatusFamily.fromStatusCode(201));
            assertEquals(HttpStatusFamily.SUCCESS, HttpStatusFamily.fromStatusCode(204));
            assertEquals(HttpStatusFamily.SUCCESS, HttpStatusFamily.fromStatusCode(299));
        }

        @Test
        @DisplayName("Should return REDIRECTION for 3xx codes")
        void shouldReturnRedirectionFor3xxCodes() {
            assertEquals(HttpStatusFamily.REDIRECTION, HttpStatusFamily.fromStatusCode(300));
            assertEquals(HttpStatusFamily.REDIRECTION, HttpStatusFamily.fromStatusCode(301));
            assertEquals(HttpStatusFamily.REDIRECTION, HttpStatusFamily.fromStatusCode(302));
            assertEquals(HttpStatusFamily.REDIRECTION, HttpStatusFamily.fromStatusCode(304));
            assertEquals(HttpStatusFamily.REDIRECTION, HttpStatusFamily.fromStatusCode(399));
        }

        @Test
        @DisplayName("Should return CLIENT_ERROR for 4xx codes")
        void shouldReturnClientErrorFor4xxCodes() {
            assertEquals(HttpStatusFamily.CLIENT_ERROR, HttpStatusFamily.fromStatusCode(400));
            assertEquals(HttpStatusFamily.CLIENT_ERROR, HttpStatusFamily.fromStatusCode(401));
            assertEquals(HttpStatusFamily.CLIENT_ERROR, HttpStatusFamily.fromStatusCode(404));
            assertEquals(HttpStatusFamily.CLIENT_ERROR, HttpStatusFamily.fromStatusCode(499));
        }

        @Test
        @DisplayName("Should return SERVER_ERROR for 5xx codes")
        void shouldReturnServerErrorFor5xxCodes() {
            assertEquals(HttpStatusFamily.SERVER_ERROR, HttpStatusFamily.fromStatusCode(500));
            assertEquals(HttpStatusFamily.SERVER_ERROR, HttpStatusFamily.fromStatusCode(501));
            assertEquals(HttpStatusFamily.SERVER_ERROR, HttpStatusFamily.fromStatusCode(503));
            assertEquals(HttpStatusFamily.SERVER_ERROR, HttpStatusFamily.fromStatusCode(599));
        }

        @Test
        @DisplayName("Should return UNKNOWN for invalid codes")
        void shouldReturnUnknownForInvalidCodes() {
            assertEquals(HttpStatusFamily.UNKNOWN, HttpStatusFamily.fromStatusCode(-1));
            assertEquals(HttpStatusFamily.UNKNOWN, HttpStatusFamily.fromStatusCode(0));
            assertEquals(HttpStatusFamily.UNKNOWN, HttpStatusFamily.fromStatusCode(99));
            assertEquals(HttpStatusFamily.UNKNOWN, HttpStatusFamily.fromStatusCode(600));
            assertEquals(HttpStatusFamily.UNKNOWN, HttpStatusFamily.fromStatusCode(1000));
        }
    }

    @Nested
    @DisplayName("contains Tests")
    class ContainsTests {

        @Test
        @DisplayName("INFORMATIONAL should contain 1xx codes")
        void informationalShouldContain1xxCodes() {
            assertTrue(HttpStatusFamily.INFORMATIONAL.contains(100));
            assertTrue(HttpStatusFamily.INFORMATIONAL.contains(101));
            assertTrue(HttpStatusFamily.INFORMATIONAL.contains(199));
            assertFalse(HttpStatusFamily.INFORMATIONAL.contains(99));
            assertFalse(HttpStatusFamily.INFORMATIONAL.contains(200));
        }

        @Test
        @DisplayName("SUCCESS should contain 2xx codes")
        void successShouldContain2xxCodes() {
            assertTrue(HttpStatusFamily.SUCCESS.contains(200));
            assertTrue(HttpStatusFamily.SUCCESS.contains(201));
            assertTrue(HttpStatusFamily.SUCCESS.contains(299));
            assertFalse(HttpStatusFamily.SUCCESS.contains(199));
            assertFalse(HttpStatusFamily.SUCCESS.contains(300));
        }

        @Test
        @DisplayName("REDIRECTION should contain 3xx codes")
        void redirectionShouldContain3xxCodes() {
            assertTrue(HttpStatusFamily.REDIRECTION.contains(300));
            assertTrue(HttpStatusFamily.REDIRECTION.contains(301));
            assertTrue(HttpStatusFamily.REDIRECTION.contains(399));
            assertFalse(HttpStatusFamily.REDIRECTION.contains(299));
            assertFalse(HttpStatusFamily.REDIRECTION.contains(400));
        }

        @Test
        @DisplayName("CLIENT_ERROR should contain 4xx codes")
        void clientErrorShouldContain4xxCodes() {
            assertTrue(HttpStatusFamily.CLIENT_ERROR.contains(400));
            assertTrue(HttpStatusFamily.CLIENT_ERROR.contains(404));
            assertTrue(HttpStatusFamily.CLIENT_ERROR.contains(499));
            assertFalse(HttpStatusFamily.CLIENT_ERROR.contains(399));
            assertFalse(HttpStatusFamily.CLIENT_ERROR.contains(500));
        }

        @Test
        @DisplayName("SERVER_ERROR should contain 5xx codes")
        void serverErrorShouldContain5xxCodes() {
            assertTrue(HttpStatusFamily.SERVER_ERROR.contains(500));
            assertTrue(HttpStatusFamily.SERVER_ERROR.contains(503));
            assertTrue(HttpStatusFamily.SERVER_ERROR.contains(599));
            assertFalse(HttpStatusFamily.SERVER_ERROR.contains(499));
            assertFalse(HttpStatusFamily.SERVER_ERROR.contains(600));
        }

        @Test
        @DisplayName("UNKNOWN should contain invalid codes")
        void unknownShouldContainInvalidCodes() {
            assertTrue(HttpStatusFamily.UNKNOWN.contains(-1));
            assertTrue(HttpStatusFamily.UNKNOWN.contains(0));
            assertTrue(HttpStatusFamily.UNKNOWN.contains(99));
            assertTrue(HttpStatusFamily.UNKNOWN.contains(600));
            assertFalse(HttpStatusFamily.UNKNOWN.contains(100));
            assertFalse(HttpStatusFamily.UNKNOWN.contains(599));
        }
    }

    @Nested
    @DisplayName("Utility Method Tests")
    class UtilityMethodTests {

        @ParameterizedTest
        @ValueSource(ints = {200, 201, 204, 299})
        @DisplayName("isSuccess should return true for 2xx codes")
        void isSuccessShouldReturnTrueFor2xxCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isSuccess(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 199, 300, 400, 500})
        @DisplayName("isSuccess should return false for non-2xx codes")
        void isSuccessShouldReturnFalseForNon2xxCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isSuccess(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {400, 401, 404, 499})
        @DisplayName("isClientError should return true for 4xx codes")
        void isClientErrorShouldReturnTrueFor4xxCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isClientError(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 200, 300, 500})
        @DisplayName("isClientError should return false for non-4xx codes")
        void isClientErrorShouldReturnFalseForNon4xxCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isClientError(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {500, 501, 503, 599})
        @DisplayName("isServerError should return true for 5xx codes")
        void isServerErrorShouldReturnTrueFor5xxCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isServerError(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 200, 300, 400})
        @DisplayName("isServerError should return false for non-5xx codes")
        void isServerErrorShouldReturnFalseForNon5xxCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isServerError(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {300, 301, 302, 304, 399})
        @DisplayName("isRedirection should return true for 3xx codes")
        void isRedirectionShouldReturnTrueFor3xxCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isRedirection(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 200, 400, 500})
        @DisplayName("isRedirection should return false for non-3xx codes")
        void isRedirectionShouldReturnFalseForNon3xxCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isRedirection(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 101, 199})
        @DisplayName("isInformational should return true for 1xx codes")
        void isInformationalShouldReturnTrueFor1xxCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isInformational(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {99, 200, 300, 400, 500})
        @DisplayName("isInformational should return false for non-1xx codes")
        void isInformationalShouldReturnFalseForNon1xxCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isInformational(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {100, 200, 300, 400, 500, 599})
        @DisplayName("isValid should return true for valid codes")
        void isValidShouldReturnTrueForValidCodes(int statusCode) {
            assertTrue(HttpStatusFamily.isValid(statusCode));
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, 0, 99, 600, 1000})
        @DisplayName("isValid should return false for invalid codes")
        void isValidShouldReturnFalseForInvalidCodes(int statusCode) {
            assertFalse(HttpStatusFamily.isValid(statusCode));
        }
    }

    @Nested
    @DisplayName("toString Tests")
    class ToStringTests {

        @Test
        @DisplayName("toString should format correctly for standard families")
        void toStringShouldFormatCorrectlyForStandardFamilies() {
            assertEquals("Informational (100-199)", HttpStatusFamily.INFORMATIONAL.toString());
            assertEquals("Success (200-299)", HttpStatusFamily.SUCCESS.toString());
            assertEquals("Redirection (300-399)", HttpStatusFamily.REDIRECTION.toString());
            assertEquals("Client Error (400-499)", HttpStatusFamily.CLIENT_ERROR.toString());
            assertEquals("Server Error (500-599)", HttpStatusFamily.SERVER_ERROR.toString());
        }

        @Test
        @DisplayName("toString should format correctly for UNKNOWN")
        void toStringShouldFormatCorrectlyForUnknown() {
            assertEquals("Unknown", HttpStatusFamily.UNKNOWN.toString());
        }
    }
}