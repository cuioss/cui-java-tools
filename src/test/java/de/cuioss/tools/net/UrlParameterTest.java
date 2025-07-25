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
package de.cuioss.tools.net;

import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.net.UrlParameter.*;
import static org.junit.jupiter.api.Assertions.*;

class UrlParameterTest {

    private UrlParameter parameter;

    @Test
    void urlParameterConstructorValidParameter() {
        parameter = new UrlParameter("name", "value");
        assertNotNull(parameter);
        parameter = new UrlParameter("na/me", "va/lue");
        assertNotNull(parameter);
        assertEquals("na%2Fme", parameter.getName());
        assertEquals("va%2Flue", parameter.getValue());
    }

    @Test
    void urlParameterConstructorInvalidNameNull() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter(null, "value"));
    }

    @Test
    void urlParameterConstructorInvalidNameEmpty() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter("", "value"));
    }

    @Test
    void urlParameterConstructorInvalidNameTrimEmpty() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter("   ", "value"));
    }

    @Test
    void isEmpty() {
        parameter = new UrlParameter("name", null);
        assertTrue(parameter.isEmpty());
        parameter = new UrlParameter("na/me", "va/lue");
        assertFalse(parameter.isEmpty());
    }

    @Test
    void createParameterString() {
        assertEquals("", UrlParameter.createParameterString());
        final var parameter1 = new UrlParameter("name1", "value1");
        final var parameter2 = new UrlParameter("name2", "value2");
        final var parameter3 = new UrlParameter("name3", "value3");
        assertEquals("?name1=value1", UrlParameter.createParameterString(parameter1));
        assertEquals("?name1=value1&name2=value2", UrlParameter.createParameterString(parameter1, parameter2));
        assertEquals("?name1=value1&name2=value2&name3=value3",
                UrlParameter.createParameterString(parameter1, parameter2, parameter3));

    }

    @Test
    void testGetUrlParameterFromMap() {
        assertTrue(getUrlParameterFromMap(null, null, true).isEmpty());
        assertTrue(getUrlParameterFromMap(new HashMap<>(), null, true).isEmpty());
        final Map<String, List<String>> testMap = new HashMap<>();
        testMap.put("name1", null);
        testMap.put("name2", mutableList(""));
        testMap.put("name3", mutableList("", ""));
        assertEquals(3, getUrlParameterFromMap(testMap, null, true).size());
        testMap.clear();
        testMap.put("name1", mutableList("value"));
        testMap.put("name2", mutableList("value1", "value2"));
        var parameters = getUrlParameterFromMap(testMap, null, true);
        final var firstParameter = parameters.getFirst();
        assertEquals("name1", firstParameter.getName());
        assertEquals("value", firstParameter.getValue());
        assertEquals("name2", parameters.get(1).getName());
        assertEquals("value1", parameters.get(1).getValue());
        testMap.clear();
        // Check sorting
        testMap.put("name2", mutableList("value"));
        testMap.put("name1", mutableList("value1"));
        parameters = getUrlParameterFromMap(testMap, null, true);
        assertEquals("name1", parameters.getFirst().getName());
        assertEquals("name2", parameters.get(1).getName());
        // Check exclude
        testMap.clear();
        testMap.put("name2", mutableList("value"));
        testMap.put("name1", mutableList("value1"));
        final var filter = new ParameterFilter(immutableList("name2"), true);
        parameters = getUrlParameterFromMap(testMap, filter, true);
        assertEquals(1, parameters.size());
        assertEquals("name1", parameters.getFirst().getName());
    }

    @Test
    void getParameterMapFromListOfUrlParameter() {
        final List<UrlParameter> list = new ArrayList<>();
        assertTrue(createParameterMap(list).isEmpty());
        assertTrue(createParameterMap(null).isEmpty());
        list.add(new UrlParameter("name1", "value1"));
        list.add(new UrlParameter("name2", "value2"));
        assertEquals(2, createParameterMap(list).size());
    }

    @Test
    void createNameValueString() {
        parameter = new UrlParameter("name", "value");
        assertEquals("name=value", parameter.createNameValueString());
    }

    @Test
    void createNameValueString2() {
        parameter = new UrlParameter("name", "value");
        assertEquals("name=value", parameter.createNameValueString(true));
    }

    @Test
    void compareTo() {
        parameter = new UrlParameter("name", "value");
        final var parameter2 = new UrlParameter("name", "value");

        assertEquals(0, parameter.compareTo(parameter2));

    }

    @Test
    void shouldProvideEscapingAfterSerialization() {
        parameter = new UrlParameter("param1", "#value");
        assertEquals("param1=%23value", parameter.createNameValueString());

        final var deserialized = (UrlParameter) ObjectMethodsAsserts.serializeAndDeserialize(parameter);

        assertEquals("param1=%23value", deserialized.createNameValueString());

        assertEquals("?param1=%23value", UrlParameter.createParameterString(deserialized));
    }

    @Test
    void shouldFilterCorrectly() {
        final List<UrlParameter> list = new ArrayList<>();
        list.add(new UrlParameter("name1", "value1"));
        final var param2 = new UrlParameter("name2", "value2");
        list.add(param2);
        final var param3 = new UrlParameter("name3", "value3");
        list.add(param3);
        list.add(new UrlParameter("javax.faces.name", "value4"));
        final var filter = new ParameterFilter(immutableList("name1"), true);

        final var filtered = UrlParameter.filterParameter(list, filter);
        assertEquals(2, filtered.size());
        assertEquals(param2, filtered.getFirst());
        assertEquals(param3, filtered.get(1));
    }

    @Test
    void shouldReturnEmpty() {
        final var filter = new ParameterFilter(immutableList("name1"), true);

        final var filtered = UrlParameter.filterParameter(null, filter);
        assertEquals(0, filtered.size());
    }

    @Test
    void shouldReturnEmpty2() {
        final List<UrlParameter> list = new ArrayList<>();
        final var filter = new ParameterFilter(immutableList("name1"), true);

        final var filtered = UrlParameter.filterParameter(list, filter);
        assertEquals(0, filtered.size());
    }

    @Test
    void parseQueryParameterShouldBehaveWellOnUnexpectedInput() {
        assertTrue(fromQueryString(null).isEmpty());
        assertTrue(fromQueryString("?").isEmpty());
        assertTrue(fromQueryString("=").isEmpty());
        assertTrue(fromQueryString("a=b=c").isEmpty());
        assertTrue(fromQueryString("?=").isEmpty());
        assertTrue(fromQueryString("?&").isEmpty());
    }

    @Test
    void parseQueryParameterShouldHandleHappyCaseKeyValue() {
        var fromQueryString = fromQueryString("name1=value1");
        assertEquals(1, fromQueryString.size());
        var urlParameter = fromQueryString.getFirst();
        assertEquals("name1", urlParameter.getName());
        assertEquals("value1", urlParameter.getValue());
    }

    @Test
    void parseQueryParameterShouldHandleHappyCaseKeyOnly() {
        var fromQueryString = fromQueryString("name1=");
        assertEquals(1, fromQueryString.size());
        var urlParameter = fromQueryString.getFirst();
        assertEquals("name1", urlParameter.getName());
        assertNull(urlParameter.getValue());

        fromQueryString = fromQueryString("name1");
        assertEquals(1, fromQueryString.size());
        urlParameter = fromQueryString.getFirst();
        assertEquals("name1", urlParameter.getName());
        assertNull(urlParameter.getValue());
    }

    @Test
    void parseQueryParameterShouldHandleHappyCaseComlexSample() {
        var fromQueryString = fromQueryString("?name1=value1&name2&name3=&");
        assertEquals(3, fromQueryString.size());
        var urlParameter = fromQueryString.getFirst();
        assertEquals("name1", urlParameter.getName());
        assertEquals("value1", urlParameter.getValue());
    }

    @Test
    void shouldHandleEmptyUrlParameterValue() {
        parameter = new UrlParameter("param1", "");
        assertEquals("param1=", parameter.createNameValueString());
    }

    @Test
    void shouldBehaveWell() {
        ObjectMethodsAsserts.assertNiceObject(new UrlParameter("name3", "value3"));
    }
}
