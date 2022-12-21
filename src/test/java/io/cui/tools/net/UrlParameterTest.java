package io.cui.tools.net;

import static io.cui.tools.collect.CollectionLiterals.immutableList;
import static io.cui.tools.collect.CollectionLiterals.mutableList;
import static io.cui.tools.net.UrlParameter.createParameterMap;
import static io.cui.tools.net.UrlParameter.fromQueryString;
import static io.cui.tools.net.UrlParameter.getUrlParameterFromMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.cui.tools.support.ObjectMethodsAsserts;

class UrlParameterTest {

    private UrlParameter parameter;

    @Test
    void testUrlParameterConstructorValidParameter() {
        parameter = new UrlParameter("name", "value");
        assertNotNull(parameter);
        parameter = new UrlParameter("na/me", "va/lue");
        assertNotNull(parameter);
        assertEquals("na%2Fme", parameter.getName());
        assertEquals("va%2Flue", parameter.getValue());
    }

    @Test
    void testUrlParameterConstructorInvalidNameNull() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter(null, "value"));
    }

    @Test
    void testUrlParameterConstructorInvalidNameEmpty() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter("", "value"));
    }

    @Test
    void testUrlParameterConstructorInvalidNameTrimEmpty() {
        assertThrows(IllegalArgumentException.class, () -> parameter = new UrlParameter("   ", "value"));
    }

    @Test
    void testIsEmpty() {
        parameter = new UrlParameter("name", null);
        assertTrue(parameter.isEmpty());
        parameter = new UrlParameter("na/me", "va/lue");
        assertFalse(parameter.isEmpty());
    }

    @Test
    void testCreateParameterString() {
        assertEquals("", UrlParameter.createParameterString());
        final UrlParameter parameter1 = new UrlParameter("name1", "value1");
        final UrlParameter parameter2 = new UrlParameter("name2", "value2");
        final UrlParameter parameter3 = new UrlParameter("name3", "value3");
        assertEquals("?name1=value1", UrlParameter.createParameterString(parameter1));
        assertEquals("?name1=value1&name2=value2",
                UrlParameter.createParameterString(parameter1, parameter2));
        assertEquals("?name1=value1&name2=value2&name3=value3",
                UrlParameter.createParameterString(parameter1, parameter2, parameter3));

    }

    @Test
    void testGetUrlParameterFromMap() {
        assertTrue(getUrlParameterFromMap(null, null, true).isEmpty());
        assertTrue(getUrlParameterFromMap(new HashMap<>(), null, true).isEmpty());
        final Map<String, List<String>> testMap = new HashMap<>();
        testMap.put("name1", null);
        testMap.put("name2", mutableList(new String()));
        testMap.put("name3", mutableList(new String(), new String()));
        assertEquals(3, getUrlParameterFromMap(testMap, null, true).size());
        testMap.clear();
        testMap.put("name1", mutableList("value"));
        testMap.put("name2", mutableList("value1", "value2"));
        List<UrlParameter> parameters = getUrlParameterFromMap(testMap, null, true);
        assertEquals("name1", parameters.get(0).getName());
        assertEquals("value", parameters.get(0).getValue());
        assertEquals("name2", parameters.get(1).getName());
        assertEquals("value1", parameters.get(1).getValue());
        testMap.clear();
        // Check sorting
        testMap.put("name2", mutableList("value"));
        testMap.put("name1", mutableList("value1"));
        parameters = getUrlParameterFromMap(testMap, null, true);
        assertEquals("name1", parameters.get(0).getName());
        assertEquals("name2", parameters.get(1).getName());
        // Check exclude
        testMap.clear();
        testMap.put("name2", mutableList("value"));
        testMap.put("name1", mutableList("value1"));
        final ParameterFilter filter = new ParameterFilter(immutableList("name2"), true);
        parameters = getUrlParameterFromMap(testMap, filter, true);
        assertEquals(1, parameters.size());
        assertEquals("name1", parameters.get(0).getName());
    }

    @Test
    void testGetParameterMapFromListOfUrlParameter() {
        final List<UrlParameter> list = new ArrayList<>();
        assertTrue(createParameterMap(list).isEmpty());
        assertTrue(createParameterMap(null).isEmpty());
        list.add(new UrlParameter("name1", "value1"));
        list.add(new UrlParameter("name2", "value2"));
        assertEquals(2, createParameterMap(list).size());
    }

    @Test
    void testCreateNameValueString() {
        parameter = new UrlParameter("name", "value");
        assertEquals("name=value", parameter.createNameValueString());
    }

    @Test
    void testCreateNameValueString2() {
        parameter = new UrlParameter("name", "value");
        assertEquals("name=value", parameter.createNameValueString(true));
    }

    @Test
    void testCompareTo() {
        parameter = new UrlParameter("name", "value");
        final UrlParameter parameter2 = new UrlParameter("name", "value");

        assertEquals(0, parameter.compareTo(parameter2));

    }

    @Test
    void shouldProvideEscapingAfterSerialization() {
        parameter = new UrlParameter("param1", "#value");
        assertEquals("param1=%23value", parameter.createNameValueString());

        final UrlParameter deserialized =
            (UrlParameter) ObjectMethodsAsserts.serializeAndDeserialize(parameter);

        assertEquals("param1=%23value", deserialized.createNameValueString());

        assertEquals("?param1=%23value", UrlParameter.createParameterString(deserialized));
    }

    @Test
    void shouldFilterCorrectly() {
        final List<UrlParameter> list = new ArrayList<>();
        list.add(new UrlParameter("name1", "value1"));
        final UrlParameter param2 = new UrlParameter("name2", "value2");
        list.add(param2);
        final UrlParameter param3 = new UrlParameter("name3", "value3");
        list.add(param3);
        list.add(new UrlParameter("javax.faces.name", "value4"));
        final ParameterFilter filter = new ParameterFilter(immutableList("name1"), true);

        final List<UrlParameter> filtered = UrlParameter.filterParameter(list, filter);
        assertEquals(2, filtered.size());
        assertEquals(param2, filtered.get(0));
        assertEquals(param3, filtered.get(1));
    }

    @Test
    void shouldReturnEmpty() {
        final ParameterFilter filter = new ParameterFilter(immutableList("name1"), true);

        final List<UrlParameter> filtered = UrlParameter.filterParameter(null, filter);
        assertEquals(0, filtered.size());
    }

    @Test
    void shouldReturnEmpty2() {
        final List<UrlParameter> list = new ArrayList<>();
        final ParameterFilter filter = new ParameterFilter(immutableList("name1"), true);

        final List<UrlParameter> filtered = UrlParameter.filterParameter(list, filter);
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
        List<UrlParameter> fromQueryString = fromQueryString("name1=value1");
        assertEquals(1, fromQueryString.size());
        UrlParameter urlParameter = fromQueryString.get(0);
        assertEquals("name1", urlParameter.getName());
        assertEquals("value1", urlParameter.getValue());
    }

    @Test
    void parseQueryParameterShouldHandleHappyCaseKeyOnly() {
        List<UrlParameter> fromQueryString = fromQueryString("name1=");
        assertEquals(1, fromQueryString.size());
        UrlParameter urlParameter = fromQueryString.get(0);
        assertEquals("name1", urlParameter.getName());
        assertNull(urlParameter.getValue());

        fromQueryString = fromQueryString("name1");
        assertEquals(1, fromQueryString.size());
        urlParameter = fromQueryString.get(0);
        assertEquals("name1", urlParameter.getName());
        assertNull(urlParameter.getValue());
    }

    @Test
    void parseQueryParameterShouldHandleHappyCaseComlexSample() {
        List<UrlParameter> fromQueryString = fromQueryString("?name1=value1&name2&name3=&");
        assertEquals(3, fromQueryString.size());
        UrlParameter urlParameter = fromQueryString.get(0);
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
