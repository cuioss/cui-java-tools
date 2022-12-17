package io.cui.util.formatting.template.token;

import org.junit.jupiter.api.Test;

import io.cui.util.support.ObjectMethodsAsserts;

class StringTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StringToken("abc"));
    }

}
