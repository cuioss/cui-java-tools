package io.cui.tools.formatting.template.token;

import org.junit.jupiter.api.Test;

import io.cui.tools.support.ObjectMethodsAsserts;

class StringTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StringToken("abc"));
    }

}
