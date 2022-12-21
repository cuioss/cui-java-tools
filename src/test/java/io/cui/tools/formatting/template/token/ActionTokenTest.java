package io.cui.tools.formatting.template.token;

import org.junit.jupiter.api.Test;

import io.cui.tools.support.ObjectMethodsAsserts;

class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new ActionToken("a,bc", ","));
    }

}
