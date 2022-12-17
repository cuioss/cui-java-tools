package io.cui.util.formatting.template.token;

import org.junit.jupiter.api.Test;

import io.cui.util.support.ObjectMethodsAsserts;

class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new ActionToken("a,bc", ","));
    }

}
