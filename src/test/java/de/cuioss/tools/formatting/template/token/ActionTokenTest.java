package de.cuioss.tools.formatting.template.token;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.support.ObjectMethodsAsserts;

class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new ActionToken("a,bc", ","));
    }

}
