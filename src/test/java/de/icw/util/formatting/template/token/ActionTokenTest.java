package de.icw.util.formatting.template.token;

import org.junit.jupiter.api.Test;

import de.icw.util.support.ObjectMethodsAsserts;

class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new ActionToken("a,bc", ","));
    }

}
