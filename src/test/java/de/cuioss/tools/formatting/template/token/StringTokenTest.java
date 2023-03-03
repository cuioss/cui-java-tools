package de.cuioss.tools.formatting.template.token;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.support.ObjectMethodsAsserts;

class StringTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StringToken("abc"));
    }

}
