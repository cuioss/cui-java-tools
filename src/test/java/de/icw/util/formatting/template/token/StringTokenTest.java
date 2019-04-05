package de.icw.util.formatting.template.token;

import org.junit.jupiter.api.Test;

import de.icw.util.support.ObjectMethodsAsserts;

class StringTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StringToken("abc"));
    }

}
