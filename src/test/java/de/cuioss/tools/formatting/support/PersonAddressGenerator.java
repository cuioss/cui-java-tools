package de.cuioss.tools.formatting.support;

import de.cuioss.tools.support.TypedGenerator;

@SuppressWarnings("javadoc")
public class PersonAddressGenerator implements TypedGenerator<PersonAddress> {

    @Override
    public PersonAddress next() {
        final var addressDto = new AddressDto();
        addressDto.setCountry("{Deutschland");
        addressDto.setCity("{Walldorf}");
        addressDto.setLine1("{69309}");
        return new PersonAddress(addressDto);
    }

    @Override
    public Class<PersonAddress> getType() {
        return PersonAddress.class;
    }

}
