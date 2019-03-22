package de.icw.util.formatting.support;

import de.icw.util.support.TypedGenerator;

@SuppressWarnings("javadoc")
public class PersonAddressGenerator implements TypedGenerator<PersonAddress> {

    @Override
    public PersonAddress next() {
        final AddressDto addressDto = new AddressDto();
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
