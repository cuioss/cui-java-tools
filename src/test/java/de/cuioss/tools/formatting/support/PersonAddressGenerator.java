/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
