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

import static de.cuioss.tools.collect.CollectionLiterals.immutableMap;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

import de.cuioss.tools.collect.CollectionBuilder;
import de.cuioss.tools.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.Synchronized;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PersonAddress consolidate several Address Objects by make a one-way
 * transformation.
 * <p/>
 * Supported Classes: Mapping of properties will be done during construction.
 * Properties which can't be mapped will be initialized to null.
 */
@ToString
@EqualsAndHashCode
public class PersonAddress implements FormatterSupport, Serializable {

    @Serial
    private static final long serialVersionUID = -5846491132374853787L;

    private String street;

    private String postalCode;

    private String city;

    private String country;

    private String state;

    private String organization;

    private String line1;

    private String line2;

    private String flat;

    private String corpus;

    private String zipCodeExtension;

    private Map<String, Serializable> propertyValues;

    private static final List<String> SUPPORTED_PROP_LIST = new CollectionBuilder<String>().add("street")
            .add("postalCode").add("city").add("country").add("state").add("organization").add("line1").add("line2")
            .add("flat").add("corpus").add("zipCodeExtension").toImmutableList();

    /**
     * provide default constructor
     */
    public PersonAddress() {
        propertyValues = retrieveAvailablePropertyValues();
    }

    /**
     * Use data from address object to copy this to PersonAddress.
     *
     * @param address must not be null.
     */
    public PersonAddress(final TransferAddressDto address) {
        requireNonNull(address, "AddressDto must not be null");
        street = address.getStreetLine();
        line1 = address.getOtherDesignation();
        postalCode = address.getPostalCode();
        city = address.getCity();
        country = address.getCountry();
        state = address.getRegion();
        propertyValues = retrieveAvailablePropertyValues();
    }

    /**
     * Use data from address object to copy this to PersonAddress. Because this is
     * just a stupid bean and AddressDto use CodeDto for some properties they must
     * be set separate. Otherwise, CodeResolverService and locale must be passed
     * throw.
     *
     * @param address must not be null.
     */
    public PersonAddress(final AddressDto address) {
        requireNonNull(address, "AddressDto must not be null");
        street = address.getStreetAddressLine();
        postalCode = address.getPostalCode();
        city = address.getCity();
        // AddressDto use CodeDto for country
        // AddressDto use CodeDto for state
        organization = address.getOrganization();
        line1 = address.getLine1();
        line2 = address.getLine2();
        flat = address.getFlat();
        corpus = address.getCorpus();
        zipCodeExtension = address.getZipCodeExtension();
        propertyValues = retrieveAvailablePropertyValues();
    }

    @Synchronized
    private Map<String, Serializable> retrieveAvailablePropertyValues() {
        final Map<String, Serializable> builder = new HashMap<>();
        putIfNotNullOrEmpty(builder, "street", street);
        putIfNotNullOrEmpty(builder, "postalCode", postalCode);
        putIfNotNullOrEmpty(builder, "city", city);
        putIfNotNullOrEmpty(builder, "country", country);
        putIfNotNullOrEmpty(builder, "state", state);
        putIfNotNullOrEmpty(builder, "organization", organization);
        putIfNotNullOrEmpty(builder, "line1", line1);
        putIfNotNullOrEmpty(builder, "line2", line2);
        putIfNotNullOrEmpty(builder, "flat", flat);
        putIfNotNullOrEmpty(builder, "corpus", corpus);
        putIfNotNullOrEmpty(builder, "zipCodeExtension", zipCodeExtension);
        return immutableMap(builder);
    }

    /**
     * @param country the country to set
     */
    public void setCountry(String country) {
        this.country = country;
        propertyValues = retrieveAvailablePropertyValues();
    }

    /**
     * @param state the state to set
     */
    public void setState(String state) {
        this.state = state;
        propertyValues = retrieveAvailablePropertyValues();
    }

    @Synchronized
    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        return propertyValues;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        return SUPPORTED_PROP_LIST;
    }

    private static void putIfNotNullOrEmpty(final Map<String, Serializable> builder, final String key,
            final String value) {
        if (!isEmpty(value)) {
            builder.put(key, value);
        }
    }

}
