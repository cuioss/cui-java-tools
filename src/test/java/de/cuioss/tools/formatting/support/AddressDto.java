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

import java.io.Serializable;

import lombok.Data;

@SuppressWarnings("javadoc")
@Data
public class AddressDto implements Serializable {

    private static final long serialVersionUID = -8011318084675794828L;
    private String streetAddressLine;
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
}
