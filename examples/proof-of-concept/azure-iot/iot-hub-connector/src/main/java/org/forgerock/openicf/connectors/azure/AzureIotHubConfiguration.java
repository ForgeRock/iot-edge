/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openicf.connectors.azure;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;


/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the AzureIotHub Connector.
 *
 */
public class AzureIotHubConfiguration extends AbstractConfiguration {

    private String iotHubConnectionString;

    @ConfigurationProperty(order = 1, displayMessageKey = "connectionString.display",
            groupMessageKey = "basic.group", helpMessageKey = "connectionString.help",
            required = true)
    public String getConnectionString() {
        return iotHubConnectionString;
    }

    public void setConnectionString(String iotHubConnectionString) {
        this.iotHubConnectionString = iotHubConnectionString;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(iotHubConnectionString)) {
            throw new IllegalArgumentException("Connection String cannot be null or empty.");
        }
    }

}
