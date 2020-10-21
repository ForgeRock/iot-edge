/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openicf.connectors.google;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;


/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the GoogleIotHub Connector.
 *
 */
public class GCPIoTCoreConfiguration extends AbstractConfiguration {

    private String projectId;
    private String region;
    private String registryId;
    private String credentials;

    @ConfigurationProperty(order = 1, displayMessageKey = "projectId.display",
            groupMessageKey = "basic.group", helpMessageKey = "projectId.help",
            required = true)
    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String iotHubProjectId) {
        this.projectId = iotHubProjectId;
    }

    @ConfigurationProperty(order = 1, displayMessageKey = "region.display",
            groupMessageKey = "basic.group", helpMessageKey = "region.help",
            required = true)
    public String getRegion() {
        return region;
    }

    public void setRegion(String iotHubRegion) {
        this.region = iotHubRegion;
    }

    @ConfigurationProperty(order = 1, displayMessageKey = "registryId.display",
            groupMessageKey = "basic.group", helpMessageKey = "registryId.help",
            required = true)
    public String getRegistryId() {
        return registryId;
    }

    public void setRegistryId(String iotHubRegistryId) {
        this.registryId = iotHubRegistryId;
    }

    @ConfigurationProperty(order = 1, displayMessageKey = "credentials.display",
            groupMessageKey = "basic.group", helpMessageKey = "credentials.help",
            required = true)
    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String iotHubCredentials) {
        this.credentials = iotHubCredentials;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(projectId)) {
            throw new IllegalArgumentException("Product ID cannot be null or empty.");
        }
    }

}
