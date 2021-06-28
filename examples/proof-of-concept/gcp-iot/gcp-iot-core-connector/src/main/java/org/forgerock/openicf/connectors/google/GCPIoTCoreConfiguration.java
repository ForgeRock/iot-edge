/*
 * Copyright 2016-2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openicf.connectors.google;

import java.io.ByteArrayInputStream;

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

    @ConfigurationProperty(order = 1,
            groupMessageKey = "basic.group",
            required = true)
    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    @ConfigurationProperty(order = 3,
            groupMessageKey = "basic.group",
            required = true)
    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    @ConfigurationProperty(order = 2,
            groupMessageKey = "basic.group",
            required = true)
    public String getRegistryId() {
        return registryId;
    }

    public void setRegistryId(String registryId) {
        this.registryId = registryId;
    }

    @ConfigurationProperty(order = 4,
            groupMessageKey = "basic.group",
            confidential = true,
            required = true)
    public String getCredentials() {
        return credentials;
    }

    public ByteArrayInputStream getCredentialsAsStream() {
        return new ByteArrayInputStream(credentials.getBytes());
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(projectId)) {
            throw new IllegalArgumentException("Product ID cannot be null or empty.");
        }
        if (StringUtil.isBlank(region)) {
            throw new IllegalArgumentException("Region cannot be null or empty.");
        }
        if (StringUtil.isBlank(registryId)) {
            throw new IllegalArgumentException("Registry ID cannot be null or empty.");
        }
        if (StringUtil.isBlank(credentials)) {
            throw new IllegalArgumentException("Credentials cannot be null or empty.");
        }
    }

}
