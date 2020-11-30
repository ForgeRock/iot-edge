/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openicf.connectors.aws;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;


/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the AWS IoT Registry Connector.
 *
 */
public class AwsRegistryConfiguration extends AbstractConfiguration {

    private String accessKeyId;
    private String secretAccessKey;

    @ConfigurationProperty(order = 1, displayMessageKey = "accessKeyId.display",
            groupMessageKey = "basic.group", helpMessageKey = "accessKeyId.help",
            required = true)
    public String getAccessKeyId() {
        return accessKeyId;
    }

    @ConfigurationProperty(order = 1, displayMessageKey = "secretAccessKey.display",
            groupMessageKey = "basic.group", helpMessageKey = "secretAccessKey.help",
            required = true)
    public String getSecretAccessKey() {
        return secretAccessKey;
    }

    public void setAccessKeyId(String accessKeyId) {
        this.accessKeyId = accessKeyId;
    }

    public void setSecretAccessKey(String secretAccessKey) {
        this.secretAccessKey = secretAccessKey;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(accessKeyId)) {
            throw new IllegalArgumentException("Access Key ID cannot be null or empty.");
        }
        if (StringUtil.isBlank(secretAccessKey)) {
            throw new IllegalArgumentException("Secret Access Key cannot be null or empty.");
        }
    }

}
