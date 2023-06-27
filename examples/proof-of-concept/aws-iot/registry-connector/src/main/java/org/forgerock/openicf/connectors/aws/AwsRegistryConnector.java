/*
 * Copyright 2016-2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openicf.connectors.aws;

import java.io.IOException;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iot.IotClient;
import software.amazon.awssdk.services.iot.model.AttributePayload;
import software.amazon.awssdk.services.iot.model.ListThingsResponse;
import software.amazon.awssdk.services.iot.model.ThingAttribute;
import software.amazon.awssdk.services.iot.model.UpdateThingRequest;

/**
 * Main implementation of the AWS IoT Registry Connector.
 */
@ConnectorClass(displayNameKey = "AwsRegistry.connector.display", configurationClass = AwsRegistryConfiguration.class)
public class AwsRegistryConnector implements Connector, TestOp, SchemaOp, SearchOp<Filter>, SyncOp, UpdateOp {
    private static final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS`Z`");
    private static final AttributeInfo THING_TYPE_ATTR_INFO = AttributeInfoBuilder.build("thingType", String.class);
    private static final AttributeInfo THING_CONFIG_ATTR_INFO = AttributeInfoBuilder.build("thingConfig", String.class);
    private static final AttributeInfo UID_ATTR_INFO = AttributeInfoBuilder.build(Uid.NAME, String.class);
    private static final Attribute THING_TYPE_ATTR = AttributeBuilder.build("thingType", "DEVICE");
    private static final ObjectClass THINGS = new ObjectClass("THINGS");
    private static final Log logger = Log.getLog(AwsRegistryConnector.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    // Note that in a production solution the region should be made configurable
    private static final Region REGION = Region.US_WEST_2;

    private AwsRegistryConfiguration configuration;
    private IotClient iotClient;
    private String accessKeyId;
    private String secretAccessKey;
    private Schema schema = null;

    private IotClient getIoTClient() {
        String id = this.configuration.getAccessKeyId();
        String secret = this.configuration.getSecretAccessKey();
        if (iotClient == null || !id.equals(accessKeyId) || !secret.equals(secretAccessKey)) {
            accessKeyId = id;
            secretAccessKey = secret;
            iotClient = IotClient.builder()
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(id, secret)))
                    .region(REGION)
                    .build();
        }
        return iotClient;
    }

    @Override
    public Configuration getConfiguration() {
        return this.configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        this.configuration = (AwsRegistryConfiguration) configuration;
    }

    @Override
    public void dispose() {
        configuration = null;
    }

    /******************
     * SPI Operations
     *
     * Implement the following operations using the contract and
     * description found in the Javadoc for these methods.
     ******************/

    @Override
    public void sync(ObjectClass objectClass, SyncToken syncToken, SyncResultsHandler handler,
            OperationOptions operationOptions) {
        isThing(objectClass);
        try {
            IotClient client = getIoTClient();
            ListThingsResponse response = client.listThings();
            SyncToken newToken = new SyncToken(simpleDateFormat.format(new Date()));
            for (ThingAttribute thingAttribute : response.things()) {
                SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
                deltaBuilder.setObject(buildThing(thingAttribute));
                deltaBuilder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
                deltaBuilder.setToken(newToken);
                if (!handler.handle(deltaBuilder.build())) {
                    break;
                }
            }
            ((SyncTokenResultsHandler) handler).handleResult(newToken);
        } catch (Exception e) {
            logger.error("Device query failed", e);
            throw new ConnectorIOException("Device query failed", e);
        }
    }

    @Override
    public SyncToken getLatestSyncToken(ObjectClass objectClass) {
        isThing(objectClass);
        return new SyncToken(simpleDateFormat.format(new Date()));
    }

    @Override
    public Schema schema() {
        if (null != schema) {
            return schema;
        }
        SchemaBuilder builder = new SchemaBuilder(AwsRegistryConnector.class);
        ObjectClassInfoBuilder thingsInfoBuilder = new ObjectClassInfoBuilder();
        thingsInfoBuilder.setType(THINGS.getObjectClassValue());
        thingsInfoBuilder.addAttributeInfo(Name.INFO);
        thingsInfoBuilder.addAttributeInfo(UID_ATTR_INFO);
        thingsInfoBuilder.addAttributeInfo(THING_TYPE_ATTR_INFO);
        thingsInfoBuilder.addAttributeInfo(THING_CONFIG_ATTR_INFO);
        builder.defineObjectClass(thingsInfoBuilder.build(), SearchOp.class, SyncOp.class);
        schema = builder.build();
        return schema;
    }

    @Override
    public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new AwsRegistryFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
        isThing(objectClass);
        try {
            IotClient client = getIoTClient();
            ListThingsResponse response = client.listThings();
            for (ThingAttribute thingAttribute : response.things()) {
                ConnectorObject thing = buildThing(thingAttribute);
                if ((query == null || query.accept(thing)) && !handler.handle(thing)) {
                    break;
                }
            }
            ((SearchResultsHandler) handler).handleResult(new SearchResult());
        } catch (Exception e) {
            logger.error("Device query failed", e);
            throw new ConnectorIOException("Device query failed", e);
        }
    }

    @Override
    public void test() {
    }

    private ConnectorObject buildThing(ThingAttribute thingAttribute) throws IOException {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(THINGS);
        builder.setUid(thingAttribute.thingName());
        builder.setName(thingAttribute.thingName());
        builder.addAttribute(THING_TYPE_ATTR);
        if (thingAttribute.hasAttributes()) {
            StringWriter writer = new StringWriter();
            objectMapper.writeValue(writer, thingAttribute.attributes());
            builder.addAttribute(AttributeBuilder.build("thingConfig", writer.toString()));
        }
        return builder.build();
    }

    private void isThing(ObjectClass objectClass) {
        if (!THINGS.equals(objectClass)) {
            throw new IllegalArgumentException(String.format("Operation requires ObjectClass %s, received %s",
                    THINGS.getDisplayNameKey(), objectClass));
        }
    }

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> set, OperationOptions operationOptions) {
        isThing(objectClass);
        AttributesAccessor accessor = new AttributesAccessor(set);
        if (accessor.hasAttribute(THING_CONFIG_ATTR_INFO.getName())) {
            try {
                Map<String, String> attributes = objectMapper.readValue(
                        accessor.findString(THING_CONFIG_ATTR_INFO.getName()).getBytes(), HashMap.class);
                IotClient client = getIoTClient();
                client.updateThing(UpdateThingRequest.builder()
                        .thingName(uid.getUidValue())
                        .attributePayload(AttributePayload.builder().attributes(attributes).merge(false).build())
                        .build());
            } catch (Exception e) {
                logger.error("Device update failed", e);
                throw new ConnectorIOException("Device update failed", e);
            }
        }
        return uid;
    }
}
