/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openicf.connectors.azure;

import static com.microsoft.azure.sdk.iot.service.DeviceStatus.Disabled;
import static com.microsoft.azure.sdk.iot.service.DeviceStatus.Enabled;
import static com.microsoft.azure.sdk.iot.service.devicetwin.SqlQuery.FromType.DEVICES;
import static com.microsoft.azure.sdk.iot.service.devicetwin.SqlQuery.createSqlQuery;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
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

import com.microsoft.azure.sdk.iot.service.Device;
import com.microsoft.azure.sdk.iot.service.RegistryManager;
import com.microsoft.azure.sdk.iot.service.devicetwin.DeviceTwin;
import com.microsoft.azure.sdk.iot.service.devicetwin.DeviceTwinDevice;
import com.microsoft.azure.sdk.iot.service.devicetwin.Query;
import com.microsoft.azure.sdk.iot.service.devicetwin.SqlQuery;
import com.microsoft.azure.sdk.iot.service.exceptions.IotHubException;
import org.identityconnectors.framework.spi.operations.UpdateOp;

/**
 * Main implementation of the AzureIotHub Connector.
 */
@ConnectorClass(displayNameKey = "AzureIotHub.connector.display", configurationClass = AzureIotHubConfiguration.class)
public class AzureIotHubConnector implements Connector, TestOp, SchemaOp, SearchOp<Filter>, SyncOp, UpdateOp {
    private static final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS`Z`");
    private static final AttributeInfo THING_TYPE_ATTR_INFO = AttributeInfoBuilder.build("thingType", String.class);
    private static final AttributeInfo STATUS_ATTR_INFO = AttributeInfoBuilder.build("accountStatus", String.class);
    private static final AttributeInfo UID_ATTR_INFO = AttributeInfoBuilder.build(Uid.NAME, String.class);
    private static final Attribute THING_TYPE_ATTR = AttributeBuilder.build("thingType", "DEVICE");
    private static final ObjectClass THINGS = new ObjectClass("THINGS");
    private static final Log logger = Log.getLog(AzureIotHubConnector.class);

    private AzureIotHubConfiguration configuration;
    private DeviceTwin twinClient;
    private String twinConnectionString;
    private RegistryManager registryManager;
    private String registryConnectionString;
    private Schema schema = null;

    private DeviceTwin getTwinClient() throws IOException {
        String connectionString = this.configuration.getConnectionString();
        if (twinClient == null || !connectionString.equals(twinConnectionString)) {
            twinConnectionString = connectionString;
            twinClient = DeviceTwin.createFromConnectionString(twinConnectionString);
        }
        return twinClient;
    }

    private RegistryManager getRegistryManager() throws IOException {
        String connectionString = this.configuration.getConnectionString();
        if (registryManager == null || !connectionString.equals(registryConnectionString)) {
            registryConnectionString = connectionString;
            registryManager = RegistryManager.createFromConnectionString(registryConnectionString);
        }
        return registryManager;
    }

    @Override
    public Configuration getConfiguration() {
        return this.configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        this.configuration = (AzureIotHubConfiguration) configuration;
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
            // Get the DeviceTwin and DeviceTwinDevice objects
            SqlQuery sqlQuery = createSqlQuery("*", DEVICES, null, null);
            DeviceTwin client = getTwinClient();
            Query twinQuery = client.queryTwin(sqlQuery.getQuery(), 100);
            while (client.hasNextDeviceTwin(twinQuery)) {
                DeviceTwinDevice twin = client.getNextDeviceTwin(twinQuery);
                SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
                deltaBuilder.setObject(buildThing(twin.getDeviceId()));
                deltaBuilder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
                deltaBuilder.setToken(syncToken);
                if (!handler.handle(deltaBuilder.build())) {
                    break;
                }
            }
            ((SyncTokenResultsHandler) handler).handleResult(syncToken);
        } catch (IOException e) {
            logger.error("Device sync failed.", e);
            throw new ConnectorIOException(e);
        } catch (IotHubException e) {
            logger.error("Device sync failed.", e);
            throw new ConnectorException(e);
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
        SchemaBuilder builder = new SchemaBuilder(AzureIotHubConnector.class);
        ObjectClassInfoBuilder thingsInfoBuilder = new ObjectClassInfoBuilder();
        thingsInfoBuilder.setType(THINGS.getObjectClassValue());
        thingsInfoBuilder.addAttributeInfo(Name.INFO);
        thingsInfoBuilder.addAttributeInfo(UID_ATTR_INFO);
        thingsInfoBuilder.addAttributeInfo(THING_TYPE_ATTR_INFO);
        thingsInfoBuilder.addAttributeInfo(STATUS_ATTR_INFO);
        builder.defineObjectClass(thingsInfoBuilder.build(), SearchOp.class, SyncOp.class);
        schema = builder.build();
        return schema;
    }

    @Override
    public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new AzureIotHubFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
        isThing(objectClass);
        try {
            // Get the DeviceTwin and DeviceTwinDevice objects
            SqlQuery sqlQuery = createSqlQuery("*", DEVICES, null, null);
            DeviceTwin client = getTwinClient();
            Query twinQuery = client.queryTwin(sqlQuery.getQuery(), 100);
            while (client.hasNextDeviceTwin(twinQuery)) {
                DeviceTwinDevice twin = client.getNextDeviceTwin(twinQuery);
                ConnectorObject thing = buildThing(twin.getDeviceId());
                if ((query == null || query.accept(thing)) && !handler.handle(thing)) {
                    break;
                }
            }
            ((SearchResultsHandler) handler).handleResult(new SearchResult());
        } catch (IOException e) {
            logger.error("Device query failed.", e);
            throw new ConnectorIOException(e);
        } catch (IotHubException e) {
            logger.error("Device query failed.", e);
            throw new ConnectorException(e);
        }
    }

    @Override
    public void test() {
        // test the connection to the IoT Hub
        try {
            getTwinClient();
            getRegistryManager();
        } catch (IOException e) {
            logger.error("IoT Hub connection failed.", e);
            throw new ConnectorIOException(e);
        }
    }

    private ConnectorObject buildThing(String deviceId) throws IOException, IotHubException {
        Device device = getRegistryManager().getDevice(deviceId);
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(THINGS);
        builder.setUid(deviceId);
        builder.setName(deviceId);
        builder.addAttribute(THING_TYPE_ATTR);
        builder.addAttribute(device.getStatus() == Enabled ? AttributeBuilder.build("accountStatus", "active") :
                AttributeBuilder.build("accountStatus", "inactive"));
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
        AttributesAccessor attributesAccessor = new AttributesAccessor(set);
        if( attributesAccessor.hasAttribute(STATUS_ATTR_INFO.getName())) {
            String accountStatus = attributesAccessor.findString(STATUS_ATTR_INFO.getName());
            logger.info("update blocked for {0} with account status {1}", uid.getUidValue(), accountStatus);
            try {
                RegistryManager manager = getRegistryManager();
                Device device = manager.getDevice(uid.getUidValue());
                device.setStatus(accountStatus.equals("inactive")? Disabled: Enabled);
                manager.updateDevice(device);
            } catch (IOException e) {
                logger.error("device update error", e);
                throw new ConnectorIOException(e);
            } catch (IotHubException e) {
                logger.error("device update error", e);
                throw new ConnectorException(e);
            }
        }
        return uid;
    }
}
