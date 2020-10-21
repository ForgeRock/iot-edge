/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openicf.connectors.google;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
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

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.services.cloudiot.v1.CloudIot;
import com.google.api.services.cloudiot.v1.CloudIotScopes;
import com.google.api.services.cloudiot.v1.model.Device;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * Main implementation of the GoogleIotHub Connector.
 */
@ConnectorClass(displayNameKey = "GCPIoTCore.connector.display", configurationClass = GCPIoTCoreConfiguration.class)
public class GCPIoTCoreConnector implements Connector, TestOp, SchemaOp, SearchOp<Filter>, SyncOp {
    private static final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS`Z`");
    private static final AttributeInfo THING_TYPE_ATTR_INFO = AttributeInfoBuilder.build("thingType", String.class);
    private static final AttributeInfo STATUS_ATTR_INFO = AttributeInfoBuilder.build("accountStatus", String.class);
    private static final AttributeInfo UID_ATTR_INFO = AttributeInfoBuilder.build(Uid.NAME, String.class);
    private static final Attribute THING_TYPE_ATTR = AttributeBuilder.build("thingType", "DEVICE");
    private static final ObjectClass THINGS = new ObjectClass("THINGS");
    private static final Log logger = Log.getLog(GCPIoTCoreConnector.class);

    private GCPIoTCoreConfiguration configuration;
    private Schema schema = null;

    private CloudIot getService() throws IOException, GeneralSecurityException {
        GoogleCredentials credentials = GoogleCredentials.fromStream(new ByteArrayInputStream(this.configuration.getCredentials().getBytes())).createScoped(CloudIotScopes.all());
        credentials.refreshIfExpired();
        CloudIot.Builder builder = new CloudIot.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                JacksonFactory.getDefaultInstance(),
                new HttpCredentialsAdapter(credentials));
        builder.setApplicationName("idm-connector");
        return builder.build();
    }

    private String getRegistryPath() {
        return String.format("projects/%1$s/locations/%2$s/registries/%3$s",
                this.configuration.getProjectId(),
                this.configuration.getRegion(),
                this.configuration.getRegistryId());
    }

    private List<Device> getDevices(CloudIot service) throws IOException {
        return service.projects()
                .locations()
                .registries()
                .devices()
                .list(getRegistryPath())
                .setFieldMask("blocked")
                .execute()
                .getDevices();
    }

    @Override
    public Configuration getConfiguration() {
        return this.configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        this.configuration = (GCPIoTCoreConfiguration) configuration;
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
            CloudIot service = getService();
            List<Device> devices = getDevices(service);
            for( Device d : devices ) {
                SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
                deltaBuilder.setObject(buildThing(d));
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
        } catch (GeneralSecurityException e) {
            logger.error("Device sync failed.", e);
            throw new ConnectorIOException(e);
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
        SchemaBuilder builder = new SchemaBuilder(GCPIoTCoreConnector.class);
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
        return new GCPIoTCoreFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
        isThing(objectClass);
        try {
            CloudIot service = getService();
            List<Device> devices = getDevices(service);
            if (devices == null) {
                logger.error(String.format("empty list returned for %s", getRegistryPath()));
                return;
            }
            for( Device d : devices ) {
                ConnectorObject thing = buildThing(d);
                if ((query == null || query.accept(thing)) && !handler.handle(thing)) {
                    break;
                }
            }
            ((SearchResultsHandler) handler).handleResult(new SearchResult());
        } catch (IOException e) {
            logger.error("Device query failed.", e);
            throw new ConnectorIOException(e);
        } catch (GeneralSecurityException e) {
            logger.error("Device query failed.", e);
            throw new ConnectorIOException(e);
        }
    }

    @Override
    public void test() {
        // test the connection to the IoT Hub
        try {
            getService();
        } catch (IOException e) {
            logger.error("IoT Hub connection failed.", e);
            throw new ConnectorIOException(e);
        } catch (GeneralSecurityException e) {
            logger.error("IoT Hub connection failed.", e);
            throw new ConnectorIOException(e);
        }
    }

    private ConnectorObject buildThing(Device device) throws IOException {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(THINGS);
        builder.setUid(device.getId());
        builder.setName(device.getId());
        builder.addAttribute(THING_TYPE_ATTR);

        Boolean blocked = device.getBlocked();
        builder.addAttribute(AttributeBuilder.build("accountStatus",
                blocked != null && blocked.booleanValue() ? "inactive" : "active"));

        return builder.build();
    }

    private void isThing(ObjectClass objectClass) {
        if (!THINGS.equals(objectClass)) {
            throw new IllegalArgumentException(String.format("Operation requires ObjectClass %s, received %s",
                    THINGS.getDisplayNameKey(), objectClass));
        }
    }
}
