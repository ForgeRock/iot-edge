/*
 * Copyright 2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

import org.forgerock.openicf.connectors.groovy.OperationType
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder
import org.identityconnectors.framework.common.objects.Name
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.Uid

def operation = operation as OperationType
def log = log as Log

log.info("Entering " + operation + " Script")

// Declare the __THING__ attributes
def THINGS = new ObjectClass("__THING__")
def uidAttrInfo = new AttributeInfoBuilder(Uid.NAME, String.class).setRequired(true)
def thingTypeAttrInfo = new AttributeInfoBuilder("thingType", String.class)
def thingConfigAttrInfo = new AttributeInfoBuilder("thingConfig", String.class)

return builder.schema({
    objectClass {
        type THINGS.getObjectClassValue()
        attribute Name.INFO
        attribute uidAttrInfo.build()
        attribute thingTypeAttrInfo.build()
        attribute thingConfigAttrInfo.build()
    }
})

log.info("Schema script done")
