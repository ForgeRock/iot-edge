/*
 * Copyright 2014-2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

import org.forgerock.openicf.connectors.groovy.OperationType
import org.identityconnectors.common.logging.Log

def operation = operation as OperationType
def log = log as Log

log.info("Entering " + operation + " Script");