#
# Copyright 2022-23 ForgeRock AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ldapmodify \
        --hostname localhost \
        --port 1636 \
        --useSsl \
        --bindDN uid=admin \
        --bindPassword $(cat $DS_UID_ADMIN_PASSWORD_FILE) \
        --trustAll <<EOF
dn: cn=schema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.20 NAME 'thingType' DESC 'Type of a thing (e.g. device, service or iec)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.21 NAME 'thingKeys' DESC 'JWKS containing the various keys used by things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.22 NAME 'thingOAuth2ClientName' DESC 'OAuth 2.0 client associated with the thing' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.23 NAME 'thingConfig' DESC 'Configuration for things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.24 NAME 'thingProperties' DESC 'Properties of things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.25 NAME 'thingCertificatePem' DESC 'Certificate for things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.26 NAME 'thingCertificateRotate' DESC 'Certificate rotation required for things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.27 NAME 'fr-idm-managed-thing-custom-attrs' EQUALITY caseIgnoreJsonQueryMatch SYNTAX 1.3.6.1.4.1.36733.2.1.3.1 SINGLE-VALUE X-STABILITY 'Internal' X-ORIGIN 'OpenAM' )
-
add: objectClasses
objectClasses: ( 1.3.6.1.4.1.36733.2.2.2.20 NAME 'fr-iot' DESC 'Auxiliary class for ForgeRock IoT Identity attributes'
 SUP top AUXILIARY MAY ( thingType $ thingKeys $ thingOAuth2ClientName $ thingConfig $ thingProperties $ thingCertificatePem $ thingCertificateRotate $ fr-idm-managed-thing-custom-attrs ) X-ORIGIN 'OpenAM' )
EOF