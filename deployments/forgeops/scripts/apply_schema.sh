#
# Copyright 2022 ForgeRock AS
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
dn: ou=things,ou=identities
objectClass: top
objectClass: organizationalUnit

dn: cn=schema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.20 NAME 'thingType' DESC 'Type of a thing (e.g. device, service or iec)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.21 NAME 'thingKeys' DESC 'JWKS containing the various keys used by things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.22 NAME 'thingOAuth2ClientName' DESC 'OAuth 2.0 client associated with the thing' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.23 NAME 'thingConfig' DESC 'Configuration for things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.24 NAME 'thingProperties' DESC 'Properties of things' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.25 NAME 'fr-idm-managed-thing-custom-attrs' EQUALITY caseIgnoreJsonQueryMatch SYNTAX 1.3.6.1.4.1.36733.2.1.3.1 SINGLE-VALUE X-STABILITY 'Internal' X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.900 NAME 'oauth-client-defaultAcrValues' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.901 NAME 'oauth-client-userinfoSignedResponseAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.902 NAME 'oauth-client-userinfoEncryptedResponseAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.903 NAME 'oauth-client-tokenIntrospectionResponseFormat' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.904 NAME 'oauth-client-contacts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.905 NAME 'oauth-client-authorizationResponseEncryptionMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.906 NAME 'oauth-client-requestParameterEncryptedEncryptionAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.907 NAME 'oauth-client-RedirectUriValidator' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.908 NAME 'oauth-client-oidcClaimsScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.909 NAME 'oauth-client-logoUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.910 NAME 'oauth-client-jwtTokenLifetime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.911 NAME 'oauth-client-backchannel-logout-session-required' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.912 NAME 'oauth-client-clientsCanSkipConsent' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.913 NAME 'oauth-client-overrideableOIDCClaims' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.914 NAME 'oauth-client-jwksCacheTimeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.915 NAME 'oauth-client-mTLSSubjectDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.916 NAME 'oauth-client-authorizationCodeLifetime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.917 NAME 'oauth-client-scopes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.918 NAME 'oauth-client-URLValidator' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.919 NAME 'oauth-client-tokenIntrospectionEncryptedResponseEncryptionAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.920 NAME 'oauth-client-status' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.921 NAME 'oauth-client-RequiredValueValidator' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.922 NAME 'oauth-client-requestParameterSignedAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.923 NAME 'oauth-client-usePolicyEngineForScope' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.924 NAME 'oauth-client-descriptions' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.925 NAME 'oauth-client-evaluateScopeScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.926 NAME 'oauth-client-accessTokenModificationPluginType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.927 NAME 'oauth-client-isConsentImplied' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.928 NAME 'oauth-client-claimsRedirectionUris' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.929 NAME 'oauth-client-idTokenEncryptionAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.930 NAME 'oauth-client-oidcClaimsPluginType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.931 NAME 'oauth-client-authorizeEndpointDataProviderScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.932 NAME 'oauth-client-name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.933 NAME 'oauth-client-authorizationResponseSigningAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.934 NAME 'oauth-client-requestUris' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.935 NAME 'oauth-client-grantTypes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.937 NAME 'oauth-client-defaultMaxAge' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.938 NAME 'oauth-client-jwkStoreCacheMissCacheTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.939 NAME 'oauth-client-refreshTokenLifetime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.940 NAME 'oauth-client-softwareVersion' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.941 NAME 'oauth-client-clientUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.942 NAME 'oauth-client-updateAccessToken' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.943 NAME 'oauth-client-jwkSet' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.944 NAME 'oauth-client-tokenIntrospectionSignedResponseAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.945 NAME 'oauth-client-tokenEndpointAuthSigningAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.946 NAME 'oauth-client-agentgroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.947 NAME 'oauth-client-accessTokenModificationScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.948 NAME 'oauth-client-redirectionUris' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.949 NAME 'oauth-client-responseTypes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.950 NAME 'oauth-client-tokenEndpointAuthMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.951 NAME 'oauth-client-idTokenSignedResponseAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.952 NAME 'oauth-client-defaultScopes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.953 NAME 'oauth-client-subjectType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.954 NAME 'oauth-client-clientSessionUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.955 NAME 'oauth-client-providerOverridesEnabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.956 NAME 'oauth-client-idTokenPublicEncryptionKey' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.957 NAME 'oauth-client-userinfoEncryptedResponseEncryptionAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.958 NAME 'oauth-client-require-pushed-authorization-requests' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.959 NAME 'oauth-client-tokenEncryptionEnabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.960 NAME 'oauth-client-loopbackInterfaceRedirection' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.961 NAME 'oauth-client-authorizationResponseEncryptionAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.962 NAME 'oauth-client-clientJwtPublicKey' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.963 NAME 'oauth-client-mTLSCertificateBoundAccessTokens' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.964 NAME 'oauth-client-accessTokenLifetime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.965 NAME 'oauth-client-mixUpMitigation' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.966 NAME 'oauth-client-oidcMayActScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.967 NAME 'oauth-client-authorizeEndpointDataProviderPluginType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.968 NAME 'oauth-client-sectorIdentifierUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.969 NAME 'oauth-client-publicKeyLocation' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.970 NAME 'oauth-client-customProperties' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.971 NAME 'oauth-client-postLogoutRedirectUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.972 NAME 'oauth-client-accessTokenMayActScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.973 NAME 'oauth-client-evaluateScopePluginType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.974 NAME 'oauth-client-clientType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.975 NAME 'oauth-client-javascriptOrigins' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.976 NAME 'oauth-client-claims' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.977 NAME 'oauth-client-defaultMaxAgeEnabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.978 NAME 'oauth-client-requestParameterEncryptedAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.979 NAME 'oauth-client-softwareIdentity' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.980 NAME 'oauth-client-statelessTokensEnabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.981 NAME 'oauth-client-tosURI' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.982 NAME 'oauth-client-GracePeriodValidator' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.983 NAME 'oauth-client-scopesPolicySet' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.984 NAME 'oauth-client-evaluateScopeClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.985 NAME 'oauth-client-validateScopeScript' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.986 NAME 'oauth-client-validateScopeClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.987 NAME 'oauth-client-accessTokenModifierClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.988 NAME 'oauth-client-oidcClaimsClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.989 NAME 'oauth-client-enableRemoteConsent' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.990 NAME 'oauth-client-idTokenEncryptionEnabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.991 NAME 'oauth-client-userinfoResponseFormat' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.992 NAME 'oauth-client-tokenIntrospectionEncryptedResponseAlg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.993 NAME 'oauth-client-backchannel-logout-uri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.994 NAME 'oauth-client-customLoginUrlTemplate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.995 NAME 'oauth-client-authorizeEndpointDataProviderClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.996 NAME 'oauth-client-tokenExchangeAuthLevel' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.997 NAME 'oauth-client-idTokenEncryptionMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.998 NAME 'oauth-client-mTLSTrustedCert' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.999 NAME 'oauth-client-remoteConsentServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1000 NAME 'oauth-client-clientName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1001 NAME 'oauth-client-issueRefreshToken' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1002 NAME 'oauth-client-issueRefreshTokenOnRefreshedToken' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1003 NAME 'oauth-client-validateScopePluginType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1004 NAME 'oauth-client-jwksUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1005 NAME 'oauth-client-refreshTokenGracePeriod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.1006 NAME 'oauth-client-policyUri' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )
-
add: objectClasses
objectClasses: ( 1.3.6.1.4.1.36733.2.2.2.20 NAME 'fr-iot' DESC 'Auxiliary class for ForgeRock IoT Identity attributes'
 SUP top STRUCTURAL MAY ( thingType $ thingKeys $ thingOAuth2ClientName $ thingConfig $ thingProperties $ fr-idm-managed-thing-custom-attrs $ oauth-client-validateScopePluginType $ oauth-client-clientName $ oauth-client-issueRefreshToken $ oauth-client-issueRefreshTokenOnRefreshedToken $ oauth-client-policyUri $ oauth-client-jwksUri $ oauth-client-refreshTokenGracePeriod $ oauth-client-contacts $ oauth-client-defaultAcrValues $ oauth-client-userinfoSignedResponseAlg $ oauth-client-userinfoEncryptedResponseAlg $ oauth-client-tokenIntrospectionResponseFormat $ oauth-client-logoUri $ oauth-client-authorizationResponseEncryptionMethod $ oauth-client-requestParameterEncryptedEncryptionAlgorithm $ oauth-client-RedirectUriValidator $ oauth-client-oidcClaimsScript $ oauth-client-jwksCacheTimeout $ oauth-client-jwtTokenLifetime $ oauth-client-backchannel-logout-session-required $ oauth-client-clientsCanSkipConsent $ oauth-client-overrideableOIDCClaims $ oauth-client-scopes $ oauth-client-mTLSSubjectDN $ oauth-client-authorizationCodeLifetime $ oauth-client-tokenIntrospectionEncryptedResponseEncryptionAlgorithm $ oauth-client-URLValidator $ oauth-client-usePolicyEngineForScope $ oauth-client-descriptions $ oauth-client-status $ oauth-client-RequiredValueValidator $ oauth-client-requestParameterSignedAlg $ oauth-client-accessTokenModificationPluginType $ oauth-client-evaluateScopeScript $ oauth-client-claimsRedirectionUris $ oauth-client-isConsentImplied $ oauth-client-name $ oauth-client-idTokenEncryptionAlgorithm $ oauth-client-oidcClaimsPluginType $ oauth-client-authorizeEndpointDataProviderScript $ oauth-client-authorizationResponseSigningAlgorithm $ userPassword $ oauth-client-requestUris $ oauth-client-grantTypes $ oauth-client-clientUri $ oauth-client-defaultMaxAge $ oauth-client-jwkStoreCacheMissCacheTime $ oauth-client-refreshTokenLifetime $ oauth-client-softwareVersion $ oauth-client-updateAccessToken $ oauth-client-jwkSet $ oauth-client-tokenIntrospectionSignedResponseAlg $ oauth-client-agentgroup $ oauth-client-tokenEndpointAuthSigningAlgorithm $ oauth-client-redirectionUris $ oauth-client-accessTokenModificationScript $ oauth-client-defaultScopes $ oauth-client-responseTypes $ oauth-client-tokenEndpointAuthMethod $ oauth-client-idTokenSignedResponseAlg $ oauth-client-subjectType $ oauth-client-idTokenPublicEncryptionKey $ oauth-client-clientSessionUri $ oauth-client-providerOverridesEnabled $ oauth-client-loopbackInterfaceRedirection $ oauth-client-userinfoEncryptedResponseEncryptionAlgorithm $ oauth-client-require-pushed-authorization-requests $ oauth-client-tokenEncryptionEnabled $ oauth-client-mixUpMitigation $ oauth-client-authorizationResponseEncryptionAlgorithm $ oauth-client-clientJwtPublicKey $ oauth-client-mTLSCertificateBoundAccessTokens $ oauth-client-accessTokenLifetime $ oauth-client-oidcMayActScript $ oauth-client-authorizeEndpointDataProviderPluginType $ oauth-client-sectorIdentifierUri $ oauth-client-publicKeyLocation $ oauth-client-customProperties $ oauth-client-postLogoutRedirectUri $ oauth-client-accessTokenMayActScript $ oauth-client-evaluateScopePluginType $ oauth-client-clientType $ oauth-client-javascriptOrigins $ oauth-client-statelessTokensEnabled $ oauth-client-claims $ oauth-client-defaultMaxAgeEnabled $ oauth-client-requestParameterEncryptedAlg $ oauth-client-softwareIdentity $ oauth-client-scopesPolicySet $ oauth-client-tosURI $ oauth-client-GracePeriodValidator $ oauth-client-accessTokenModifierClass $ oauth-client-evaluateScopeClass $ oauth-client-validateScopeScript $ oauth-client-validateScopeClass $ oauth-client-idTokenEncryptionEnabled $ oauth-client-oidcClaimsClass $ oauth-client-enableRemoteConsent $ oauth-client-userinfoResponseFormat $ oauth-client-tokenExchangeAuthLevel $ oauth-client-tokenIntrospectionEncryptedResponseAlg $ oauth-client-backchannel-logout-uri $ oauth-client-customLoginUrlTemplate $ oauth-client-authorizeEndpointDataProviderClass $ oauth-client-idTokenEncryptionMethod $ oauth-client-mTLSTrustedCert $ oauth-client-remoteConsentServiceId ) X-ORIGIN 'OpenAM' )
EOF