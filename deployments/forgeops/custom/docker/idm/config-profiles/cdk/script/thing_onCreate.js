
var request = {
    'url': 'http://am/am/oauth2/realms/root/thing/register',
    'method': 'POST',
    'headers': {
        'Content-Type': 'application/json'
    },
    'body': '\
        { \
            "grant_types" : [ "client_credentials" ], \
            "response_types" : [ "token" ], \
            "jwks" : { \
                "keys" : [ { \
                    "alg" : "ES256", \
                    "crv" : "P-256", \
                    "kid" : "dYhQA7Fj9A8y1HuniPijRZ296DQIs5LngnqCrDP940k=", \
                    "kty" : "EC", \
                    "use" : "sig", \
                    "x" : "-xoqUAGTqF3jh6QQmbbBSmnvefXVTjWS4n4i1s_qdzI", \
                    "y" : "DQHn2b7wBVbC815dmbnlKq_eIqOq2v1Gh-vhc-1Grwc" \
                } ] \
            }, \
            "redirect_uris" : [ "https://client.example.com:8443/callback" ], \
            "scope": "write", \
            "client_id": "' + object._id + '" \
        }'
};

try {
    logger.debug('OnCreate OAuth 2.0 dynamic client registration request: {}', request);
    var result = openidm.action('external/rest', 'call', request);
    logger.debug('OnCreate API call response: {}', result);

    // var resultJson = JSON.parse(result);
    // object.put("clientId", resultJson.client_id);
    // var clientAccessToken = resultJson.registration_access_token;

} catch (e) {
    logger.error('OnCreate OAuth 2.0 dynamic client registration error detail: {}', e);
}