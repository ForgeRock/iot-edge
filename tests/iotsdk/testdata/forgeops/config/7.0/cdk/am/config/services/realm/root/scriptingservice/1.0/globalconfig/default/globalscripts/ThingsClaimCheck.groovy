/*
  - Data made available by nodes that have already executed are available in the sharedState variable.
  - The script should set outcome to either "true" or "false".
 */

outcome = "true"

def verifiedClaims = transientState.get("org.forgerock.am.iot.jwt.pop.verified_claims")

if ( verifiedClaims = null || verifiedClaims.get("life_universe_everything") != "42") {
    logger.error("Custom claim 'life_universe_everything' not correct")
    outcome = "false"
}