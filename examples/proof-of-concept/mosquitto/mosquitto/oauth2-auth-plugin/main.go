package main

/*
#include <mosquitto.h>
#include <mosquitto_plugin.h>
typedef const struct mosquitto const_mosquitto;
typedef const struct mosquitto_acl_msg const_mosquitto_acl_msg;
typedef const char const_char;
*/
import "C"
import (
	"crypto/x509"
	"fmt"
	"github.com/ForgeRock/iot-edge/v7/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"log"
	"net/http"
	"net/url"
	"os"
	"unsafe"
)

var (
	logger *log.Logger
	file   *os.File = nil
)

//export mosquitto_auth_plugin_version
/*
 * Returns the value of MOSQ_AUTH_PLUGIN_VERSION defined in the mosquitto header file that the plugin was compiled
 * against.
 */
func mosquitto_auth_plugin_version() C.int {
	return C.MOSQ_AUTH_PLUGIN_VERSION
}

//export mosquitto_auth_plugin_init
/*
 * Initialises the plugin.
 */
func mosquitto_auth_plugin_init(cUserData *unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	var err error
	// copy opts from the C world into Go
	optMap := extractOptions(cOpts, cOptCount)

	// initialise logger
	if logger, file, err = initialiseLogger(optMap[optLogDest]); err != nil {
		fmt.Printf("error initialising logger, %s", err)
		return C.MOSQ_ERR_AUTH
	}
	logger.Println("Init plugin")

	// ForgeRock connection information
	thingID := "572ddcde-1532-4175-861b-0622ac2f3bf3"
	signer := secrets.Signer(thingID)
	certificate := []*x509.Certificate{secrets.Certificate(thingID, signer.Public())}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, _ := url.Parse(os.Getenv("AM_URL"))

	dynamicThing, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(thingID, "/", keyID, signer, nil).
		RegisterThing(certificate, nil).
		Create()
	logger.Printf("Created thing %v, %v", dynamicThing, err)

	// initialise the user data that will be used in subsequent plugin calls
	userData, err := initialiseUserData(optMap)
	if err != nil {
		logger.Println("initialiseUserData failed with err:", err)
		return C.MOSQ_ERR_AUTH
	}
	userData.t = dynamicThing
	*cUserData = unsafe.Pointer(&userData)

	logger.Println("leave - plugin init successful")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_plugin_cleanup
/*
 * Cleans up the plugin before the server shuts down.
 */
func mosquitto_auth_plugin_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	logger.Println("enter - plugin cleanup")
	// close logfile
	if file != nil {
		file.Sync()
		file.Close()
		file = nil
	}
	// set the client cache to nil so it can be garage collected
	clearUserData((*userData)(cUserData))

	logger.Println("leave - plugin cleanup")
	logger = nil
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_acl_check
/*
 * Checks whether a client is authorised to read from or write to a topic.
 */
func mosquitto_auth_acl_check(cUserData unsafe.Pointer, cAccess C.int, cClient *C.const_mosquitto, cMsg *C.const_mosquitto_acl_msg) C.int {
	logger.Println("enter - acl check")
	if cUserData == nil {
		logger.Println("Missing cUserData")
		return C.MOSQ_ERR_AUTH
	}

	access := access(cAccess)
	allow, err := authorise(http.DefaultClient, (*userData)(cUserData), access, unsafe.Pointer(cClient),
		C.GoString(cMsg.topic))
	if err != nil {
		logger.Printf("leave - acl check error, %s", err)
		return C.MOSQ_ERR_AUTH
	}
	if !allow {
		logger.Printf("leave - acl check %s denied", access)
		return C.MOSQ_ERR_PLUGIN_DEFER
	}
	logger.Printf("leave - acl check %s granted", access)
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_unpwd_check
/*
 * Authenticates the client by checking the supplied username and password.
 */
func mosquitto_auth_unpwd_check(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cUsername, cPassword *C.const_char) C.int {
	logger.Println("enter - unpwd check")
	if cUsername == nil || cPassword == nil {
		return C.MOSQ_ERR_AUTH
	}

	username := goStringFromConstant(cUsername)
	password := goStringFromConstant(cPassword)
	logger.Printf("u: %s, p: %s\n", username, password)

	data := (*userData)(cUserData)
	introspection, err := data.t.IntrospectAccessToken(password)
	logger.Printf("Introspection %v, %v", introspection, err)
	if err != nil {
		logger.Printf("leave - unpwd check error, %s", err)
		return C.MOSQ_ERR_AUTH
	}

	logger.Printf("leave - unpwd check successful, user authorised? %v", introspection.Active())
	if !introspection.Active() {
		return C.MOSQ_ERR_PLUGIN_DEFER
	}
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_init
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_init(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_cleanup
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_psk_key_get
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_psk_key_get(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cHint, cIdentity *C.const_char, cKey *C.char, cMaxKeyLen C.int) C.int {
	return C.MOSQ_ERR_SUCCESS
}

func main() {

}
