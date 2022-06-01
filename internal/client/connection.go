/*
 * Copyright 2020-2022 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"gopkg.in/square/go-jose.v2"
)

type ContentType string

const (
	ApplicationJSON ContentType = "application/json"
	ApplicationJOSE ContentType = "application/jose"
)

var (
	// Success response codes
	// https://tools.ietf.org/html/rfc7252#section-5.9.1
	CodeCreated = ResponseCode{
		HTTP:    http.StatusCreated,
		CoAP:    codes.Created,
		Name:    "created",
		Success: true,
	}
	CodeDeleted = ResponseCode{
		HTTP:    http.StatusNoContent,
		CoAP:    codes.Deleted,
		Name:    "deleted",
		Success: true,
	}
	CodeValid = ResponseCode{
		HTTP:    http.StatusNotModified,
		CoAP:    codes.Valid,
		Name:    "valid",
		Success: true,
	}
	CodeChanged = ResponseCode{
		HTTP:    http.StatusNoContent,
		CoAP:    codes.Changed,
		Name:    "changed",
		Success: true,
	}
	CodeContent = ResponseCode{
		HTTP:    http.StatusOK,
		CoAP:    codes.Content,
		Name:    "content",
		Success: true,
	}
	// Client error codes
	// https://tools.ietf.org/html/rfc7252#section-5.9.2
	CodeBadRequest = ResponseCode{
		HTTP:    http.StatusBadRequest,
		CoAP:    codes.BadRequest,
		Name:    "bad request",
		Success: false,
	}
	CodeUnauthorized = ResponseCode{
		HTTP:    http.StatusUnauthorized,
		CoAP:    codes.Unauthorized,
		Name:    "unauthorized",
		Success: false,
	}
	CodeBadOption = ResponseCode{
		HTTP:    0, // no mapping
		CoAP:    codes.BadOption,
		Name:    "bad option",
		Success: false,
	}
	CodeForbidden = ResponseCode{
		HTTP:    http.StatusForbidden,
		CoAP:    codes.Forbidden,
		Name:    "forbidden",
		Success: false,
	}
	CodeNotFound = ResponseCode{
		HTTP:    http.StatusNotFound,
		CoAP:    codes.NotFound,
		Name:    "not found",
		Success: false,
	}
	CodeMethodNotAllowed = ResponseCode{
		HTTP:    http.StatusMethodNotAllowed,
		CoAP:    codes.MethodNotAllowed,
		Name:    "method not allowed",
		Success: false,
	}
	CodeNotAcceptable = ResponseCode{
		HTTP:    http.StatusNotAcceptable,
		CoAP:    codes.NotAcceptable,
		Name:    "not acceptable",
		Success: false,
	}
	CodePreconditionFailed = ResponseCode{
		HTTP:    http.StatusPreconditionFailed,
		CoAP:    codes.PreconditionFailed,
		Name:    "precondition failed",
		Success: false,
	}
	CodeRequestEntityTooLarge = ResponseCode{
		HTTP:    http.StatusRequestEntityTooLarge,
		CoAP:    codes.RequestEntityTooLarge,
		Name:    "request entity too large",
		Success: false,
	}
	CodeUnsupportedContentFormat = ResponseCode{
		HTTP:    http.StatusUnsupportedMediaType,
		CoAP:    codes.UnsupportedMediaType,
		Name:    "unsupported content format",
		Success: false,
	}
	// Server error codes
	// https://tools.ietf.org/html/rfc7252#section-5.9.3
	CodeInternalServerError = ResponseCode{
		HTTP:    http.StatusInternalServerError,
		CoAP:    codes.InternalServerError,
		Name:    "internal server error",
		Success: false,
	}
	CodeNotImplemented = ResponseCode{
		HTTP:    http.StatusNotImplemented,
		CoAP:    codes.NotImplemented,
		Name:    "not implemented",
		Success: false,
	}
	CodeBadGateway = ResponseCode{
		HTTP:    http.StatusBadGateway,
		CoAP:    codes.BadGateway,
		Name:    "bad gateway",
		Success: false,
	}
	CodeServiceUnavailable = ResponseCode{
		HTTP:    http.StatusServiceUnavailable,
		CoAP:    codes.ServiceUnavailable,
		Name:    "service unavailable",
		Success: false,
	}
	CodeGatewayTimeout = ResponseCode{
		HTTP:    http.StatusGatewayTimeout,
		CoAP:    codes.GatewayTimeout,
		Name:    "gateway timeout",
		Success: false,
	}
	CodeProxyingNotSupported = ResponseCode{
		HTTP:    0, // no mapping
		CoAP:    codes.ProxyingNotSupported,
		Name:    "proxying not supported",
		Success: false,
	}
)

// ResponseCodes list all the mapped response codes
var ResponseCodes = []ResponseCode{
	CodeCreated,
	CodeDeleted,
	CodeValid,
	CodeChanged,
	CodeContent,
	CodeBadRequest,
	CodeUnauthorized,
	CodeBadOption,
	CodeForbidden,
	CodeNotFound,
	CodeMethodNotAllowed,
	CodeNotAcceptable,
	CodePreconditionFailed,
	CodeRequestEntityTooLarge,
	CodeUnsupportedContentFormat,
	CodeInternalServerError,
	CodeNotImplemented,
	CodeBadGateway,
	CodeServiceUnavailable,
	CodeGatewayTimeout,
	CodeProxyingNotSupported,
}

// ResponseCode is used to relay the outcome of HTTP/CoAP requests made to AM/Gateway
type ResponseCode struct {
	HTTP    int
	CoAP    codes.Code
	Name    string
	Success bool
}

// IsWrappedIn will check if the given error is a ResponseError and if it wraps this ResponseCode
func (r ResponseCode) IsWrappedIn(err error) bool {
	if respErr, ok := err.(ResponseError); ok {
		return r == respErr.ResponseCode
	}
	return false
}

// ResponseError is used to wrap a ResponseCode into an error
type ResponseError struct {
	ResponseCode
	Message string
}

// Error ensures the error interface is implemented for ResponseError
func (r ResponseError) Error() string {
	if r.Message != "" {
		return r.Message
	}
	return r.Name
}

// Connection to the ForgeRock platform
type Connection interface {
	// Initialise the client. Must be called before the Client is used by a Thing
	Initialise() error

	// Authenticate sends an authenticate request to the ForgeRock platform
	Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error)

	// AMInfo returns the information required to construct valid signed JWTs
	AMInfo() (info AMInfoResponse, err error)

	// ValidateSession sends a validate session request
	ValidateSession(tokenID string, content ContentType, payload string) (ok bool, err error)

	// LogoutSession makes a request to logout the session
	LogoutSession(tokenID string, content ContentType, payload string) (err error)

	// AccessToken makes an access token request with the given session token and payload
	AccessToken(tokenID string, content ContentType, payload string) (reply []byte, err error)

	// IntrospectAccessToken makes a request to introspect an access token
	IntrospectAccessToken(tokenID string, content ContentType, payload string) (introspection []byte, err error)

	// Attributes makes a thing attributes request with the given session token and payload
	Attributes(tokenID string, content ContentType, payload string, names []string) (reply []byte, err error)

	// UserCode makes a user code request with the given session token and payload
	UserCode(tokenID string, content ContentType, payload string) (reply []byte, err error)

	// UserToken makes a user token request with the given session token and payload
	UserToken(tokenID string, content ContentType, payload string) (reply []byte, err error)
}

type ConnectionBuilder struct {
	url     *url.URL
	realm   string
	tree    string
	key     crypto.Signer
	timeout time.Duration
}

func NewConnection() *ConnectionBuilder {
	return &ConnectionBuilder{}
}

func (b *ConnectionBuilder) ConnectTo(url *url.URL) *ConnectionBuilder {
	b.url = url
	return b
}

func (b *ConnectionBuilder) InRealm(realm string) *ConnectionBuilder {
	b.realm = realm
	return b
}

func (b *ConnectionBuilder) WithTree(tree string) *ConnectionBuilder {
	b.tree = tree
	return b
}

func (b *ConnectionBuilder) WithKey(key crypto.Signer) *ConnectionBuilder {
	b.key = key
	return b
}

func (b *ConnectionBuilder) TimeoutRequestAfter(timeout time.Duration) *ConnectionBuilder {
	b.timeout = timeout
	return b
}

// amConnection contains information for connecting directly to AM
type amConnection struct {
	http.Client
	baseURL         string
	realm           string
	authTree        string
	cookieName      string
	accessTokenJWKS jose.JSONWebKeySet
}

// gatewayConnection contains information for connecting to the IoT Gateway via COAP
type gatewayConnection struct {
	address string
	timeout time.Duration
	key     crypto.Signer
	client  *coap.Client
	conn    *coap.ClientConn
}

func (b *ConnectionBuilder) Create() (Connection, error) {
	var connection Connection
	switch b.url.Scheme {
	case "http", "https":
		connection = &amConnection{baseURL: b.url.String(), realm: b.realm, authTree: b.tree, Client: http.Client{
			Timeout: b.timeout,
		}}
	case "coap", "coaps":
		var err error
		if b.key == nil {
			b.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			return nil, err
		}
		connection = &gatewayConnection{address: b.url.Host, key: b.key, timeout: b.timeout}
	default:
		return nil, fmt.Errorf("unsupported scheme `%s`, must be one of http(s) or coap(s)", b.url.Scheme)
	}
	err := connection.Initialise()
	return connection, err
}
