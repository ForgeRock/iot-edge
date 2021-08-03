/*
 * Copyright 2021 ForgeRock AS
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

package crypto

import (
	"encoding/pem"
	"testing"
)

var (
	// Generated using:
	// openssl ecparam -genkey -name prime256v1 -noout -out ec256PKCS1.pem
	ec256PEMPKCS1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM3RcTThVUlQ1U2TUig6xRn+brCI0IeHro3jmBOC740SoAoGCCqGSM49
AwEHoUQDQgAEa6nVv5ZcvU9xsnyLqMOdmgwu8ysL1+pyupveoFWw5ZuHikhgaEs9
lio9Yg931kOL2C2yaaass73uPYm7wtyWDA==
-----END EC PRIVATE KEY-----`

	// Generated using:
	// openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ec256PKCS1.pem -out ec256PKCS8.pem
	ec256PEMPKCS8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzdFxNOFVSVDVTZNS
KDrFGf5usIjQh4eujeOYE4LvjRKhRANCAARrqdW/lly9T3GyfIuow52aDC7zKwvX
6nK6m96gVbDlm4eKSGBoSz2WKj1iD3fWQ4vYLbJppqyzve49ibvC3JYM
-----END PRIVATE KEY-----`

	// Generated using:
	// openssl genrsa -out rsaPKCS1.pem
	rsaPEMPKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1OQQKJ6FXRy2LibN9n3NkFL4elZ61Trb2Sv/gxyCnQAapDZt
MfCJgv0YAnkWGNI3BqHYdT5/cebBYAFWOxQ5qtRQKt9xpSn5FZ/7LbpDaNEbOczN
gAdo8SfFOAQlci7fAmzX1ZmWvmhdnyAQXJzZYbEFBpIljKhGVg4QqDOwN7w+ivT4
/m+ihFLs3drgv2YCHLX2zW3+aE66W0rL7vwxy3cv/57qXgP8ZgMm+no0NDDKNH/8
OwgGyl8aENLNvNsA1nvYZhTaCVNrbrmkVaFdmQHdrtJJNiCp6Cv+Im2ofMphupWh
TJRkGPOSrPBBXHInAtcShNZJds0qmrj6yf7puwIDAQABAoIBAA7t/4QZudiRzuTl
q8QBhoz8hJhvwCV7/zb3su+K7E3+V9/0QSwjZkFdZnWl8DrFYz5/0yJFw8JFIIKP
FXEHNhQY15ZqHRosG1+83GyUh22uXG5tQmwcGOvwkhAfmlCroNAWufwszTmFMCuc
oAkeptAHDgcr8J4wnt4iFmD1XwJJfIoB9SZAwSxAlGQyfFDTuF1l5YGrJxde8yyQ
7rDqSJ9lBawMU3AOZhc/9VnkNnC213sAWTb6MTvDWqbtM8+izfia0VD5tWwoTU4C
kMECH/22A0se5VHjoCc0zkoPqwiUXIO5zctMNiMFSOsp41ejxzrJq5Ncutedjs3P
h5xj0SECgYEA7PoyhwHkwbY1EcQS4kqvsSlz7AtZB8It0Kr8spufFIDoy8mNqmXs
WO/6rUmXYN/JTu9pT8lAUFu1OAKgkbWArx5mi+9adSqQw4CVR4n1kyy2ze4kECoo
cKFkXm2pbfvwblBmPmVu/Q3POBNDTfY8JglqXuvhdjMychEdwkXiKB0CgYEA5frl
setH2LppkqWKeNAPJeMXGifdqohh1FOdAypQVDreUW+pc9xcz3vvQ+R9NYiw/tfs
xlO8HXsbmb2MwzkdZ5YsXPZyvaoVO/cPtfC3/TsqQO3Jml4hjR2CBrQ2Pg3rRLua
Bifesbmg52Luwr5EU324GZVf3tSgYQLnVwtiobcCgYEAjwzFPXwmI80iofPTVmix
P+d/A4kiGC3eTC07V3HbiJv8ay/i5W6bSmCq2LoouCC+u3iIANLCkP+bGBF17h87
a/qU+nnlB/9G3c0bz9B2vn3qZ8sOV/eq67pxBRN7iFniHCVKYvYGFpmkcfwmz8QJ
MQjT/jKzqg9jrzmn1iMrTv0CgYA8BxsBL5pXNYDs6AyWsCfkCbwz9YfkRSjT1Oc8
tkS1V5BDzVN7jF8lQQIYxIDyAjXArvd8ZMrLHyD7JgChzDyilw4JTcJxQv274ybU
pHpBvLmwrOBcTImRXcxcl5k45UUtcZIoXSvBU+RtwOL1LdiDumLdOqIFdZZO/AUK
MUyTTQKBgQDVNgElIZ8cqAod0mRjYI4jiIWgCPw1GvYy6fYmziq2iXw8QbwYwTTf
9CtJ+W/RsEHvsnJvhSjXx6NhSONhxflM38nQ0gMKAHrGoA5bZwPm32OwhuCyOVBe
3pS4Iixt1kh8jZlJ8kI2oxRjUqP+qLaNnSiJdiudBcPgsoMo0y/aSA==
-----END RSA PRIVATE KEY-----`

	// Generated using:
	// openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsaPKCS1.pem -out rsaPKCS8.pem
	rsaPEMPKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU5BAonoVdHLYu
Js32fc2QUvh6VnrVOtvZK/+DHIKdABqkNm0x8ImC/RgCeRYY0jcGodh1Pn9x5sFg
AVY7FDmq1FAq33GlKfkVn/stukNo0Rs5zM2AB2jxJ8U4BCVyLt8CbNfVmZa+aF2f
IBBcnNlhsQUGkiWMqEZWDhCoM7A3vD6K9Pj+b6KEUuzd2uC/ZgIctfbNbf5oTrpb
Ssvu/DHLdy//nupeA/xmAyb6ejQ0MMo0f/w7CAbKXxoQ0s282wDWe9hmFNoJU2tu
uaRVoV2ZAd2u0kk2IKnoK/4ibah8ymG6laFMlGQY85Ks8EFccicC1xKE1kl2zSqa
uPrJ/um7AgMBAAECggEADu3/hBm52JHO5OWrxAGGjPyEmG/AJXv/Nvey74rsTf5X
3/RBLCNmQV1mdaXwOsVjPn/TIkXDwkUggo8VcQc2FBjXlmodGiwbX7zcbJSHba5c
bm1CbBwY6/CSEB+aUKug0Ba5/CzNOYUwK5ygCR6m0AcOByvwnjCe3iIWYPVfAkl8
igH1JkDBLECUZDJ8UNO4XWXlgasnF17zLJDusOpIn2UFrAxTcA5mFz/1WeQ2cLbX
ewBZNvoxO8Napu0zz6LN+JrRUPm1bChNTgKQwQIf/bYDSx7lUeOgJzTOSg+rCJRc
g7nNy0w2IwVI6ynjV6PHOsmrk1y6152Ozc+HnGPRIQKBgQDs+jKHAeTBtjURxBLi
Sq+xKXPsC1kHwi3Qqvyym58UgOjLyY2qZexY7/qtSZdg38lO72lPyUBQW7U4AqCR
tYCvHmaL71p1KpDDgJVHifWTLLbN7iQQKihwoWRebalt+/BuUGY+ZW79Dc84E0NN
9jwmCWpe6+F2MzJyER3CReIoHQKBgQDl+uWx60fYummSpYp40A8l4xcaJ92qiGHU
U50DKlBUOt5Rb6lz3FzPe+9D5H01iLD+1+zGU7wdexuZvYzDOR1nlixc9nK9qhU7
9w+18Lf9OypA7cmaXiGNHYIGtDY+DetEu5oGJ96xuaDnYu7CvkRTfbgZlV/e1KBh
AudXC2KhtwKBgQCPDMU9fCYjzSKh89NWaLE/538DiSIYLd5MLTtXcduIm/xrL+Ll
bptKYKrYuii4IL67eIgA0sKQ/5sYEXXuHztr+pT6eeUH/0bdzRvP0Ha+fepnyw5X
96rrunEFE3uIWeIcJUpi9gYWmaRx/CbPxAkxCNP+MrOqD2OvOafWIytO/QKBgDwH
GwEvmlc1gOzoDJawJ+QJvDP1h+RFKNPU5zy2RLVXkEPNU3uMXyVBAhjEgPICNcCu
93xkyssfIPsmAKHMPKKXDglNwnFC/bvjJtSkekG8ubCs4FxMiZFdzFyXmTjlRS1x
kihdK8FT5G3A4vUt2IO6Yt06ogV1lk78BQoxTJNNAoGBANU2ASUhnxyoCh3SZGNg
jiOIhaAI/DUa9jLp9ibOKraJfDxBvBjBNN/0K0n5b9GwQe+ycm+FKNfHo2FI42HF
+UzfydDSAwoAesagDltnA+bfY7CG4LI5UF7elLgiLG3WSHyNmUnyQjajFGNSo/6o
to2dKIl2K50Fw+CygyjTL9pI
-----END PRIVATE KEY-----`
)

func TestParsePEM(t *testing.T) {
	tests := []struct {
		name string
		pem  string
	}{
		{name: "ec256PEMPKCS1", pem: ec256PEMPKCS1},
		{name: "ec256PEMPKCS8", pem: ec256PEMPKCS8},
		{name: "rsaPEMPKCS1", pem: rsaPEMPKCS1},
		{name: "rsaPEMPKCS8", pem: rsaPEMPKCS8},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(subtest.pem))
			if block == nil {
				t.Fatal("failed to decode PEM block")
			}
			_, err := ParsePEM(block)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
