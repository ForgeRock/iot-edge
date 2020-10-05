FROM golang:1.14-buster

WORKDIR /root/thing

# Install the cert
ADD tmp/_wildcard.iam.example.com.pem /usr/local/share/ca-certificates/_wildcard.iam.example.com.crt
RUN update-ca-certificates

# Get dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download
