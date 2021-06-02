FROM golang:1.15-buster

WORKDIR /root/things

# Install the cert
ADD tmp/_wildcard.iam.example.com.pem /usr/local/share/ca-certificates/_wildcard.iam.example.com.crt
RUN update-ca-certificates

# Copy demo code
COPY cmd cmd
COPY go.mod .
COPY go.sum .

# Build the executable
RUN cd /root/things/cmd/cert-management && go install

WORKDIR /go/bin
COPY .secrets .

CMD ["cert-management"]
