FROM golang:1.14-buster

WORKDIR /root/thing

# Create and install the cert
RUN git clone https://github.com/FiloSottile/mkcert && cd mkcert && go build -ldflags "-X main.Version=$(git describe --tags)"
RUN cd mkcert && ./mkcert "*.iam.example.com" && ./mkcert -install

# Get dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download
