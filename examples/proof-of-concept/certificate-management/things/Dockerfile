FROM golang:1.15-buster

WORKDIR /root/things

# Copy demo code
COPY cmd cmd
COPY go.mod .
COPY go.sum .

# Build the executable
RUN cd /root/things/cmd/cert-management && go install

WORKDIR /go/bin
COPY .secrets .

CMD ["cert-management"]
