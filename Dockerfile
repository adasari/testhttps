FROM golang:alpine AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=1

WORKDIR /testhttps

COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code necessary to build the application
# You may want to change this to copy only what you actually need.
COPY . .

# Build the binary.

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /go/bin/testhttps
#RUN go build -o /go/bin/app

FROM scratch
COPY --from=builder /go/bin/testhttps /
EXPOSE 9090
EXPOSE 8080
ENTRYPOINT ["/testhttps"]