FROM golang:alpine

RUN apk update && apk add build-base

WORKDIR /build
COPY glauth.go .
COPY go.mod .

RUN go mod tidy
RUN go build -o /bin/glauth -ldflags '-w -s' glauth.go

FROM alpine:latest

COPY --from=0 /bin/glauth /bin/glauth
CMD ["glauth", "-h"]
