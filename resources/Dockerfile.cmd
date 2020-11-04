FROM golang:1.14.5 as build
ENV CGO_ENABLED=0
ENV GOPATH=/go

WORKDIR /go/src/invoca/tenable-scan-launcher

COPY . .

RUN go mod download

RUN go build -mod=readonly -o /nmap-diff $PWD/cmd/nmap-diff

FROM debian:latest

COPY --from=build /nmap-diff /

RUN apt-get update && apt-get install nmap -y

ENTRYPOINT ["/nmap-diff"]
