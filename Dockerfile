FROM golang:1.14-alpine AS builder

WORKDIR /
ADD go.* *.go /
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o tlser

FROM scratch
COPY --from=builder /tlser /
ENTRYPOINT ["/tlser"]
