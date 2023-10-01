FROM golang:1.21.1-alpine3.18 as builder
WORKDIR /app

COPY go.* .
RUN go mod download
COPY . .

ARG version
ARG commitId
ENV version=${version}
ENV commitId=${commitId}

RUN go build -ldflags "-X crtforge/cmd.version=$version -X crtforge/cmd.commitId=$commitId" -o crtforge -v .

FROM alpine:3.18.4 as runner
RUN apk add openssl --no-cache
COPY --from=builder /app/crtforge /crtforge
ENTRYPOINT [ "/crtforge" ]

