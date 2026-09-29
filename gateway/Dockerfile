FROM node:22-alpine AS portal
WORKDIR /portal
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 go build -trimpath -o /gateway ./cmd/gateway

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 gateway && mkdir /data && chown gateway:gateway /data
WORKDIR /app
COPY --from=backend /gateway /app/gateway
COPY --from=portal /portal/dist /app/web/dist
COPY --from=portal /client /app/client
USER gateway
EXPOSE 8080
ENTRYPOINT ["/app/gateway", "-config", "/app/config.json"]
