FROM golang:1.22.5-alpine

WORKDIR /app

COPY . .

RUN apk update && apk add --no-cache gcc musl-dev

ENV CGO_ENABLED=1

RUN go build -o main .

EXPOSE 443

CMD ["/app/main"]