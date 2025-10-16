FROM golang:1.25-bookworm

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0
CMD ["go", "test", "-v", "-tags", "integration", "./test/integration/tacacs"]
