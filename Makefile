MAIN_FILE=cmd/app/main.go
PROTO_FILE=./internal/server/api/netvuln.proto
PORT=8080

run:
	go run $(MAIN_FILE)

generate:
	protoc -I . --go_out=plugins=grpc:. $(PROTO_FILE)

evans:
	evans $(PROTO_FILE) -p $(PORT)

.PHONY: run generate evans start-docker