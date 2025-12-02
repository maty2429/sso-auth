run:
	go run cmd/api/main.go

sqlc:
	sqlc generate

migrate-up:
	# Add migration command here if using a tool like migrate
	echo "Running migrations..."

test:
	go test ./...
