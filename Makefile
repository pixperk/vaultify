# Variables
DB_URL ?= postgres://vaultify:vaultify@localhost:5432/vaultify?sslmode=disable
MIGRATIONS_DIR := internal/db/migrations
MIGRATE := migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)"

#sqlc-generate: Generate SQL queries and models
sqlc:
	sqlc generate

# Create new migration (usage: make migrate-create name=create_users_table)
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $$name

# Run migrations
migrate-up:
	$(MIGRATE) up

# Rollback last migration
migrate-down:
	$(MIGRATE) down 1

# Reset DB (dangerous in prod)
migrate-drop:
	$(MIGRATE) drop -f

# Show current migration version
migrate-version:
	$(MIGRATE) version

# Force set migration version (careful)
migrate-force:
	@read -p "Enter version to force: " version; \
	$(MIGRATE) force $$version


# Run the app (adjust as needed)
run:
	go run cmd/server/main.go

.PHONY: migrate-create migrate-up migrate-down migrate-drop migrate-version migrate-force run sqlc
