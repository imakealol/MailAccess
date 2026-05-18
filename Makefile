.PHONY: dev prod logs shell help

# MailAccess Docker Workflow Commands
# 
# Note for Production:
# This setup does not include Kubernetes, CI/CD pipelines, or SSL termination.
# For production deployments exposed to the internet, you MUST put a reverse proxy
# such as Nginx, Caddy, or Traefik in front of the application to handle SSL/TLS
# termination.

# Load environment variables to detect POSTGRES_ENABLED
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Determine if we should activate the postgres profile
ifeq ($(POSTGRES_ENABLED),true)
    COMPOSE_PROFILES := --profile postgres
else
    COMPOSE_PROFILES :=
endif

help:
	@echo "Available commands:"
	@echo "  make dev    - Starts the development environment with hot-reload"
	@echo "  make prod   - Builds and starts the production-optimized environment"
	@echo "  make logs   - Tails logs for all running containers"
	@echo "  make shell  - Opens an interactive shell inside the backend container"

dev:
	docker compose $(COMPOSE_PROFILES) -f docker-compose.yml up --build

prod:
	@echo "Starting production environment. Ensure you have SSL termination configured upstream!"
	docker compose $(COMPOSE_PROFILES) -f docker-compose.prod.yml up --build -d

logs:
	docker compose logs -f

shell:
	docker compose exec backend /bin/bash || docker compose exec backend /bin/sh
