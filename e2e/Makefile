.PHONY: e2e-build e2e-up e2e-down e2e-test e2e-logs e2e-clean

e2e-build:
	docker-compose -f docker-compose.yaml build

e2e-up:
	docker-compose -f docker-compose.yaml up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Services started. Run 'make e2e-test' to run E2E tests."

e2e-down:
	docker-compose -f docker-compose.yaml down -v --remove-orphans

e2e-logs:
	docker-compose -f docker-compose.yaml logs -f

e2e-test:
	go test -v -tags e2e -timeout 120s ./e2e/

e2e-clean:
	docker-compose -f docker-compose.yaml down -v --remove-orphans
	rm -rf docker/step-ca docker/secrets docker/sshd
	mkdir -p docker/step-ca docker/secrets docker/sshd

e2e-status:
	docker-compose -f docker-compose.yaml ps

help:
	@echo "E2E test targets:"
	@echo "  e2e-build   - Build Docker images"
	@echo "  e2e-up      - Start Docker services (keycloak, step-ca, sshd)"
	@echo "  e2e-down    - Stop and remove Docker services"
	@echo "  e2e-logs    - Follow Docker logs"
	@echo "  e2e-test    - Run E2E tests"
	@echo "  e2e-clean   - Clean up Docker volumes and temp files"
	@echo "  e2e-status  - Show Docker service status"
	@echo ""
	@echo "Prerequisites:"
	@echo "  1. Copy e2e/testenv.json.example to e2e/testenv.json and fill values"
	@echo "  2. Run 'make e2e-up' to start services"
	@echo "  3. Run 'make e2e-test' to run tests"
