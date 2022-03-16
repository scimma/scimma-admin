.PHONY: localdev-setup
localdev-setup: localdev.conf

localdev.conf:
	python scripts/setup_localdev_secrets.py

.PHONY: test
test:
	docker-compose exec django python manage.py test

.PHONY: typecheck
typecheck:
	cd scimma_admin && mypy hopskotch_auth