build:
	@docker build -t jmorenoamor/api-connect-code-quality-action:latest .

test:
	@docker run --rm jmorenoamor/api-connect-code-quality-action
