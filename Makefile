# Makefile

# Configurable variables
BINARY_NAME := prompt_agent_shield
LOG_DIR := logs
DATE_FMT := %d%b%Y_%H%M
TS := $(shell date +"$(DATE_FMT)" | tr '[:upper:]' '[:lower:]')

# Ensure logs directory exists
$(LOG_DIR):
	@mkdir -p $(LOG_DIR)

.PHONY: run-agent
run-agent: $(LOG_DIR)
	echo ">> Running $(BINARY_NAME)" && \
	nohup uv run python -m $(BINARY_NAME) > /dev/null 2>&1 &

.PHONY: run-agent-logs
run-agent-logs: $(LOG_DIR)
	@LOG_FILE="$(LOG_DIR)/agent_logs_$(TS).log" && \
	echo ">> Running $(BINARY_NAME)" && \
	echo ">> Logging to $${LOG_FILE}" && \
	nohup uv run python -m $(BINARY_NAME) > "$${LOG_FILE}" 2>&1 &

.PHONY: run-agent-terminal
run-agent-terminal: $(LOG_DIR)
	@LOG_FILE="$(LOG_DIR)/agent_logs_$(TS).log" && \
	echo ">> Running $(BINARY_NAME)" && \
	uv run python -m $(BINARY_NAME) &

.PHONY: show
show:
	@echo ">> Showing all $(BINARY_NAME) processes"
	@pgrep -af $(BINARY_NAME)

.PHONY: kill-all
kill-all:
	@echo ">> Killing all $(BINARY_NAME) processes"
	@pkill -f $(BINARY_NAME)
	@echo ">> All $(BINARY_NAME) processes killed"

