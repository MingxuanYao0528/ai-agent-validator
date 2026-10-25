#!/bin/bash
# PreToolUse hook: block executor dispatch unless the plan was approved
INPUT=$(cat)
AGENT=$(echo "$INPUT" | jq -r '.tool_input.subagent_type')
if [[ "$AGENT" == "executor" && ! -f approved.flag ]]; then
  echo "blocked: approved.flag missing"
  exit 1
fi
exit 0
