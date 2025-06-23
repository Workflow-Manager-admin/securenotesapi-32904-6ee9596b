#!/bin/bash
cd /home/kavia/workspace/code-generation/securenotesapi-32904-6ee9596b/notes_api_backend_workspace/notes_api_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

