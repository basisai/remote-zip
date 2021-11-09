#!/bin/sh
set -euo pipefail

# Enable if desired
# yarn audit
yarn lint
yarn test:coverage
