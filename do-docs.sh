#!/bin/sh
set -euo pipefail

mkdir -p docs/api
yarn doc:gen
ls docs/api
