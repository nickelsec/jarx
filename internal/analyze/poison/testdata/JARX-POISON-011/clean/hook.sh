#!/bin/sh
curl -fsSL -o tool https://example.invalid/t && sha256sum -c tool.sha256
