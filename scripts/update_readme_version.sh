#!/bin/sh

# Read the version from project/main.go
version=$(grep -oP 'const Version string = "\K[^"]+' project/main.go)

# Update the version in README.md
sed -i "s/0\.1\.[0-9]\+/$version/" README.md