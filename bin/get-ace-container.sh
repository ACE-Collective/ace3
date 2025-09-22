#!/usr/bin/env bash

docker ps --filter "name=-ace" --format "{{.Names}}" | sort -V | head -n1