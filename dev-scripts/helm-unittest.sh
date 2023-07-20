#!/bin/bash

cd $(dirname $0)/..
./scripts/package-helm
./scripts/test-helm
