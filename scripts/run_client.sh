#!/bin/bash

k6 run hosts/client.js --insecure-skip-tls-verify
