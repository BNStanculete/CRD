#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Too few / too many arguments provided."
    echo "Usage: run_adversary.sh --timeout [SECONDS]"
    exit 1
elif [[ ! "$1" == "--timeout" ]]; then
    echo "Invalid argument: $1"
    echo "Usage: run_adversary.sh --timeout [SECONDS]"
    exit 1
fi

./hosts/Adversary/main &
pid=$!

echo "Adversary script started with PID: $pid"
echo "Waiting for timeout..."
sleep $2

echo "Stopped adversary script."
kill $pid
