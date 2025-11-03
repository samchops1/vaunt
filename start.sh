#!/bin/bash

python server/app.py &
BACKEND_PID=$!

npm run dev

kill $BACKEND_PID
