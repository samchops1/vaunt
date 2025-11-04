#!/bin/bash

npm run dev &
FRONTEND_PID=$!

sleep 3
python server/app.py &
BACKEND_PID=$!

wait $FRONTEND_PID

kill $BACKEND_PID
