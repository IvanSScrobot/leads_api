#!/bin/bash

# Run Ardent Intake API tests in TEST MODE
# This allows tests to run without PostgreSQL database

echo "Starting Ardent Intake API in TEST MODE..."
echo "================================================"

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "Installing dependencies..."
    venv/bin/pip install -q -r requirements.txt
    venv/bin/pip install -q -r requirements_dev.txt
fi

# Activate virtual environment
source venv/bin/activate

# Set test mode environment variable
export TEST_MODE=true

# Start the server in the background
echo "Starting server..."
venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ ERROR: Server failed to start"
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"
echo ""

# Run tests
echo "Running tests..."
echo "================================================"
venv/bin/pytest tests

# Store test exit code
TEST_EXIT_CODE=$?

# Kill the server
echo ""
echo "================================================"
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "✅ Server stopped"
echo ""

# Deactivate virtual environment
deactivate

# Exit with test result
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All tests completed"
else
    echo "⚠️  Some tests failed"
fi

exit $TEST_EXIT_CODE
