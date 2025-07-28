#!/bin/bash

# Mobile Security Test Runner
echo "🧪 Starting Mobile Security Tests"
echo "================================="

# Check if device is connected
if ! adb devices | grep -q "device$"; then
    echo "❌ No device connected. Please connect a device or start an emulator."
    exit 1
fi

# Set environment
export NODE_ENV=test
export TEST_ENVIRONMENT=${TEST_ENVIRONMENT:-development}

# Run security tests
echo "🔒 Running security tests..."
npm run test:security

# Run integration tests
echo "🔗 Running integration tests..."
npm run test:integration

echo "✅ Test run completed"
