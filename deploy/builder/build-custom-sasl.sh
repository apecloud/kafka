#!/bin/bash
# Build script for custom SASL handler

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$PROJECT_DIR/deploy/target"
OUTPUT_DIR="$PROJECT_DIR/deploy/output"
JAR_NAME="kafka-custom-sasl-handler.jar"

echo "PROJECT_DIR: $PROJECT_DIR, OUTPUT_DIR: $OUTPUT_DIR"
echo "Building custom SASL handler..."

# Clean and create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Compile the Java file
cd "$PROJECT_DIR"
./gradlew :clients:compileJava --no-daemon

# Copy the compiled class file to output directory
CLASS_FILE="$PROJECT_DIR/clients/build/classes/java/main/org/apache/kafka/common/security/plain/internals/DynamicPlainServerCallbackHandler.class"

if [ ! -f "$CLASS_FILE" ]; then
    echo "Error: Compiled class file not found at $CLASS_FILE"
    exit 1
fi

# Create JAR structure
mkdir -p "$TARGET_DIR/org/apache/kafka/common/security/plain/internals/"
cp "$CLASS_FILE" "$TARGET_DIR/org/apache/kafka/common/security/plain/internals/"

# Create JAR file
cd "$TARGET_DIR"
jar cf "$JAR_NAME" org/

# Move JAR to project root
mv "$JAR_NAME" "$OUTPUT_DIR/"

echo "✅ Successfully created $JAR_NAME"
echo "📦 JAR location: $OUTPUT_DIR/$JAR_NAME"
echo ""
echo "Deployment instructions:"
echo "1. add to Dockerfile:"
echo "   COPY $JAR_NAME /opt/bitnami/kafka/libs/"

