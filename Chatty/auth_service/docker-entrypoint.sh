#!/bin/bash
set -e


wait_for_db() {
  echo "Waiting for database at $DB_HOST:$DB_PORT..."
  while ! nc -z "$DB_HOST" "$DB_PORT"; do
    echo "Database is not ready yet..."
    sleep 1
  done
  echo "Database is ready!"
}


wait_for_rabbitmq() {
  echo "Waiting for RabbitMQ at $RABBITMQ_HOST:$RABBITMQ_PORT..."
  while ! nc -z "$RABBITMQ_HOST" "$RABBITMQ_PORT"; do
    echo "RabbitMQ is not ready yet..."
    sleep 1
  done
  echo "RabbitMQ is ready!"
}

wait_for_db
wait_for_rabbitmq

echo "Applying Alembic migrations..."
alembic upgrade head

echo "Starting AuthService..."
exec uvicorn main:app --host 0.0.0.0 --port 8003 --reload
