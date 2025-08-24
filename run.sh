#!/bin/bash

# Apply database migrations
flask db upgrade

# Start the Gunicorn server
gunicorn --bind 0.0.0.0:7860 app:app