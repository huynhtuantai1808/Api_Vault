#!/bin/bash
# setup.sh - Quick setup script for API Vault
set -e

echo "============================================"
echo "  API Vault - Setup Script"
echo "============================================"

# Check .env exists
if [ ! -f ".env" ]; then
  echo "[1/5] Creating .env from .env.example..."
  cp .env.example .env
  echo "      ⚠️  Edit .env with your Vault credentials before proceeding!"
  echo "      Press Enter to continue after editing .env, or Ctrl+C to abort."
  read -r
fi

# Install dependencies
echo "[2/5] Installing Python dependencies..."
source venv/bin/activate
pip install -r requirements.txt -q

# Initialize Flask-Migrate
echo "[3/5] Setting up database migrations..."
if [ ! -d "migrations/versions" ]; then
  mkdir -p migrations/versions
  flask db init 2>/dev/null || true
fi

flask db migrate -m "initial schema" 2>/dev/null || echo "      (Migration already exists)"
flask db upgrade

echo "[4/5] Database ready."

echo "[5/5] Done! Starting API Vault..."
echo ""
echo "  Dashboard : http://localhost:5055/"
echo "  API Docs  : http://localhost:5055/apidocs"
echo "  Health    : http://localhost:5055/api/v1/admin/health"
echo ""
echo "  Default login: admin / Admin@123456"
echo ""
python run.py >> /home/taiht/logs/api.log
