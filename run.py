"""
run.py - Application entry point.
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5055))
    debug = os.getenv("FLASK_ENV", "development") == "development"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║            🔐  API Vault  v1.0.0                         ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard :  http://localhost:{port}/                     ║
║  API Docs  :  http://localhost:{port}/apidocs              ║
║  Health    :  http://localhost:{port}/api/v1/admin/health  ║
╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=debug)
