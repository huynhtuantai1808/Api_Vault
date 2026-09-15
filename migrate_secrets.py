import os
import sys

# Ensure app context
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app import create_app
from app.utils.vault_client import VaultClient
from app.models.user import User

app = create_app()
with app.app_context():
    print("Starting Vault migration for user-isolated secrets...")
    
    # We will migrate existing global secrets to the 'admin' user by default.
    # Get the admin user or the first user.
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User.query.first()
    
    if not admin:
        print("No users found in database. Cannot migrate.")
        sys.exit(0)
        
    admin_username = admin.username
    print(f"Migrating orphaned global secrets to user: {admin_username}")
    
    # List all entries in servers/
    try:
        keys = VaultClient.kv_list("servers/")
    except Exception as e:
        print(f"Error listing Vault servers/: {e}")
        keys = []
        
    migrated = 0
    for key in keys:
        if key.endswith("/"):
            # This is a user directory (like admin/), skip it.
            continue
            
        print(f"Migrating secret: {key}")
        data = VaultClient.kv_read(f"servers/{key}")
        if data:
            # Write to new path
            VaultClient.kv_write(f"servers/{admin_username}/{key}", data)
            # Delete old path
            VaultClient.kv_delete(f"servers/{key}")
            migrated += 1
            
    print(f"Migration completed. Moved {migrated} secrets.")
