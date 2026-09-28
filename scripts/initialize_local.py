"""Create a private, authenticated local demo configuration without hard-coded credentials."""
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
env = root / ".env"
if env.exists():
    print("Existing .env retained")
else:
    password = secrets.token_urlsafe(24)
    content = (root / ".env.example").read_text()
    content = content.replace("THREATLEANS_AUTH_REQUIRED=false", "THREATLEANS_AUTH_REQUIRED=true")
    content = content.replace("THREATLEANS_ADMIN_PASSWORD=", "THREATLEANS_ADMIN_PASSWORD=" + password)
    env.write_text(content, encoding="utf-8")
    credential = root / "data" / "runtime" / "initial-admin.txt"
    credential.parent.mkdir(parents=True, exist_ok=True)
    credential.write_text("ThreatLeans initial local administrator\nUsername: admin\nPassword: " + password +
                          "\n\nKeep this file private. It is ignored by version control.\n", encoding="utf-8")
    print("Authenticated local configuration created; credentials: data/runtime/initial-admin.txt")
