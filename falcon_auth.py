"""
falcon_auth.py
--------------
Secure credential provider for CrowdStrike Falcon API scripts.

Priority order:
  1. AWS Secrets Manager   (production recommended)
  2. Azure Key Vault        (production alternative)
  3. HashiCorp Vault        (production alternative)
  4. Encrypted local file   (dev/testing only — NOT for production)

Usage:
    from falcon_auth import get_falcon_credentials
    creds = get_falcon_credentials()
    # creds["client_id"], creds["client_secret"],
    # creds["rclient_id"], creds["rclient_secret"]

Environment variables consumed (never credential values):
  FALCON_SECRET_BACKEND   : "aws" | "azure" | "vault" | "local"  (default: "aws")

  AWS backend:
    AWS_SECRET_NAME       : e.g. "prod/crowdstrike/falcon"
    AWS_REGION_NAME       : e.g. "us-east-1"
    (Auth via IAM role / instance profile — no keys in env)

  Azure backend:
    AZURE_VAULT_URL        : e.g. "https://myvault.vault.azure.net/"
    AZURE_SECRET_NAME      : e.g. "crowdstrike-falcon"
    (Auth via Managed Identity / DefaultAzureCredential)

  HashiCorp Vault backend:
    VAULT_ADDR             : e.g. "https://vault.example.com:8200"
    VAULT_TOKEN            : Vault token (short-lived, from CI/CD injection)
    VAULT_SECRET_PATH      : e.g. "secret/data/crowdstrike/falcon"

  Local encrypted backend (dev only):
    FALCON_CRED_FILE       : path to encrypted JSON (default: ~/.falcon_creds.enc)
    FALCON_CRED_KEY_FILE   : path to Fernet key file  (default: ~/.falcon_creds.key)

Secrets JSON shape (all backends expect this structure):
  {
    "client_id":      "...",
    "client_secret":  "...",
    "rclient_id":     "...",
    "rclient_secret": "..."
  }
"""

import os
import json
import logging
import warnings
from pathlib import Path

log = logging.getLogger(__name__)

REQUIRED_KEYS = {"client_id", "client_secret", "rclient_id", "rclient_secret"}


# ── Validation ────────────────────────────────────────────────────────────────

def _validate(creds: dict) -> dict:
    """Ensure all required keys are present and non-empty."""
    missing = [k for k in REQUIRED_KEYS if not creds.get(k)]
    if missing:
        raise ValueError(f"Credential payload is missing required keys: {missing}")
    return creds


# ── Backend: AWS Secrets Manager ──────────────────────────────────────────────

def _from_aws() -> dict:
    """
    Fetch credentials from AWS Secrets Manager.

    Authentication is handled automatically by boto3 via:
      - IAM instance profile (EC2 / ECS / Lambda)
      - Environment-injected role (GitHub Actions OIDC, etc.)
    No AWS access keys should ever be placed in environment variables.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise ImportError("boto3 is required for the AWS backend: pip install boto3")

    secret_name = os.environ.get("AWS_SECRET_NAME")
    region = os.environ.get("AWS_REGION_NAME", "us-east-1")

    if not secret_name:
        raise EnvironmentError("AWS_SECRET_NAME environment variable is not set.")

    log.info(f"Fetching credentials from AWS Secrets Manager (secret={secret_name!r}, region={region!r})")

    client = boto3.session.Session().client(
        service_name="secretsmanager",
        region_name=region,
    )

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise RuntimeError(f"AWS Secrets Manager error [{code}]: {exc}") from exc

    raw = response.get("SecretString") or response.get("SecretBinary", b"").decode()
    return _validate(json.loads(raw))


# ── Backend: Azure Key Vault ──────────────────────────────────────────────────

def _from_azure() -> dict:
    """
    Fetch credentials from Azure Key Vault.

    Authentication is handled by DefaultAzureCredential, which tries
    (in order): Managed Identity, Azure CLI, environment SPN, etc.
    Never put client secrets in environment variables.
    """
    try:
        from azure.keyvault.secrets import SecretClient
        from azure.identity import DefaultAzureCredential
    except ImportError:
        raise ImportError(
            "Azure SDK packages required: pip install azure-keyvault-secrets azure-identity"
        )

    vault_url = os.environ.get("AZURE_VAULT_URL")
    secret_name = os.environ.get("AZURE_SECRET_NAME")

    if not vault_url or not secret_name:
        raise EnvironmentError("AZURE_VAULT_URL and AZURE_SECRET_NAME must be set.")

    log.info(f"Fetching credentials from Azure Key Vault (vault={vault_url!r}, secret={secret_name!r})")

    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    secret = client.get_secret(secret_name)
    return _validate(json.loads(secret.value))


# ── Backend: HashiCorp Vault ──────────────────────────────────────────────────

def _from_vault() -> dict:
    """
    Fetch credentials from HashiCorp Vault (KV v2).

    VAULT_TOKEN should be a short-lived token injected by your CI/CD
    pipeline (e.g. Vault Agent, GitHub Actions vault-action), never
    a long-lived root token stored in config.
    """
    try:
        import hvac
    except ImportError:
        raise ImportError("hvac is required for the Vault backend: pip install hvac")

    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    path = os.environ.get("VAULT_SECRET_PATH")

    if not addr or not token or not path:
        raise EnvironmentError("VAULT_ADDR, VAULT_TOKEN, and VAULT_SECRET_PATH must all be set.")

    log.info(f"Fetching credentials from HashiCorp Vault (addr={addr!r}, path={path!r})")

    client = hvac.Client(url=addr, token=token)
    if not client.is_authenticated():
        raise RuntimeError("HashiCorp Vault authentication failed — check VAULT_TOKEN.")

    # KV v2: path format is "secret/data/<your-path>"
    mount, *secret_path_parts = path.lstrip("/").split("/", 1)
    secret_path = secret_path_parts[0] if secret_path_parts else ""

    response = client.secrets.kv.v2.read_secret_version(
        path=secret_path, mount_point=mount
    )
    data = response["data"]["data"]
    return _validate(data)


# ── Backend: Local encrypted file (dev / testing only) ───────────────────────

def _from_local_encrypted() -> dict:
    """
    Read credentials from a local Fernet-encrypted JSON file.

    THIS IS FOR LOCAL DEVELOPMENT AND TESTING ONLY.
    Never use this backend in production or commit the key/cred files.

    To create the encrypted credential file, run:
        python falcon_auth.py --init-local
    """
    warnings.warn(
        "Using local encrypted credential file. "
        "This is for development only — use a secrets manager in production.",
        UserWarning,
        stacklevel=3,
    )

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise ImportError("cryptography is required for local backend: pip install cryptography")

    cred_file = Path(os.environ.get("FALCON_CRED_FILE", Path.home() / ".falcon_creds.enc"))
    key_file = Path(os.environ.get("FALCON_CRED_KEY_FILE", Path.home() / ".falcon_creds.key"))

    if not key_file.exists():
        raise FileNotFoundError(f"Fernet key file not found: {key_file}")
    if not cred_file.exists():
        raise FileNotFoundError(f"Encrypted credential file not found: {cred_file}")

    key = key_file.read_bytes().strip()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(cred_file.read_bytes())
    return _validate(json.loads(decrypted))


# ── Public entry point ────────────────────────────────────────────────────────

def get_falcon_credentials() -> dict:
    """
    Returns a dict with keys: client_id, client_secret, rclient_id, rclient_secret.
    Selects backend based on FALCON_SECRET_BACKEND env var (default: "aws").
    """
    backend = os.environ.get("FALCON_SECRET_BACKEND", "azure").lower()

    backends = {
        "aws":   _from_aws,
        "azure": _from_azure,
        "vault": _from_vault,
        "local": _from_local_encrypted,
    }

    if backend not in backends:
        raise ValueError(
            f"Unknown FALCON_SECRET_BACKEND={backend!r}. "
            f"Valid options: {list(backends.keys())}"
        )

    log.info(f"Credential backend selected: {backend!r}")
    return backends[backend]()


# ── CLI helper: initialise local dev credentials ──────────────────────────────

def _init_local_creds():
    """
    Interactive helper to create a local encrypted credential file for development.
    Run via:  python falcon_auth.py --init-local
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise ImportError("pip install cryptography")

    print("\n=== Local dev credential setup (NOT for production) ===\n")
    creds = {
        "client_id":      input("client_id:      ").strip(),
        "client_secret":  input("client_secret:  ").strip(),
        "rclient_id":     input("rclient_id:     ").strip(),
        "rclient_secret": input("rclient_secret: ").strip(),
    }

    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(creds).encode())

    key_file = Path.home() / ".falcon_creds.key"
    cred_file = Path.home() / ".falcon_creds.enc"

    key_file.write_bytes(key)
    key_file.chmod(0o600)
    cred_file.write_bytes(encrypted)
    cred_file.chmod(0o600)

    print(f"\nKey written to:         {key_file}")
    print(f"Credentials written to: {cred_file}")
    print("\nAdd both paths to .gitignore immediately.")
    print("Set FALCON_SECRET_BACKEND=local to use these during development.\n")


if __name__ == "__main__":
    import sys
    if "--init-local" in sys.argv:
        _init_local_creds()
    else:
        print(__doc__)