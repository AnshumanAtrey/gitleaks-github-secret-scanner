"""Per-service test fixtures. Each entry plants known leaks + known FPs.

Each fixture defines:
  files: dict[file_path -> file_contents]
  expected_secrets: list[str]      # secret values that MUST be detected (TP)
  expected_negatives: list[str]    # values that MUST NOT be detected (FP avoidance)
  expected_pairs: list[tuple]      # (id_value, secret_value) — when paired logic must produce a pair
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Fixture:
    files: dict[str, str] = field(default_factory=dict)
    expected_secrets: list[str] = field(default_factory=list)
    expected_negatives: list[str] = field(default_factory=list)
    expected_pairs: list[tuple[str, str]] = field(default_factory=list)


# Note: every secret/key below is a SYNTHETIC value crafted to match real-world
# regex shapes. None of these strings are real production credentials.

FIXTURES: dict[str, Fixture] = {
    "razorpay": Fixture(
        files={
            "settings.py": (
                "RAZORPAY_KEY_ID = 'rzp_live_R8nQpKxF2vHmJa'\n"
                "RAZORPAY_KEY_SECRET = 'K9pNxQ7vRzBwL4mYjT2hC8sA'\n"
            ),
            "docs/README.md": (
                "Example: rzp_live_1234567890abcd (placeholder)\n"
                "Brand: razorpay is a payment gateway.\n"
            ),
            "checkout.js": "var key = 'rzp_test_QwErTyUiOpAsDf';\n",
        },
        expected_secrets=["rzp_live_R8nQpKxF2vHmJa", "K9pNxQ7vRzBwL4mYjT2hC8sA", "rzp_test_QwErTyUiOpAsDf"],
        expected_negatives=["rzp_live_1234567890abcd"],  # placeholder, allowlisted
        expected_pairs=[("rzp_live_R8nQpKxF2vHmJa", "K9pNxQ7vRzBwL4mYjT2hC8sA")],
    ),
    "stripe": Fixture(
        files={
            ".env": (
                "STRIPE_SECRET_KEY=sk_live_AbCdEf0123456789AbCdEf01\n"
                "STRIPE_PUBLISHABLE_KEY=pk_live_AbCdEf0123456789AbCdEf01\n"
                "STRIPE_WEBHOOK_SECRET=whsec_AbCdEf0123456789AbCdEf01AbCdEf0123\n"
            ),
        },
        expected_secrets=[
            "sk_live_AbCdEf0123456789AbCdEf01",
            "whsec_AbCdEf0123456789AbCdEf01AbCdEf0123",
            "pk_live_AbCdEf0123456789AbCdEf01",
        ],
        expected_pairs=[("pk_live_AbCdEf0123456789AbCdEf01", "sk_live_AbCdEf0123456789AbCdEf01")],
    ),
    "aws": Fixture(
        files={
            ".aws/credentials": (
                "[default]\n"
                "aws_access_key_id = AKIAIOSFODNN7BCDEFGH\n"
                "aws_secret_access_key = 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\n"
            ),
        },
        expected_secrets=["AKIAIOSFODNN7BCDEFGH", "wJalrXUtnFEMI/K7MDENGbPxRfiCYREALK0HZX+V"],
        expected_negatives=["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        expected_pairs=[("AKIAIOSFODNN7BCDEFGH", "wJalrXUtnFEMI/K7MDENGbPxRfiCYREALK0HZX+V")],
    ),
    "openai": Fixture(
        files={
            "config.py": "OPENAI_API_KEY = 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf'\n",
        },
        expected_secrets=["sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf"],
    ),
    "anthropic": Fixture(
        files={
            ".env": "ANTHROPIC_API_KEY=sk-ant-api03-abCD12_-eF34gH56ijKL78mn90OpQR_qstuvwXYZabCD12_-eF34gH56ijKL78mn90OpQRstuvwxyzABCDEF12-_qrstuvwx\n",
        },
        expected_secrets=["sk-ant-api03-abCD12_-eF34gH56ijKL78mn90OpQR_qstuvwXYZabCD12_-eF34gH56ijKL78mn90OpQRstuvwxyzABCDEF12-_qrstuvwx"],
    ),
    "groq": Fixture(
        files={
            ".env": "GROQ_API_KEY=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\n",
        },
        expected_secrets=["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"],
    ),
    "gemini": Fixture(
        files={
            ".env": "GEMINI_API_KEY=AIzaSyBcK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP\n",
        },
        expected_secrets=["AIzaSyBcK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP"],
    ),
    "github-pat": Fixture(
        files={
            "deploy.sh": "GITHUB_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ\n",
        },
        expected_secrets=["ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"],
    ),
    "sendgrid": Fixture(
        files={
            ".env": "SENDGRID_API_KEY=SG.aB3kF8nQ2pL5vT7yC4m_.Z9rH6xJ1eD0sW8bN4qP7tM3kF8nQ2pL5vT7yC4mZ9rH6xJ1\n",
        },
        expected_secrets=["SG.aB3kF8nQ2pL5vT7yC4m_.Z9rH6xJ1eD0sW8bN4qP7tM3kF8nQ2pL5vT7yC4mZ9rH6xJ1"],
    ),
    "mailgun": Fixture(
        files={
            ".env": "MAILGUN_API_KEY=key-a1b2c3d4e5f6789012345678901234ab\n",
        },
        expected_secrets=["key-a1b2c3d4e5f6789012345678901234ab"],
    ),
    "postmark": Fixture(
        files={
            ".env": "POSTMARK_TOKEN=abcdef01-2345-6789-abcd-ef0123456789\n",
        },
        expected_secrets=["abcdef01-2345-6789-abcd-ef0123456789"],
    ),
    "twilio": Fixture(
        files={
            ".env": (
                "TWILIO_ACCOUNT_SID=ACa1b2c3d4e5f6789012345678901234ab\n"
                "TWILIO_AUTH_TOKEN=f0e9d8c7b6a543210fedcba98765432a\n"
            ),
        },
        expected_secrets=["ACa1b2c3d4e5f6789012345678901234ab", "f0e9d8c7b6a543210fedcba98765432a"],
        expected_pairs=[("ACa1b2c3d4e5f6789012345678901234ab", "f0e9d8c7b6a543210fedcba98765432a")],
    ),
    "slack-bot": Fixture(
        files={
            ".env": "SLACK_BOT_TOKEN=xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\n",
        },
        expected_secrets=["xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"],
    ),
    "slack-webhook": Fixture(
        files={
            "config.json": '{"webhook":"https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/AbCdEfGhIjKlMnOpQrStUvWx"}\n',
        },
        expected_secrets=["https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/AbCdEfGhIjKlMnOpQrStUvWx"],
    ),
    "discord-bot": Fixture(
        files={
            ".env": "DISCORD_TOKEN=MTAxMjM0NTY3ODkwMTIzNDU2Nw.GAbCDe.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABC\n",
        },
        expected_secrets=["MTAxMjM0NTY3ODkwMTIzNDU2Nw.GAbCDe.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABC"],
    ),
    "datadog": Fixture(
        files={
            ".env": (
                "DD_API_KEY=a1b2c3d4e5f6789012345678901234ab\n"
                "DD_APP_KEY=0fedcba987654321a1b2c3d4e5f6789012345678\n"
            ),
        },
        expected_secrets=[
            "a1b2c3d4e5f6789012345678901234ab",
            "0fedcba987654321a1b2c3d4e5f6789012345678",
        ],
    ),
    "pagerduty": Fixture(
        files={
            ".env": "PAGERDUTY_ROUTING_KEY=a1b2c3d4e5f6789012345678901234ab\n",
        },
        expected_secrets=["a1b2c3d4e5f6789012345678901234ab"],
    ),
    "mongodb-uri": Fixture(
        files={
            ".env": "MONGO_URI=mongodb+srv://admin:RealPass4!@cluster0.example.mongodb.net/mydb\n",
        },
        expected_secrets=["mongodb+srv://admin:RealPass4!@cluster0.example.mongodb.net/mydb"],
        expected_negatives=["mongodb://user:password@localhost:27017"],
    ),
    "postgres-uri": Fixture(
        files={
            ".env": "DATABASE_URL=postgresql://app:RealPa55w0rd@db.example.com:5432/myapp\n",
        },
        expected_secrets=["postgresql://app:RealPa55w0rd@db.example.com:5432/myapp"],
        expected_negatives=["postgres://postgres:postgres@localhost:5432/test"],
    ),
    "redis-uri": Fixture(
        files={
            ".env": "REDIS_URL=rediss://default:RealRedisPass99@redis-prod.example.com:6380/0\n",
        },
        expected_secrets=["rediss://default:RealRedisPass99@redis-prod.example.com:6380/0"],
    ),
    "payu": Fixture(
        files={
            ".env": (
                "PAYU_MERCHANT_KEY=AbCdEf12\n"
                "PAYU_MERCHANT_SALT=XyZpQrSt9876UvWxAbCd1234\n"
                "PAYU_AUTH_HEADER=AbCdEfGhIjKlMnOpQrStUvWxYz0123\n"
            ),
        },
        expected_secrets=["AbCdEf12", "XyZpQrSt9876UvWxAbCd1234", "AbCdEfGhIjKlMnOpQrStUvWxYz0123"],
        expected_pairs=[("AbCdEf12", "XyZpQrSt9876UvWxAbCd1234")],
    ),
    "firecrawl": Fixture(
        files={
            ".env": "FIRECRAWL_API_KEY=fc-a1B2c3D4e5F6g7H8i9J0kLmN1234567890\n",
        },
        expected_secrets=["fc-a1B2c3D4e5F6g7H8i9J0kLmN1234567890"],
    ),
    "trigger-dev": Fixture(
        files={
            ".env": "TRIGGER_SECRET_KEY=tr_prod_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZabCD12EF34g\n",
        },
        expected_secrets=["tr_prod_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZabCD12EF34g"],
    ),
    "jwt-generic": Fixture(
        files={
            ".env": (
                "ACCESS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NSIsImlhdCI6MTczOTE5NjA3NX0."
                "DUMMY_SIG_xy0z1a2b3c4d5e\n"
            ),
        },
        expected_secrets=[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImlhdCI6MTczOTE5NjA3NX0.DUMMY_SIG_xy0z1a2b3c4d5e"
        ],
    ),
    "rsa-private-key": Fixture(
        files={
            "private.pem": (
                "-----BEGIN PRIVATE KEY-----\n"
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJCRtU46F2tdmM\n"
                "Rwsmiu7nW9UoZKZNmED7fHhI/lAS1qRk8RhV+ieg1Z31HWuTuehNP7FVtd5JmqaG\n"
                "-----END PRIVATE KEY-----\n"
            ),
        },
        expected_secrets=[
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJCRtU46F2tdmM\n"
            "Rwsmiu7nW9UoZKZNmED7fHhI/lAS1qRk8RhV+ieg1Z31HWuTuehNP7FVtd5JmqaG\n"
            "-----END PRIVATE KEY-----"
        ],
    ),
    "clerk": Fixture(
        files={
            ".env": (
                "CLERK_SECRET_KEY=sk_live_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZabCD12345E\n"
                "CLERK_PUBLISHABLE_KEY=pk_live_Z9rH6xJ1eD0sW8bN4qP7tM3kF8nQ2pL5vT7yC4mZ9rH6xJ1\n"
            ),
        },
        expected_secrets=[
            "sk_live_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZabCD12345E",
            "pk_live_Z9rH6xJ1eD0sW8bN4qP7tM3kF8nQ2pL5vT7yC4mZ9rH6xJ1",
        ],
        expected_pairs=[(
            "pk_live_Z9rH6xJ1eD0sW8bN4qP7tM3kF8nQ2pL5vT7yC4mZ9rH6xJ1",
            "sk_live_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZabCD12345E",
        )],
    ),
    "supabase": Fixture(
        files={
            ".env": (
                "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzZXJ2aWNlX3JvbGUiOnRydWV9.SERVICE_ROLE_SIGNATURE_X\n"
                "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJhbm9uIjp0cnVlfQ.ANON_SIGNATURE_Y\n"
            ),
        },
        expected_secrets=[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlX3JvbGUiOnRydWV9.SERVICE_ROLE_SIGNATURE_X",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbm9uIjp0cnVlfQ.ANON_SIGNATURE_Y",
        ],
    ),
    "firebase": Fixture(
        files={
            "firebase-config.js": (
                "const firebaseConfig = { apiKey: 'AIzaSyBcK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP' };\n"
            ),
        },
        expected_secrets=[
            "AIzaSyBcK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP",
        ],
    ),
    "gcp-service-account": Fixture(
        files={
            "service-account.json": (
                '{\n'
                '  "type": "service_account",\n'
                '  "project_id": "demo-project",\n'
                '  "private_key_id": "f12345abcdef67890123456789abcdef01234567",\n'
                '  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJCRtU46F2tdmM\\n-----END PRIVATE KEY-----\\n",\n'
                '  "client_email": "demo@demo-project.iam.gserviceaccount.com"\n'
                '}\n'
            ),
        },
        expected_secrets=["-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJCRtU46F2tdmM\\n-----END PRIVATE KEY-----"],
    ),
    "gcp-api-key": Fixture(
        files={
            "config.js": "const GCP_KEY = 'AIzaSyDdK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP';\n",
        },
        expected_secrets=["AIzaSyDdK3lF9mQ2pT5vY8nR4xH7eD0sW1bN6aP"],
    ),
    "cashfree": Fixture(
        files={
            ".env": (
                "CASHFREE_APP_ID=PROD1234abcdEFG5678hijk\n"
                "CASHFREE_SECRET_KEY=cfsk_ma_prod_AbCdEfGhIjKlMnOpQrStUvWxYzABC\n"
            ),
            "config.py": (
                "X_CLIENT_ID = 'TEST9876zyxwVUT5432abcd'\n"
                "X_CLIENT_SECRET = 'cfsk_ma_test_ZyXwVuTsRqPoNmLkJiHgFeDcBaABC'\n"
            ),
        },
        expected_secrets=[
            "PROD1234abcdEFG5678hijk",
            "cfsk_ma_prod_AbCdEfGhIjKlMnOpQrStUvWxYzABC",
            "TEST9876zyxwVUT5432abcd",
            "cfsk_ma_test_ZyXwVuTsRqPoNmLkJiHgFeDcBaABC",
        ],
        expected_pairs=[
            ("PROD1234abcdEFG5678hijk", "cfsk_ma_prod_AbCdEfGhIjKlMnOpQrStUvWxYzABC"),
            ("TEST9876zyxwVUT5432abcd", "cfsk_ma_test_ZyXwVuTsRqPoNmLkJiHgFeDcBaABC"),
        ],
    ),
    "surepass": Fixture(
        files={
            ".env": (
                "SUREPASS_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD\n"
                "SUREPASS_BEARER=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.AbCdEf12gH34iJ56kL78\n"
            ),
        },
        expected_secrets=[
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.AbCdEf12gH34iJ56kL78",
        ],
    ),
    "decentro": Fixture(
        files={
            ".env": (
                "DECENTRO_CLIENT_ID=demo_client_12345_id\n"
                "DECENTRO_CLIENT_SECRET=demo_client_secret_AbCdEfGh1234\n"
                "DECENTRO_MODULE_SECRET=demo_module_secret_ZyXwVuTsRqPo\n"
            ),
        },
        expected_secrets=[
            "demo_client_12345_id",
            "demo_client_secret_AbCdEfGh1234",
            "demo_module_secret_ZyXwVuTsRqPo",
        ],
        expected_pairs=[
            ("demo_client_12345_id", "demo_client_secret_AbCdEfGh1234"),
        ],
    ),
    "karza": Fixture(
        files={
            ".env": "KARZA_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n",
            "config.js": (
                "headers = { 'x-karza-key': 'ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210' }\n"
            ),
        },
        expected_secrets=[
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210",
        ],
    ),
    "attestr": Fixture(
        files={
            ".env": "ATTESTR_API_KEY=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5\n",
            "config.py": "ATTESTR_AUTH = 'AbCdEfGhIjKlMnOpQrStUv0123456789'\n",
        },
        expected_secrets=[
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5",
            "AbCdEfGhIjKlMnOpQrStUv0123456789",
        ],
    ),
    "tartan": Fixture(
        files={
            ".env": "TARTAN_API_KEY=tartanhq_AbCdEfGhIjKlMnOpQrStUvWx9876\n",
            "config.py": "TARTANHQ_TOKEN = 'ZyXwVuTsRqPoNmLkJiHgFe5432'\n",
        },
        expected_secrets=[
            "tartanhq_AbCdEfGhIjKlMnOpQrStUvWx9876",
            "ZyXwVuTsRqPoNmLkJiHgFe5432",
        ],
    ),
    "evm-private-key": Fixture(
        files={
            ".env": (
                "PRIVATE_KEY=0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
                "DEPLOYER_KEY=0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\n"
            ),
            "hardhat.config.js": (
                "const PRIVATE_KEY_MAINNET = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';\n"
                "// public anvil key 0 should NOT trigger:\n"
                "const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';\n"
            ),
        },
        expected_secrets=[
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ],
        expected_negatives=["ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"],
    ),
    "solana-private-key": Fixture(
        files={
            "keypair.js": (
                "const { Keypair } = require('@solana/web3.js');\n"
                "const secretKey = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64];\n"
            ),
        },
        expected_secrets=[
            "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]",
        ],
    ),
    "bitcoin-private-key": Fixture(
        files={
            "wallet.js": (
                "// bitcoin WIF (compressed mainnet)\n"
                "const bitcoin = require('bitcoinjs-lib');\n"
                "const WIF = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6XwgdMUUTf8ekZX';\n"
            ),
        },
        expected_secrets=["KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6XwgdMUUTf8ekZX"],
    ),
    "bip39-mnemonic": Fixture(
        files={
            ".env": (
                "MNEMONIC=witch collapse practice feed shame open despair creek road again ice least\n"
                "# public BIP39 test phrase — should NOT trigger:\n"
                "TEST_SEED=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n"
            ),
        },
        expected_secrets=[
            "witch collapse practice feed shame open despair creek road again ice least",
        ],
        expected_negatives=[
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ],
    ),
}
