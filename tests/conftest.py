import os
from pathlib import Path


# Se define antes de que pytest importe app.py. Así db.drop_all() nunca puede
# apuntar accidentalmente a Neon ni a otra base configurada en .env.
TEST_DATABASE = Path("/tmp/paul_soluciones_pytest.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
os.environ["SECRET_KEY"] = "clave-exclusiva-para-pruebas"
