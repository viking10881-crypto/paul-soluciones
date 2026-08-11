import pytest
from werkzeug.security import generate_password_hash

from app import app, db, obtener_cuentas_contables
from models import Usuario, CuentaContable


@pytest.fixture
def escenario():
    app.config.update(TESTING=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = Usuario(nombre="Admin", usuario="admin", password_hash=generate_password_hash("admin123456"), rol="admin")
        prestamista = Usuario(nombre="Prestamista", usuario="prestamista", password_hash=generate_password_hash("prestamista123"), rol="prestamista")
        db.session.add_all([admin, prestamista])
        db.session.commit()
        banco_admin = obtener_cuentas_contables(admin)[1]
        banco_prestamista = obtener_cuentas_contables(prestamista)[1]
        banco_admin.saldo = 100_000
        db.session.commit()
        datos = (admin.id, prestamista.id, banco_admin.id, banco_prestamista.id)
    with app.test_client() as client:
        yield client, datos


def test_admin_no_puede_inyectar_directamente_a_prestamista(escenario):
    client, (_, _, banco_admin_id, banco_prestamista_id) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/cuentas", data={"cuenta_id": banco_prestamista_id, "monto": 500_000})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0


def test_transferencia_rechazada_si_admin_no_tiene_saldo(escenario):
    client, (_, prestamista_id, banco_admin_id, banco_prestamista_id) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/admin/transferir", data={"prestamista_id": prestamista_id, "monto": 200_000, "tasa_admin": 6, "plazo": 5})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0


def test_prestamista_no_puede_recargarse_directamente(escenario):
    client, (_, _, _, banco_prestamista_id) = escenario
    client.post("/login", data={"usuario": "prestamista", "password": "prestamista123"})
    client.post("/cuentas", data={"cuenta_id": banco_prestamista_id, "monto": 500_000})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0
