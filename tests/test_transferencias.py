import pytest
from werkzeug.security import generate_password_hash

from app import app, db, obtener_cuentas_contables
from models import Usuario, CuentaContable, CuentaMovimiento, CapitalPrestamista


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
        caja_admin, banco_admin = obtener_cuentas_contables(admin)
        caja_prestamista, banco_prestamista = obtener_cuentas_contables(prestamista)
        banco_admin.saldo = 100_000
        caja_admin.saldo = 50_000
        db.session.commit()
        datos = (admin.id, prestamista.id, banco_admin.id, caja_admin.id, banco_prestamista.id, caja_prestamista.id)
    with app.test_client() as client:
        yield client, datos


def test_admin_no_puede_inyectar_directamente_a_prestamista(escenario):
    client, (_, _, banco_admin_id, _, banco_prestamista_id, _) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/cuentas", data={"cuenta_id": banco_prestamista_id, "monto": 500_000})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0


def test_transferencia_rechazada_si_admin_no_tiene_saldo(escenario):
    client, (_, prestamista_id, banco_admin_id, _, banco_prestamista_id, _) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/admin/transferir", data={"prestamista_id": prestamista_id, "monto": 200_000, "tasa_admin": 6, "plazo": 5})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0


def test_prestamista_no_puede_recargarse_directamente(escenario):
    client, (_, _, _, _, banco_prestamista_id, _) = escenario
    client.post("/login", data={"usuario": "prestamista", "password": "prestamista123"})
    client.post("/cuentas", data={"cuenta_id": banco_prestamista_id, "monto": 500_000})
    with app.app_context():
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0


def test_transferencia_mixta_descuenta_y_abona_cada_cuenta(escenario):
    client, (_, prestamista_id, banco_admin_id, caja_admin_id, banco_prestamista_id, caja_prestamista_id) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    respuesta = client.post("/admin/transferir", data={
        "prestamista_id": prestamista_id,
        "monto_banco": 70_000,
        "monto_caja_menor": 30_000,
        "tasa_admin": 6,
        "plazo": 5,
    })
    assert respuesta.status_code == 302
    with app.app_context():
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 30_000
        assert db.session.get(CuentaContable, caja_admin_id).saldo == 20_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 70_000
        assert db.session.get(CuentaContable, caja_prestamista_id).saldo == 30_000
        from models import CapitalPrestamista
        capital = CapitalPrestamista.query.one()
        assert capital.monto == 100_000


def test_historial_muestra_origen_y_protege_cuentas_ajenas(escenario):
    client, (_, _, banco_admin_id, _, banco_prestamista_id, _) = escenario
    with app.app_context():
        cuenta = db.session.get(CuentaContable, banco_prestamista_id)
        cuenta.saldo = 70_000
        db.session.add_all([
            CuentaMovimiento(cuenta_id=cuenta.id, tipo="transferencia", monto=100_000, descripcion="Capital desde administrador"),
            CuentaMovimiento(cuenta_id=cuenta.id, tipo="desembolso", monto=-30_000, descripcion="Préstamo al cliente"),
        ])
        db.session.commit()

    client.post("/login", data={"usuario": "prestamista", "password": "prestamista123"})
    historial = client.get(f"/cuentas/{banco_prestamista_id}/movimientos")
    assert historial.status_code == 200
    cuerpo = historial.get_data(as_text=True)
    assert "Capital desde administrador" in cuerpo
    assert "Préstamo al cliente" in cuerpo
    assert "$70,000" in cuerpo
    assert client.get(f"/cuentas/{banco_admin_id}/movimientos").status_code == 404


def test_transferencia_interna_mueve_saldo_sin_crear_capital(escenario):
    client, (_, _, banco_admin_id, caja_admin_id, _, _) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    assert client.get("/cuentas").status_code == 200
    respuesta = client.post("/cuentas/transferencia-interna", data={
        "cuenta_origen": "caja_menor", "cuenta_destino": "banco", "monto": 20_000,
    })
    assert respuesta.status_code == 302
    with app.app_context():
        assert db.session.get(CuentaContable, caja_admin_id).saldo == 30_000
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 120_000
        assert CapitalPrestamista.query.count() == 0
        movimientos = CuentaMovimiento.query.filter_by(tipo="transferencia_interna").all()
        assert sorted(m.monto for m in movimientos) == [-20_000, 20_000]


def test_transferencia_interna_rechaza_saldo_insuficiente(escenario):
    client, (_, _, banco_admin_id, caja_admin_id, _, _) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/cuentas/transferencia-interna", data={
        "cuenta_origen": "caja_menor", "cuenta_destino": "banco", "monto": 60_000,
    })
    with app.app_context():
        assert db.session.get(CuentaContable, caja_admin_id).saldo == 50_000
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000


def test_anular_capital_reintegra_cuentas_y_conserva_historial(escenario):
    client, (_, prestamista_id, banco_admin_id, caja_admin_id, banco_prestamista_id, caja_prestamista_id) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/admin/transferir", data={
        "prestamista_id": prestamista_id,
        "monto_banco": 70_000,
        "monto_caja_menor": 30_000,
        "tasa_admin": 6,
        "plazo": 5,
    })
    with app.app_context():
        capital_id = CapitalPrestamista.query.one().id

    respuesta = client.post(f"/admin/capital/{capital_id}/anular", data={"motivo": "Monto equivocado"})
    assert respuesta.status_code == 302
    with app.app_context():
        capital = db.session.get(CapitalPrestamista, capital_id)
        assert capital.estado == "anulado"
        assert capital.saldo_pendiente == 0
        assert capital.motivo_anulacion == "Monto equivocado"
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, caja_admin_id).saldo == 50_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0
        assert db.session.get(CuentaContable, caja_prestamista_id).saldo == 0
        assert CuentaMovimiento.query.filter_by(
            capital_prestamista_id=capital_id, tipo="anulacion_capital"
        ).count() == 4


def test_anulacion_funciona_despues_de_mover_caja_a_banco(escenario):
    client, (_, prestamista_id, banco_admin_id, caja_admin_id, banco_prestamista_id, caja_prestamista_id) = escenario
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post("/admin/transferir", data={
        "prestamista_id": prestamista_id, "monto_banco": 0, "monto_caja_menor": 30_000,
        "tasa_admin": 6, "plazo": 5,
    })
    with app.app_context():
        capital_id = CapitalPrestamista.query.one().id
    client.post("/logout")
    client.post("/login", data={"usuario": "prestamista", "password": "prestamista123"})
    client.post("/cuentas/transferencia-interna", data={
        "cuenta_origen": "caja_menor", "cuenta_destino": "banco", "monto": 30_000,
    })
    client.post("/logout")
    client.post("/login", data={"usuario": "admin", "password": "admin123456"})
    client.post(f"/admin/capital/{capital_id}/anular", data={"motivo": "Corrección"})
    with app.app_context():
        assert db.session.get(CapitalPrestamista, capital_id).estado == "anulado"
        assert db.session.get(CuentaContable, caja_admin_id).saldo == 50_000
        assert db.session.get(CuentaContable, banco_admin_id).saldo == 100_000
        assert db.session.get(CuentaContable, banco_prestamista_id).saldo == 0
        assert db.session.get(CuentaContable, caja_prestamista_id).saldo == 0
