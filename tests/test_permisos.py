import pytest
from werkzeug.security import generate_password_hash

from app import app, db, Usuario, Deudor, Prestamo


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
        uno = Usuario(nombre="Uno", usuario="uno", password_hash=generate_password_hash("secreto1"), rol="prestamista")
        dos = Usuario(nombre="Dos", usuario="dos", password_hash=generate_password_hash("secreto2"), rol="prestamista")
        admin = Usuario(nombre="Admin", usuario="admin", password_hash=generate_password_hash("admin123"), rol="admin")
        db.session.add_all([uno, dos, admin])
        db.session.flush()
        cliente_uno = Deudor(nombre="Cliente uno", usuario_id=uno.id)
        cliente_dos = Deudor(nombre="Cliente dos", usuario_id=dos.id)
        db.session.add_all([cliente_uno, cliente_dos])
        db.session.flush()
        db.session.add_all([
            Prestamo(deudor_id=cliente_uno.id, monto=100, numero_cuotas=1, dia_pago=1, saldo_capital=100),
            Prestamo(deudor_id=cliente_dos.id, monto=200, numero_cuotas=1, dia_pago=1, saldo_capital=200),
        ])
        db.session.commit()
        ids = {"uno": cliente_uno.id, "dos": cliente_dos.id}
    with app.test_client() as test_client:
        yield test_client, ids


def login(client, usuario, password):
    return client.post("/login", data={"usuario": usuario, "password": password})


def test_prestamista_solo_ve_sus_clientes(client):
    navegador, ids = client
    login(navegador, "uno", "secreto1")
    listado = navegador.get("/deudores").get_data(as_text=True)
    assert "Cliente uno" in listado
    assert "Cliente dos" not in listado
    assert navegador.get(f"/deudor/{ids['dos']}").status_code == 404


def test_admin_ve_todos_y_administra_prestamistas(client):
    navegador, _ = client
    login(navegador, "admin", "admin123")
    listado = navegador.get("/deudores").get_data(as_text=True)
    assert "Cliente uno" in listado and "Cliente dos" in listado
    assert navegador.get("/prestamistas").status_code == 200


def test_prestamista_no_accede_a_administracion(client):
    navegador, _ = client
    login(navegador, "uno", "secreto1")
    assert navegador.get("/prestamistas").status_code == 403
