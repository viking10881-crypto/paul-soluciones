from datetime import date, timedelta

import pytest
from werkzeug.security import generate_password_hash

from app import app, db, Usuario, Deudor, Prestamo, Cuota


@pytest.fixture
def client():
    app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite://")

    with app.app_context():
        db.drop_all()
        db.create_all()

        user = Usuario(
            nombre="Administrador",
            usuario="admin",
            password_hash=generate_password_hash("dummy"),
            rol="admin",
            activo=True,
        )
        db.session.add(user)
        db.session.commit()

        deudor = Deudor(nombre="Test", telefono="111", referencia="x", nota="y", usuario_id=user.id)
        db.session.add(deudor)
        db.session.commit()

        prestamo = Prestamo(
            deudor_id=deudor.id,
            monto=1000,
            interes_mensual=10,
            numero_cuotas=2,
            dia_pago=1,
            saldo_capital=1000,
            estado="activo",
        )
        db.session.add(prestamo)
        db.session.commit()

        db.session.add_all(
            [
                Cuota(
                    prestamo_id=prestamo.id,
                    numero=1,
                    fecha_vencimiento=date.today() + timedelta(days=1),
                    capital=500,
                    interes=50,
                    total=550,
                    estado="pendiente",
                ),
                Cuota(
                    prestamo_id=prestamo.id,
                    numero=2,
                    fecha_vencimiento=date.today(),
                    capital=500,
                    interes=50,
                    total=550,
                    estado="pendiente",
                ),
            ]
        )
        db.session.commit()

    with app.test_client() as client:
        yield client


def test_notificaciones_incluyen_cuotas_para_manana_y_vencidas_hoy(client):
    client.post(
        "/login",
        data={"usuario": "admin", "password": "dummy"},
        follow_redirects=True,
    )

    dashboard = client.get("/dashboard")
    assert '<span class="notif-badge">2</span>' in dashboard.get_data(as_text=True)

    notifications = client.get("/notificaciones")
    body = notifications.get_data(as_text=True)
    assert "Cobros para mañana" in body
    assert "Vencidas hoy o atrasadas" in body
