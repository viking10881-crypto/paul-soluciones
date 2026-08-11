from datetime import date

import pytest
from werkzeug.security import generate_password_hash

from app import app, db, obtener_cuentas_contables
from models import Usuario, Deudor, Prestamo, Cuota, Pago, CuentaContable, CuentaMovimiento


@pytest.fixture
def escenario_contable():
    app.config.update(TESTING=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
        usuario = Usuario(
            nombre="Prestamista", usuario="prestamista",
            password_hash=generate_password_hash("clave123"), rol="prestamista"
        )
        db.session.add(usuario)
        db.session.flush()
        deudor = Deudor(nombre="Cliente", usuario_id=usuario.id)
        db.session.add(deudor)
        db.session.flush()
        prestamo = Prestamo(
            deudor_id=deudor.id, monto=100_000, interes_mensual=10,
            numero_cuotas=2, dia_pago=15, saldo_capital=100_000, estado="activo"
        )
        db.session.add(prestamo)
        db.session.flush()
        cuota = Cuota(
            prestamo_id=prestamo.id, numero=1, fecha_vencimiento=date.today(),
            capital=50_000, interes=10_000, total=60_000, estado="pendiente"
        )
        db.session.add(cuota)
        caja, banco = obtener_cuentas_contables(usuario)
        banco.saldo = 100_000
        db.session.commit()
        ids = dict(usuario=usuario.id, deudor=deudor.id, prestamo=prestamo.id,
                   cuota=cuota.id, caja=caja.id, banco=banco.id)
    with app.test_client() as client:
        client.post("/login", data={"usuario": "prestamista", "password": "clave123"})
        yield client, ids


def test_cuota_completa_exige_monto_exacto(escenario_contable):
    client, ids = escenario_contable
    client.post(f"/pago/cuota/{ids['cuota']}", data={
        "tipo_pago": "cuota_completa", "monto": "1", "cuenta_destino": "caja_menor"
    })
    with app.app_context():
        assert Pago.query.count() == 0
        assert db.session.get(Cuota, ids["cuota"]).estado == "pendiente"
        assert db.session.get(CuentaContable, ids["caja"]).saldo == 0


def test_no_admite_interes_repetido_ni_abono_excedido(escenario_contable):
    client, ids = escenario_contable
    datos = {"tipo_pago": "solo_interes", "monto": "10000", "cuenta_destino": "caja_menor"}
    client.post(f"/pago/cuota/{ids['cuota']}", data=datos)
    client.post(f"/pago/cuota/{ids['cuota']}", data=datos)
    client.post(f"/pago/cuota/{ids['cuota']}", data={
        "tipo_pago": "abono_capital", "monto": "50001", "cuenta_destino": "caja_menor"
    })
    with app.app_context():
        assert Pago.query.count() == 1
        cuota = db.session.get(Cuota, ids["cuota"])
        assert cuota.pagado_interes == 10_000
        assert cuota.pagado_capital == 0


def test_editar_pago_sincroniza_movimiento_y_saldo(escenario_contable):
    client, ids = escenario_contable
    client.post(f"/pago/cuota/{ids['cuota']}", data={
        "tipo_pago": "abono_parcial", "monto": "20000", "cuenta_destino": "caja_menor"
    })
    with app.app_context():
        pago_id = Pago.query.one().id
    client.post(f"/pago/editar/{pago_id}", data={
        "monto": "25000", "capital_pagado": "15000", "interes_pagado": "10000"
    })
    with app.app_context():
        pago = db.session.get(Pago, pago_id)
        movimiento = CuentaMovimiento.query.filter_by(pago_id=pago_id).one()
        assert pago.monto == movimiento.monto == 25_000
        assert db.session.get(CuentaContable, ids["caja"]).saldo == 25_000


def test_refinanciacion_descuenta_solo_efectivo_adicional(escenario_contable):
    client, ids = escenario_contable
    client.post(f"/prestamo/refinanciar/{ids['prestamo']}", data={
        "monto": "130000", "numero_cuotas": "5", "dia_pago": "15",
        "interes_mensual": "10", "cuenta_desembolso": "banco"
    })
    with app.app_context():
        anterior = db.session.get(Prestamo, ids["prestamo"])
        nuevo = Prestamo.query.filter(Prestamo.id != anterior.id).one()
        assert anterior.estado == "refinanciado"
        assert anterior.cuotas[0].estado == "refinanciada"
        assert anterior.cuotas[0].pagado_capital == 0
        assert nuevo.monto == 130_000
        assert db.session.get(CuentaContable, ids["banco"]).saldo == 70_000
        mov = CuentaMovimiento.query.filter_by(tipo="refinanciacion").one()
        assert mov.monto == -30_000


def test_no_elimina_prestamo_con_historial_contable(escenario_contable):
    client, ids = escenario_contable
    with app.app_context():
        db.session.add(CuentaMovimiento(
            cuenta_id=ids["banco"], prestamo_id=ids["prestamo"],
            tipo="desembolso", monto=-100_000, descripcion="Desembolso original"
        ))
        db.session.commit()
    client.post(f"/prestamo/eliminar/{ids['prestamo']}")
    with app.app_context():
        assert db.session.get(Prestamo, ids["prestamo"]) is not None
