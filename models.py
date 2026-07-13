from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class Usuario(db.Model, UserMixin):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)


class CuentaContable(db.Model):
    __tablename__ = "cuentas_contables"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(50), nullable=False, unique=True)
    saldo = db.Column(db.Float, default=0.0, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    movimientos = db.relationship(
        "CuentaMovimiento",
        backref="cuenta",
        lazy=True,
        cascade="all, delete-orphan"
    )


class CuentaMovimiento(db.Model):
    __tablename__ = "cuenta_movimientos"

    id = db.Column(db.Integer, primary_key=True)
    cuenta_id = db.Column(db.Integer, db.ForeignKey("cuentas_contables.id"), nullable=False)
    prestamo_id = db.Column(db.Integer, db.ForeignKey("prestamos.id"), nullable=True)
    pago_id = db.Column(db.Integer, db.ForeignKey("pagos.id"), nullable=True)
    tipo = db.Column(db.String(50), nullable=False)
    monto = db.Column(db.Float, nullable=False)
    descripcion = db.Column(db.String(200))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)


class Deudor(db.Model):
    __tablename__ = "deudores"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=True)
    cedula = db.Column(db.String(50), unique=True, nullable=True)
    telefono = db.Column(db.String(50), nullable=True)
    direccion = db.Column(db.String(200))
    correo = db.Column(db.String(120))
    referencia = db.Column(db.String(150))
    nota = db.Column(db.Text)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    prestamos = db.relationship(
        "Prestamo",
        backref="deudor",
        lazy=True,
        cascade="all, delete-orphan"
    )


class Prestamo(db.Model):
    __tablename__ = "prestamos"

    id = db.Column(db.Integer, primary_key=True)

    deudor_id = db.Column(db.Integer, db.ForeignKey("deudores.id"), nullable=False)
    cuenta_desembolso_id = db.Column(db.Integer, db.ForeignKey("cuentas_contables.id"), nullable=True)

    monto = db.Column(db.Float, nullable=False)
    interes_mensual = db.Column(db.Float, default=7.0)
    numero_cuotas = db.Column(db.Integer, nullable=False)

    fecha_inicio = db.Column(db.Date, default=date.today)
    dia_pago = db.Column(db.Integer, nullable=False)

    saldo_capital = db.Column(db.Float, nullable=False)
    estado = db.Column(db.String(30), default="activo")  
    # activo, pagado, atrasado

    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    cuotas = db.relationship(
        "Cuota",
        backref="prestamo",
        lazy=True,
        cascade="all, delete-orphan"
    )

    pagos = db.relationship(
        "Pago",
        backref="prestamo",
        lazy=True,
        cascade="all, delete-orphan"
    )

    cuenta_desembolso = db.relationship(
        "CuentaContable",
        backref="prestamos_desembolsados",
        foreign_keys=[cuenta_desembolso_id]
    )


class Cuota(db.Model):
    __tablename__ = "cuotas"

    id = db.Column(db.Integer, primary_key=True)

    prestamo_id = db.Column(db.Integer, db.ForeignKey("prestamos.id"), nullable=False)

    numero = db.Column(db.Integer, nullable=False)

    fecha_vencimiento = db.Column(db.Date, nullable=False)

    capital = db.Column(db.Float, nullable=False)
    interes = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)

    pagado_capital = db.Column(db.Float, default=0)
    pagado_interes = db.Column(db.Float, default=0)

    estado = db.Column(db.String(30), default="pendiente")
    # pendiente, pagada, parcial, solo_interes, vencida

    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    pagos = db.relationship(
        "Pago",
        backref="cuota",
        lazy=True
    )


class Pago(db.Model):
    __tablename__ = "pagos"

    id = db.Column(db.Integer, primary_key=True)

    prestamo_id = db.Column(db.Integer, db.ForeignKey("prestamos.id"), nullable=False)
    cuota_id = db.Column(db.Integer, db.ForeignKey("cuotas.id"), nullable=True)
    cuenta_destino_id = db.Column(db.Integer, db.ForeignKey("cuentas_contables.id"), nullable=True)

    tipo_pago = db.Column(db.String(50), nullable=False)
    # cuota_completa, solo_interes, abono_capital, abono_parcial

    monto = db.Column(db.Float, nullable=False)

    capital_pagado = db.Column(db.Float, default=0)
    interes_pagado = db.Column(db.Float, default=0)

    nota = db.Column(db.Text)

    fecha_pago = db.Column(db.DateTime, default=datetime.utcnow)

    cuenta_destino = db.relationship(
        "CuentaContable",
        backref="pagos_recibidos",
        foreign_keys=[cuenta_destino_id]
    )