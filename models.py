from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.types import TypeDecorator, Numeric

db = SQLAlchemy()


class Dinero(TypeDecorator):
    """NUMERIC exacto en la base, compatible con los valores usados por las vistas."""
    impl = Numeric(18, 2)
    cache_ok = True

    def process_result_value(self, value, dialect):
        return float(value) if value is not None else None


class Usuario(db.Model, UserMixin):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="prestamista")
    activo = db.Column(db.Boolean, nullable=False, default=True)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    deudores = db.relationship("Deudor", backref="propietario", lazy=True)
    cuentas = db.relationship("CuentaContable", backref="propietario", lazy=True)

    @property
    def es_admin(self):
        return self.rol == "admin"

    @property
    def is_active(self):
        return self.activo


class CuentaContable(db.Model):
    __tablename__ = "cuentas_contables"

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True, index=True)
    nombre = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(50), nullable=False, unique=True)
    saldo = db.Column(Dinero(), default=0.0, nullable=False)
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
    capital_prestamista_id = db.Column(db.Integer, db.ForeignKey("capital_prestamista.id"), nullable=True)
    tipo = db.Column(db.String(50), nullable=False)
    monto = db.Column(Dinero(), nullable=False)
    descripcion = db.Column(db.String(200))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)


class Deudor(db.Model):
    __tablename__ = "deudores"

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True, index=True)
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
    capital_prestamista_id = db.Column(db.Integer, db.ForeignKey("capital_prestamista.id"), nullable=True, index=True)

    monto = db.Column(Dinero(), nullable=False)
    interes_mensual = db.Column(db.Float, default=7.0)
    numero_cuotas = db.Column(db.Integer, nullable=False)

    fecha_inicio = db.Column(db.Date, default=date.today)
    dia_pago = db.Column(db.Integer, nullable=False)

    saldo_capital = db.Column(Dinero(), nullable=False)
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

    capital = db.Column(Dinero(), nullable=False)
    interes = db.Column(Dinero(), nullable=False)
    total = db.Column(Dinero(), nullable=False)

    pagado_capital = db.Column(Dinero(), default=0)
    pagado_interes = db.Column(Dinero(), default=0)

    estado = db.Column(db.String(30), default="pendiente")
    # pendiente, pagada, parcial, solo_interes, vencida

    liquidado = db.Column(db.Boolean, default=False, nullable=False)
    tasa_admin = db.Column(db.Float, nullable=True)
    ganancia_prestamista = db.Column(Dinero(), default=0.0, nullable=False)
    fecha_liquidacion = db.Column(db.DateTime, nullable=True)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    pagos = db.relationship(
        "Pago",
        backref="cuota",
        lazy=True
    )

    liquidacion = db.relationship(
        "LiquidacionCapital",
        backref="cuota",
        uselist=False,
        cascade="all, delete-orphan"
    )


class Pago(db.Model):
    __tablename__ = "pagos"

    id = db.Column(db.Integer, primary_key=True)

    prestamo_id = db.Column(db.Integer, db.ForeignKey("prestamos.id"), nullable=False)
    cuota_id = db.Column(db.Integer, db.ForeignKey("cuotas.id"), nullable=True)
    cuenta_destino_id = db.Column(db.Integer, db.ForeignKey("cuentas_contables.id"), nullable=True)

    tipo_pago = db.Column(db.String(50), nullable=False)
    # cuota_completa, solo_interes, abono_capital, abono_parcial

    monto = db.Column(Dinero(), nullable=False)

    capital_pagado = db.Column(Dinero(), default=0)
    interes_pagado = db.Column(Dinero(), default=0)

    nota = db.Column(db.Text)

    fecha_pago = db.Column(db.DateTime, default=datetime.utcnow)

    cuenta_destino = db.relationship(
        "CuentaContable",
        backref="pagos_recibidos",
        foreign_keys=[cuenta_destino_id]
    )


class CapitalPrestamista(db.Model):
    __tablename__ = "capital_prestamista"

    id = db.Column(db.Integer, primary_key=True)
    prestamista_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    monto = db.Column(Dinero(), nullable=False)
    monto_banco = db.Column(Dinero(), nullable=False, default=0.0)
    monto_caja_menor = db.Column(Dinero(), nullable=False, default=0.0)
    tasa_admin = db.Column(db.Float, nullable=False)
    plazo_meses = db.Column(db.Integer, nullable=True)
    saldo_pendiente = db.Column(Dinero(), nullable=False)
    capital_liquidado = db.Column(Dinero(), nullable=False, default=0.0)
    interes_liquidado = db.Column(Dinero(), nullable=False, default=0.0)
    estado = db.Column(db.String(20), nullable=False, default="disponible")
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    anulado_en = db.Column(db.DateTime, nullable=True)
    anulado_por_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True)
    motivo_anulacion = db.Column(db.String(250), nullable=True)

    prestamista = db.relationship("Usuario", backref="capital_prestamos", foreign_keys=[prestamista_id])
    anulado_por = db.relationship("Usuario", foreign_keys=[anulado_por_id])
    prestamos = db.relationship("Prestamo", backref="capital_administrador")

    @property
    def pendiente_por_liquidar(self):
        return max(float(self.monto or 0) - float(self.capital_liquidado or 0), 0)

    @property
    def puede_anularse(self):
        return self.estado == "disponible" and not self.prestamos and not self.liquidaciones


class LiquidacionCapital(db.Model):
    __tablename__ = "liquidaciones_capital"

    id = db.Column(db.Integer, primary_key=True)
    cuota_id = db.Column(db.Integer, db.ForeignKey("cuotas.id"), nullable=False, unique=True)
    capital_prestamista_id = db.Column(db.Integer, db.ForeignKey("capital_prestamista.id"), nullable=False)
    capital_inicial = db.Column(Dinero(), nullable=False)
    tasa_admin = db.Column(db.Float, nullable=False)
    tasa_cliente = db.Column(db.Float, nullable=False)
    tasa_prestamista = db.Column(db.Float, nullable=False)
    capital_admin = db.Column(Dinero(), nullable=False)
    interes_admin = db.Column(Dinero(), nullable=False)
    ganancia_prestamista = db.Column(Dinero(), nullable=False)
    pago_cliente = db.Column(Dinero(), nullable=False)
    total_admin = db.Column(Dinero(), nullable=False)
    liquidado_por_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    capital_origen = db.relationship("CapitalPrestamista", backref="liquidaciones")
    liquidado_por = db.relationship("Usuario")
