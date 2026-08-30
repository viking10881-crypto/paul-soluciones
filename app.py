import os
import hmac
import secrets
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from types import SimpleNamespace
from datetime import date, datetime, timedelta
from calendar import monthrange
from flask import Flask, render_template, redirect, url_for, request, flash, abort, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from dotenv import load_dotenv

from models import (
    db,
    Usuario,
    Deudor,
    Prestamo,
    Cuota,
    Pago,
    CuentaContable,
    CuentaMovimiento,
    CapitalPrestamista,
    LiquidacionCapital,
)
from servicios_liquidacion import calcular_distribucion_liquidacion

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///prestamos_paul.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_size": 5,
    "max_overflow": 2,
}

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Debes iniciar sesión para continuar."

_esquema_preparado = False
CENTAVO = Decimal("0.01")


def dinero(valor, campo="monto"):
    """Convierte una entrada monetaria y la normaliza a dos decimales."""
    try:
        numero = Decimal(str(valor)).quantize(CENTAVO, rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f"El {campo} no es válido.")
    if not numero.is_finite():
        raise ValueError(f"El {campo} no es válido.")
    return numero


def como_float(valor):
    return float(dinero(valor))


def cuenta_bloqueada(cuenta_id, usuario_id):
    """Bloquea la fila en PostgreSQL hasta terminar la transacción."""
    return CuentaContable.query.filter_by(
        id=cuenta_id, usuario_id=usuario_id
    ).with_for_update().first()


def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validar_csrf():
    if app.config.get("TESTING"):
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        esperado = session.get("_csrf_token", "")
        recibido = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not esperado or not hmac.compare_digest(esperado, recibido):
            abort(400, description="La sesión del formulario venció. Recarga la página e inténtalo nuevamente.")


@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(400)
def handle_bad_request(e):
    # Mostrar el motivo (por ejemplo CSRF fallido) y redirigir al login
    descripcion = getattr(e, 'description', None)
    if descripcion:
        flash(descripcion, 'error')
    else:
        flash('Solicitud inválida (400).', 'error')
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.es_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def deudor_visible_o_404(deudor_id):
    query = Deudor.query.filter_by(id=deudor_id)
    if not current_user.es_admin:
        query = query.filter_by(usuario_id=current_user.id)
    return query.first_or_404()


def prestamo_visible_o_404(prestamo_id):
    query = Prestamo.query.join(Deudor).filter(Prestamo.id == prestamo_id)
    if not current_user.es_admin:
        query = query.filter(Deudor.usuario_id == current_user.id)
    return query.first_or_404()


def cuota_visible_o_404(cuota_id):
    query = Cuota.query.join(Prestamo).join(Deudor).filter(Cuota.id == cuota_id)
    if not current_user.es_admin:
        query = query.filter(Deudor.usuario_id == current_user.id)
    return query.first_or_404()


def pago_visible_o_404(pago_id):
    query = Pago.query.join(Prestamo).join(Deudor).filter(Pago.id == pago_id)
    if not current_user.es_admin:
        query = query.filter(Deudor.usuario_id == current_user.id)
    return query.first_or_404()


def obtener_cuotas_urgentes():
    hoy = date.today()
    manana = hoy + timedelta(days=1)

    query = Cuota.query.join(Prestamo).join(Deudor)
    if not current_user.es_admin:
        query = query.filter(Deudor.usuario_id == current_user.id)

    cuotas_urgentes = query.filter(
        Cuota.estado.notin_(["pagada"]),
        (
            (Cuota.fecha_vencimiento == manana) |
            (Cuota.fecha_vencimiento == hoy) |
            (Cuota.fecha_vencimiento < hoy)
        )
    ).all()

    return hoy, manana, cuotas_urgentes


@app.context_processor
def inject_notificaciones_count():
    if current_user.is_authenticated:
        _, _, cuotas_urgentes = obtener_cuotas_urgentes()
        return {"notificaciones_count": len(cuotas_urgentes)}
    return {"notificaciones_count": 0}


def crear_admin():
    admin = Usuario.query.filter_by(usuario="admin").first()

    if not admin:
        nuevo_admin = Usuario(
            nombre="Administrador",
            usuario="admin",
            password_hash=generate_password_hash("admin123"),
            rol="admin",
            activo=True,
        )

        db.session.add(nuevo_admin)
        db.session.commit()

        print("✅ Usuario admin creado: admin / admin123")
    else:
        admin.rol = "admin"
        admin.activo = True
        db.session.commit()


def asignar_datos_existentes_al_admin():
    admin = Usuario.query.filter_by(usuario="admin").first()
    if not admin:
        return
    Deudor.query.filter(Deudor.usuario_id.is_(None)).update({"usuario_id": admin.id})
    CuentaContable.query.filter(CuentaContable.usuario_id.is_(None)).update({"usuario_id": admin.id})
    db.session.commit()

def asegurar_esquema():
    db.create_all()

    dialect = db.engine.dialect.name

    with db.engine.connect() as conn:
        if dialect == "sqlite":
            result = conn.execute(text("PRAGMA table_info(usuarios)"))
            usuarios_cols = [row[1] for row in result.fetchall()]
            if "rol" not in usuarios_cols:
                conn.execute(text("ALTER TABLE usuarios ADD COLUMN rol VARCHAR(20) NOT NULL DEFAULT 'prestamista'"))
            if "activo" not in usuarios_cols:
                conn.execute(text("ALTER TABLE usuarios ADD COLUMN activo BOOLEAN NOT NULL DEFAULT 1"))

            result = conn.execute(text("PRAGMA table_info(deudores)"))
            deudores_cols = [row[1] for row in result.fetchall()]
            if "usuario_id" not in deudores_cols:
                conn.execute(text("ALTER TABLE deudores ADD COLUMN usuario_id INTEGER"))

            result = conn.execute(text("PRAGMA table_info(cuentas_contables)"))
            cuentas_cols = [row[1] for row in result.fetchall()]
            if "usuario_id" not in cuentas_cols:
                conn.execute(text("ALTER TABLE cuentas_contables ADD COLUMN usuario_id INTEGER"))

            result = conn.execute(text("PRAGMA table_info(prestamos)"))
            prestamos_cols = [row[1] for row in result.fetchall()]
            if "cuenta_desembolso_id" not in prestamos_cols:
                conn.execute(text("ALTER TABLE prestamos ADD COLUMN cuenta_desembolso_id INTEGER"))
            if "capital_prestamista_id" not in prestamos_cols:
                conn.execute(text("ALTER TABLE prestamos ADD COLUMN capital_prestamista_id INTEGER"))

            result = conn.execute(text("PRAGMA table_info(pagos)"))
            pagos_cols = [row[1] for row in result.fetchall()]
            if "cuenta_destino_id" not in pagos_cols:
                conn.execute(text("ALTER TABLE pagos ADD COLUMN cuenta_destino_id INTEGER"))

            result = conn.execute(text("PRAGMA table_info(cuenta_movimientos)"))
            movimientos_cols = [row[1] for row in result.fetchall()]
            if "prestamo_id" not in movimientos_cols:
                conn.execute(text("ALTER TABLE cuenta_movimientos ADD COLUMN prestamo_id INTEGER"))
            if "pago_id" not in movimientos_cols:
                conn.execute(text("ALTER TABLE cuenta_movimientos ADD COLUMN pago_id INTEGER"))
            if "capital_prestamista_id" not in movimientos_cols:
                conn.execute(text("ALTER TABLE cuenta_movimientos ADD COLUMN capital_prestamista_id INTEGER"))

            result = conn.execute(text("PRAGMA table_info(cuotas)"))
            cuotas_cols = [row[1] for row in result.fetchall()]
            if "liquidado" not in cuotas_cols:
                conn.execute(text("ALTER TABLE cuotas ADD COLUMN liquidado BOOLEAN NOT NULL DEFAULT 0"))
            if "tasa_admin" not in cuotas_cols:
                conn.execute(text("ALTER TABLE cuotas ADD COLUMN tasa_admin FLOAT"))
            if "ganancia_prestamista" not in cuotas_cols:
                conn.execute(text("ALTER TABLE cuotas ADD COLUMN ganancia_prestamista FLOAT NOT NULL DEFAULT 0.0"))
            if "fecha_liquidacion" not in cuotas_cols:
                conn.execute(text("ALTER TABLE cuotas ADD COLUMN fecha_liquidacion DATETIME"))

            result = conn.execute(text("PRAGMA table_info(capital_prestamista)"))
            capital_cols = [row[1] for row in result.fetchall()]
            if "capital_liquidado" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN capital_liquidado FLOAT NOT NULL DEFAULT 0.0"))
            if "interes_liquidado" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN interes_liquidado FLOAT NOT NULL DEFAULT 0.0"))
            if "estado" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN estado VARCHAR(20) NOT NULL DEFAULT 'disponible'"))
            if "monto_banco" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN monto_banco NUMERIC(18,2) NOT NULL DEFAULT 0"))
            if "monto_caja_menor" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN monto_caja_menor NUMERIC(18,2) NOT NULL DEFAULT 0"))
            if "anulado_en" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN anulado_en DATETIME"))
            if "anulado_por_id" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN anulado_por_id INTEGER"))
            if "motivo_anulacion" not in capital_cols:
                conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN motivo_anulacion VARCHAR(250)"))

            conn.execute(text("PRAGMA foreign_keys = ON"))
            conn.commit()

        elif dialect in ("postgresql", "postgres"):
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS rol VARCHAR(20) NOT NULL DEFAULT 'prestamista'"))
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS activo BOOLEAN NOT NULL DEFAULT TRUE"))
            conn.execute(text("ALTER TABLE deudores ADD COLUMN IF NOT EXISTS usuario_id INTEGER"))
            conn.execute(text("ALTER TABLE cuentas_contables ADD COLUMN IF NOT EXISTS usuario_id INTEGER"))
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'prestamos' AND column_name = 'cuenta_desembolso_id'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE prestamos ADD COLUMN IF NOT EXISTS cuenta_desembolso_id INTEGER"
                ))
            conn.execute(text("ALTER TABLE prestamos ADD COLUMN IF NOT EXISTS capital_prestamista_id INTEGER"))

            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'pagos' AND column_name = 'cuenta_destino_id'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE pagos ADD COLUMN IF NOT EXISTS cuenta_destino_id INTEGER"
                ))

            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'cuenta_movimientos' AND column_name = 'prestamo_id'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE cuenta_movimientos ADD COLUMN IF NOT EXISTS prestamo_id INTEGER"
                ))

            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'cuenta_movimientos' AND column_name = 'pago_id'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE cuenta_movimientos ADD COLUMN IF NOT EXISTS pago_id INTEGER"
                ))
            conn.execute(text("ALTER TABLE cuenta_movimientos ADD COLUMN IF NOT EXISTS capital_prestamista_id INTEGER"))

            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'cuotas' AND column_name = 'liquidado'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS liquidado BOOLEAN NOT NULL DEFAULT FALSE"
                ))
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'cuotas' AND column_name = 'tasa_admin'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS tasa_admin FLOAT"
                ))
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'cuotas' AND column_name = 'ganancia_prestamista'"
            ))
            if result.fetchone() is None:
                conn.execute(text(
                    "ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS ganancia_prestamista FLOAT NOT NULL DEFAULT 0.0"
                ))
            conn.execute(text("ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS fecha_liquidacion TIMESTAMP"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS capital_liquidado FLOAT NOT NULL DEFAULT 0.0"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS interes_liquidado FLOAT NOT NULL DEFAULT 0.0"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS estado VARCHAR(20) NOT NULL DEFAULT 'disponible'"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS monto_banco NUMERIC(18,2) NOT NULL DEFAULT 0"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS monto_caja_menor NUMERIC(18,2) NOT NULL DEFAULT 0"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS anulado_en TIMESTAMP"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS anulado_por_id INTEGER"))
            conn.execute(text("ALTER TABLE capital_prestamista ADD COLUMN IF NOT EXISTS motivo_anulacion VARCHAR(250)"))

            # El dinero se almacena con precisión decimal; USING redondea cualquier
            # residuo binario legado sin alterar el valor visible a dos decimales.
            columnas_dinero = {
                "cuentas_contables": ("saldo",),
                "cuenta_movimientos": ("monto",),
                "prestamos": ("monto", "saldo_capital"),
                "cuotas": ("capital", "interes", "total", "pagado_capital", "pagado_interes", "ganancia_prestamista"),
                "pagos": ("monto", "capital_pagado", "interes_pagado"),
                "capital_prestamista": ("monto", "monto_banco", "monto_caja_menor", "saldo_pendiente", "capital_liquidado", "interes_liquidado"),
                "liquidaciones_capital": ("capital_inicial", "capital_admin", "interes_admin", "ganancia_prestamista", "pago_cliente", "total_admin"),
            }
            for tabla, columnas in columnas_dinero.items():
                for columna in columnas:
                    tipo_actual = conn.execute(text(
                        "SELECT data_type FROM information_schema.columns "
                        "WHERE table_schema = current_schema() AND table_name = :tabla AND column_name = :columna"
                    ), {"tabla": tabla, "columna": columna}).scalar()
                    if tipo_actual and tipo_actual != "numeric":
                        conn.execute(text(
                            f"ALTER TABLE {tabla} ALTER COLUMN {columna} TYPE NUMERIC(18,2) "
                            f"USING ROUND({columna}::numeric, 2)"
                        ))

            conn.commit()

        else:
            # Otros motores de base de datos pueden no necesitar alteraciones explícitas.
            pass


@app.before_request
def preparar_base_de_datos():
    """Aplica las ampliaciones de esquema también al ejecutar con Gunicorn."""
    global _esquema_preparado
    if not _esquema_preparado:
        asegurar_esquema()
        crear_admin()
        asignar_datos_existentes_al_admin()
        _esquema_preparado = True


def actualizar_cuotas_vencidas():
    hoy = date.today()

    query = Cuota.query.join(Prestamo).join(Deudor)
    if current_user.is_authenticated and not current_user.es_admin:
        query = query.filter(Deudor.usuario_id == current_user.id)
    cuotas_vencidas = query.filter(
        Cuota.fecha_vencimiento < hoy,
        Cuota.estado.in_(["pendiente", "parcial", "solo_interes"])
    ).all()

    for cuota in cuotas_vencidas:
        cuota.estado = "vencida"
        cuota.prestamo.estado = "atrasado"

    db.session.commit()


def recalcular_prestamo(prestamo):
    """
    Recalcula saldo_capital y estado del préstamo
    leyendo el estado real de todas sus cuotas.
    Llama esto después de cualquier cambio en cuotas o pagos.
    """
    saldo = 0
    for c in prestamo.cuotas:
        pagado = c.pagado_capital or 0
        saldo += max(c.capital - pagado, 0)

    prestamo.saldo_capital = max(saldo, 0)

    if prestamo.saldo_capital <= 0:
        prestamo.saldo_capital = 0
        prestamo.estado = "pagado"
    else:
        hoy = date.today()
        tiene_vencidas = any(
            c.fecha_vencimiento < hoy and c.estado not in ("pagada",)
            for c in prestamo.cuotas
        )
        prestamo.estado = "atrasado" if tiene_vencidas else "activo"


def obtener_cuentas_contables(usuario=None):
    usuario = usuario or current_user
    sufijo = "" if usuario.es_admin else f"_{usuario.id}"
    caja = CuentaContable.query.filter_by(usuario_id=usuario.id, slug=f"caja_menor{sufijo}").first()
    banco = CuentaContable.query.filter_by(usuario_id=usuario.id, slug=f"banco{sufijo}").first()
    ganancia = CuentaContable.query.filter_by(usuario_id=usuario.id, slug=f"ganancia{sufijo}").first()

    if not caja:
        caja = CuentaContable(nombre="Caja menor", slug=f"caja_menor{sufijo}", saldo=0.0, usuario_id=usuario.id)
        db.session.add(caja)

    if not banco:
        banco = CuentaContable(nombre="Banco", slug=f"banco{sufijo}", saldo=0.0, usuario_id=usuario.id)
        db.session.add(banco)

    if not ganancia:
        ganancia = CuentaContable(nombre="Ganancia", slug=f"ganancia{sufijo}", saldo=0.0, usuario_id=usuario.id)
        db.session.add(ganancia)

    if not caja.id or not banco.id or not ganancia.id:
        db.session.commit()

    return [caja, banco]


def obtener_cuenta(slug, usuario=None):
    usuario = usuario or current_user
    cuentas_base = {"banco", "caja_menor", "ganancia"}
    sufijo = "" if usuario.es_admin else f"_{usuario.id}"

    # Los formularios envian el slug real de la cuenta, que para los
    # prestamistas incluye su sufijo (por ejemplo, banco_4).
    slug_base = slug[:-len(sufijo)] if sufijo and slug.endswith(sufijo) else slug
    if slug_base not in cuentas_base:
        return None

    slug_cuenta = f"{slug_base}{sufijo}"
    cuenta = CuentaContable.query.filter_by(
        usuario_id=usuario.id, slug=slug_cuenta
    ).first()
    if cuenta:
        return cuenta

    # Si no existe la cuenta, crearla automáticamente para evitar errores de transferencia.
    nombre = "Banco" if slug_base == "banco" else "Caja menor" if slug_base == "caja_menor" else slug_base.capitalize()
    cuenta = CuentaContable(nombre=nombre, slug=slug_cuenta, saldo=0.0, usuario_id=usuario.id)
    db.session.add(cuenta)
    db.session.commit()
    return cuenta


def ajustar_saldo_cuenta(cuenta, monto, descripcion, tipo, prestamo_id=None, pago_id=None, capital_prestamista_id=None):
    monto = como_float(monto)
    cuenta.saldo = como_float(dinero(cuenta.saldo or 0) + dinero(monto))

    movimiento = CuentaMovimiento(
        cuenta_id=cuenta.id,
        prestamo_id=prestamo_id,
        pago_id=pago_id,
        capital_prestamista_id=capital_prestamista_id,
        tipo=tipo,
        monto=monto,
        descripcion=descripcion,
    )

    db.session.add(movimiento)


def calcular_liquidacion_cuota(cuota):
    prestamo = cuota.prestamo
    capital_admin = prestamo.capital_administrador
    if not capital_admin:
        raise ValueError("El préstamo no está vinculado a un capital entregado por el administrador.")
    return calcular_distribucion_liquidacion(
        capital_inicial=prestamo.monto,
        numero_cuotas=prestamo.numero_cuotas,
        tasa_admin=capital_admin.tasa_admin,
        tasa_cliente=prestamo.interes_mensual,
        capital_cuota=cuota.capital,
    )


@app.route("/api/liquidacion/simular")
@login_required
def simular_liquidacion():
    try:
        datos = calcular_distribucion_liquidacion(
            capital_inicial=request.args.get("capital", type=float),
            numero_cuotas=request.args.get("cuotas", type=int),
            tasa_admin=request.args.get("tasa_admin", default=0, type=float),
            tasa_cliente=request.args.get("tasa_cliente", type=float),
        )
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(datos)


@app.route("/liquidacion")
@login_required
def liquidaciones():
    cuotas = Cuota.query.join(Cuota.prestamo).join(Prestamo.deudor)
    if not current_user.es_admin:
        cuotas = cuotas.filter(Deudor.usuario_id == current_user.id)
    cuotas = cuotas.filter(Cuota.estado == "pagada").order_by(
        Cuota.fecha_liquidacion.desc().nullslast(),
        Cuota.fecha_vencimiento.desc(),
        Cuota.numero.desc(),
    ).all()
    capitales_query = CapitalPrestamista.query
    if not current_user.es_admin:
        capitales_query = capitales_query.filter_by(prestamista_id=current_user.id)
    capitales = capitales_query.order_by(CapitalPrestamista.creado_en.desc()).all()
    resumenes = []
    for capital in capitales:
        proyeccion = None
        if capital.prestamo_cliente:
            proyeccion = calcular_distribucion_liquidacion(
                capital.monto,
                capital.prestamo_cliente.numero_cuotas,
                capital.tasa_admin,
                capital.prestamo_cliente.interes_mensual,
            )
        resumenes.append({"capital": capital, "proyeccion": proyeccion})
    compatibles = {}
    for cuota in cuotas:
        prestamo = cuota.prestamo
        if prestamo.capital_prestamista_id is None:
            compatibles[prestamo.id] = [
                capital for capital in capitales
                if capital.prestamista_id == prestamo.deudor.usuario_id
                and capital.estado == "disponible"
                and abs(capital.monto - prestamo.monto) <= 0.01
                and (not capital.plazo_meses or capital.plazo_meses == prestamo.numero_cuotas)
                and capital.tasa_admin <= prestamo.interes_mensual
            ]
    return render_template(
        "liquidaciones.html",
        cuotas=cuotas,
        resumenes=resumenes,
        compatibles=compatibles,
    )


@app.route("/liquidacion/prestamo/<int:prestamo_id>/vincular", methods=["POST"])
@login_required
def vincular_capital_prestamo(prestamo_id):
    prestamo = prestamo_visible_o_404(prestamo_id)
    if prestamo.capital_prestamista_id:
        flash("El préstamo ya tiene un capital del administrador vinculado.", "error")
        return redirect(url_for("liquidaciones"))

    capital_id = request.form.get("capital_prestamista_id", type=int)
    capital = CapitalPrestamista.query.filter_by(
        id=capital_id,
        prestamista_id=prestamo.deudor.usuario_id,
        estado="disponible",
    ).first_or_404()
    if abs(capital.monto - prestamo.monto) > 0.01 or (
        capital.plazo_meses and capital.plazo_meses != prestamo.numero_cuotas
    ):
        flash("El monto y el plazo del capital no coinciden con el préstamo.", "error")
        return redirect(url_for("liquidaciones"))
    if capital.tasa_admin > prestamo.interes_mensual:
        flash("La tasa administrativa no puede superar la tasa del cliente.", "error")
        return redirect(url_for("liquidaciones"))

    prestamo.capital_prestamista_id = capital.id
    capital.estado = "colocado"
    db.session.commit()
    flash("Capital vinculado. Las cuotas pagadas ya están disponibles para liquidar.", "success")
    return redirect(url_for("liquidaciones"))


@app.route('/admin/transferir', methods=['GET', 'POST'])
@admin_required
def transferir_prestamista():
    prestamistas = Usuario.query.filter_by(rol='prestamista', activo=True).order_by(Usuario.nombre).all()
    admin_usuario = Usuario.query.filter_by(rol='admin').first()
    obtener_cuentas_contables(admin_usuario)
    banco_admin = obtener_cuenta('banco', admin_usuario)
    caja_admin = obtener_cuenta('caja_menor', admin_usuario)

    if request.method == 'POST':
        prestamista_id = int(request.form.get('prestamista_id'))
        monto_banco = float(request.form.get('monto_banco') or request.form.get('monto') or 0)
        monto_caja = float(request.form.get('monto_caja_menor') or 0)
        monto = monto_banco + monto_caja
        tasa_admin = float(request.form.get('tasa_admin') or 0)
        plazo = int(request.form.get('plazo') or 0)

        if monto <= 0 or monto_banco < 0 or monto_caja < 0 or tasa_admin < 0 or plazo <= 0:
            flash('Los montos y el plazo deben ser válidos; la tasa no puede ser negativa.', 'error')
            return redirect(url_for('transferir_prestamista'))

        prestamista = Usuario.query.filter_by(id=prestamista_id, rol="prestamista", activo=True).first_or_404()
        banco_prestamista = obtener_cuenta('banco', prestamista)
        caja_prestamista = obtener_cuenta('caja_menor', prestamista)

        # Serializa transferencias simultáneas que consumen las mismas cuentas.
        ids_cuentas = sorted({banco_admin.id, caja_admin.id, banco_prestamista.id, caja_prestamista.id})
        bloqueadas = {
            cuenta.id: cuenta for cuenta in CuentaContable.query.filter(
                CuentaContable.id.in_(ids_cuentas)
            ).order_by(CuentaContable.id).with_for_update().all()
        }
        banco_admin = bloqueadas[banco_admin.id]
        caja_admin = bloqueadas[caja_admin.id]
        banco_prestamista = bloqueadas[banco_prestamista.id]
        caja_prestamista = bloqueadas[caja_prestamista.id]

        if (banco_admin.saldo or 0) < monto_banco:
            flash(f'Saldo insuficiente en Banco del administrador: disponible ${banco_admin.saldo:,.0f}.', 'error')
            return redirect(url_for('transferir_prestamista'))
        if (caja_admin.saldo or 0) < monto_caja:
            flash(f'Saldo insuficiente en Caja menor del administrador: disponible ${caja_admin.saldo:,.0f}.', 'error')
            return redirect(url_for('transferir_prestamista'))

        capital = CapitalPrestamista(
            prestamista_id=prestamista.id,
            monto=monto,
            monto_banco=monto_banco,
            monto_caja_menor=monto_caja,
            tasa_admin=tasa_admin,
            plazo_meses=plazo,
            saldo_pendiente=monto,
            estado="disponible",
        )
        db.session.add(capital)
        db.session.flush()

        if monto_banco > 0:
            ajustar_saldo_cuenta(banco_admin, -monto_banco, f'Transferencia de capital #{capital.id} a {prestamista.nombre}', 'transferencia', capital_prestamista_id=capital.id)
            ajustar_saldo_cuenta(banco_prestamista, monto_banco, f'Capital #{capital.id} desde Banco del administrador', 'transferencia', capital_prestamista_id=capital.id)
        if monto_caja > 0:
            ajustar_saldo_cuenta(caja_admin, -monto_caja, f'Transferencia de capital #{capital.id} a {prestamista.nombre}', 'transferencia', capital_prestamista_id=capital.id)
            ajustar_saldo_cuenta(caja_prestamista, monto_caja, f'Capital #{capital.id} desde Caja menor del administrador', 'transferencia', capital_prestamista_id=capital.id)

        db.session.commit()
        flash('Transferencia registrada correctamente.', 'success')
        return redirect(url_for('cuentas'))

    return render_template(
        'transferir_prestamista.html',
        prestamistas=prestamistas,
        banco_admin=banco_admin,
        caja_admin=caja_admin,
    )


@app.route("/admin/capital/<int:capital_id>/anular", methods=["POST"])
@admin_required
def anular_capital_prestamista(capital_id):
    capital = CapitalPrestamista.query.filter_by(id=capital_id).with_for_update().first_or_404()
    motivo = (request.form.get("motivo") or "Error al registrar la transferencia").strip()[:250]
    if capital.estado != "disponible" or capital.prestamo_cliente or capital.liquidaciones:
        flash("Este capital ya fue utilizado o liquidado y no puede anularse.", "error")
        return redirect(url_for("liquidaciones"))

    monto_banco = dinero(capital.monto_banco or 0)
    monto_caja = dinero(capital.monto_caja_menor or 0)
    if monto_banco + monto_caja != dinero(capital.monto):
        flash("Este capital antiguo no tiene trazabilidad completa de origen y no puede anularse automáticamente.", "error")
        return redirect(url_for("liquidaciones"))

    admin = Usuario.query.filter_by(rol="admin").first_or_404()
    cuentas = [
        obtener_cuenta("banco", admin), obtener_cuenta("caja_menor", admin),
        obtener_cuenta("banco", capital.prestamista), obtener_cuenta("caja_menor", capital.prestamista),
    ]
    bloqueadas = {
        c.id: c for c in CuentaContable.query.filter(
            CuentaContable.id.in_(sorted(c.id for c in cuentas))
        ).order_by(CuentaContable.id).with_for_update().all()
    }
    banco_admin, caja_admin, banco_prestamista, caja_prestamista = [bloqueadas[c.id] for c in cuentas]
    total_anular = monto_banco + monto_caja
    saldo_prestamista = dinero(banco_prestamista.saldo or 0) + dinero(caja_prestamista.saldo or 0)
    if saldo_prestamista < total_anular:
        db.session.rollback()
        flash("El prestamista ya no conserva todo el capital; no se puede anular automáticamente.", "error")
        return redirect(url_for("liquidaciones"))

    descripcion = f"Anulación de capital #{capital.id}: {motivo}"
    restante = total_anular
    retiro_banco = min(dinero(banco_prestamista.saldo or 0), restante)
    if retiro_banco > 0:
        ajustar_saldo_cuenta(banco_prestamista, -retiro_banco, descripcion, "anulacion_capital", capital_prestamista_id=capital.id)
        restante -= retiro_banco
    if restante > 0:
        ajustar_saldo_cuenta(caja_prestamista, -restante, descripcion, "anulacion_capital", capital_prestamista_id=capital.id)
    if monto_banco > 0:
        ajustar_saldo_cuenta(banco_admin, monto_banco, descripcion, "anulacion_capital", capital_prestamista_id=capital.id)
    if monto_caja > 0:
        ajustar_saldo_cuenta(caja_admin, monto_caja, descripcion, "anulacion_capital", capital_prestamista_id=capital.id)
    capital.estado = "anulado"
    capital.saldo_pendiente = 0
    capital.anulado_en = datetime.utcnow()
    capital.anulado_por_id = current_user.id
    capital.motivo_anulacion = motivo
    db.session.commit()
    flash(f"Capital #{capital.id} anulado. El dinero regresó a las cuentas del administrador.", "success")
    return redirect(url_for("liquidaciones"))


@app.route("/liquidacion/cuota/<int:cuota_id>", methods=["GET", "POST"])
@login_required
def liquidar_cuota(cuota_id):
    cuota = cuota_visible_o_404(cuota_id)
    prestamo = cuota.prestamo
    prestamista = prestamo.deudor.propietario
    capital_admin = prestamo.capital_administrador

    if not capital_admin:
        flash("Este préstamo no está vinculado a un capital del administrador.", "error")
        return redirect(url_for("liquidaciones"))

    try:
        datos_liquidacion = calcular_liquidacion_cuota(cuota)
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("liquidaciones"))

    if request.method == "POST":
        if cuota.estado != "pagada":
            flash("Solo se puede liquidar una cuota que esté pagada.", "error")
            return redirect(url_for("liquidar_cuota", cuota_id=cuota.id))

        if cuota.liquidado:
            flash("Esta cuota ya fue liquidada.", "error")
            return redirect(url_for("liquidaciones"))

        admin_total = datos_liquidacion["admin_total"]
        ganancia_prestamista = datos_liquidacion["ganancia_prestamista"]

        admin_usuario = Usuario.query.filter_by(rol="admin").first()
        if not admin_usuario:
            abort(500)

        obtener_cuentas_contables(admin_usuario)
        cuenta_admin = obtener_cuenta("banco", admin_usuario)
        if not cuenta_admin:
            abort(500)

        cuenta_prestamista_banco = obtener_cuenta("banco", prestamista)
        cuenta_prestamista_caja = obtener_cuenta("caja_menor", prestamista)

        saldo_operativo = (cuenta_prestamista_banco.saldo or 0) + (cuenta_prestamista_caja.saldo or 0)
        total_a_distribuir = admin_total + ganancia_prestamista
        if saldo_operativo + 0.01 < total_a_distribuir:
            flash(
                "No está disponible el pago completo del cliente en las cuentas del prestamista. "
                "La cuota no fue liquidada.",
                "error",
            )
            return redirect(url_for("liquidar_cuota", cuota_id=cuota.id))

        cantidad_restante = admin_total
        fuentes = []
        if cuenta_prestamista_banco and (cuenta_prestamista_banco.saldo or 0) > 0:
            usado = min(cuenta_prestamista_banco.saldo, cantidad_restante)
            fuentes.append((cuenta_prestamista_banco, usado))
            cantidad_restante -= usado

        if cantidad_restante > 0 and cuenta_prestamista_caja and (cuenta_prestamista_caja.saldo or 0) > 0:
            usado = min(cuenta_prestamista_caja.saldo, cantidad_restante)
            fuentes.append((cuenta_prestamista_caja, usado))
            cantidad_restante -= usado

        if cantidad_restante > 0:
            flash(
                "No hay saldo suficiente en las cuentas del prestamista para liquidar al administrador.",
                "error"
            )
            return redirect(url_for("liquidar_cuota", cuota_id=cuota.id))

        for cuenta, monto in fuentes:
            if monto > 0:
                ajustar_saldo_cuenta(
                    cuenta,
                    -monto,
                    f"Liquidación capital cuota #{cuota.id} al administrador",
                    "liquidacion",
                    prestamo_id=prestamo.id
                )

        ajustar_saldo_cuenta(
            cuenta_admin,
            admin_total,
            f"Liquidación capital cuota #{cuota.id} de {prestamista.nombre}",
            "liquidacion",
            prestamo_id=prestamo.id
        )

        # Separar la ganancia del prestamista a una cuenta específica 'ganancia'
        cuenta_ganancia = obtener_cuenta('ganancia', prestamista)
        ganancia_a_mover = ganancia_prestamista or 0
        if ganancia_a_mover > 0:
            restante_g = ganancia_a_mover
            fuentes_g = []
            if cuenta_prestamista_banco and (cuenta_prestamista_banco.saldo or 0) > 0:
                usado = min(cuenta_prestamista_banco.saldo, restante_g)
                fuentes_g.append((cuenta_prestamista_banco, usado))
                restante_g -= usado

            if restante_g > 0 and cuenta_prestamista_caja and (cuenta_prestamista_caja.saldo or 0) > 0:
                usado = min(cuenta_prestamista_caja.saldo, restante_g)
                fuentes_g.append((cuenta_prestamista_caja, usado))
                restante_g -= usado

            movido = 0
            for cuenta, monto in fuentes_g:
                if monto > 0:
                    ajustar_saldo_cuenta(
                        cuenta,
                        -monto,
                        f"Separación ganancia cuota #{cuota.id}",
                        "transferencia_ganancia",
                        prestamo_id=prestamo.id
                    )
                    movido += monto

            if movido + 0.01 < ganancia_a_mover:
                db.session.rollback()
                flash("No fue posible separar la ganancia completa del prestamista.", "error")
                return redirect(url_for("liquidar_cuota", cuota_id=cuota.id))

            if movido > 0:
                ajustar_saldo_cuenta(
                    cuenta_ganancia,
                    movido,
                    f"Ganancia cuota #{cuota.id}",
                    "ganancia",
                    prestamo_id=prestamo.id
                )

        cuota.liquidado = True
        cuota.tasa_admin = capital_admin.tasa_admin
        cuota.ganancia_prestamista = ganancia_prestamista
        cuota.fecha_liquidacion = datetime.utcnow()

        capital_admin.capital_liquidado = (capital_admin.capital_liquidado or 0) + datos_liquidacion["capital_mensual"]
        capital_admin.interes_liquidado = (capital_admin.interes_liquidado or 0) + datos_liquidacion["interes_admin"]
        capital_admin.saldo_pendiente = max(
            (capital_admin.saldo_pendiente or 0) - datos_liquidacion["capital_mensual"],
            0,
        )
        if capital_admin.saldo_pendiente <= 0.01:
            capital_admin.saldo_pendiente = 0
            capital_admin.estado = "liquidado"

        db.session.add(LiquidacionCapital(
            cuota_id=cuota.id,
            capital_prestamista_id=capital_admin.id,
            capital_inicial=datos_liquidacion["capital_inicial"],
            tasa_admin=datos_liquidacion["tasa_admin"],
            tasa_cliente=datos_liquidacion["tasa_cliente"],
            tasa_prestamista=datos_liquidacion["tasa_prestamista"],
            capital_admin=datos_liquidacion["capital_mensual"],
            interes_admin=datos_liquidacion["interes_admin"],
            ganancia_prestamista=ganancia_prestamista,
            pago_cliente=datos_liquidacion["cuota_cliente"],
            total_admin=admin_total,
            liquidado_por_id=current_user.id,
        ))

        db.session.commit()

        flash(
            f"Cuota liquidada. Admin recibe ${admin_total:,.0f} y el prestamista conserva ${ganancia_prestamista:,.0f}.",
            "success"
        )
        return redirect(url_for("liquidaciones"))

    return render_template(
        "liquidar_cuota.html",
        cuota=cuota,
        prestamista=prestamista,
        datos=datos_liquidacion,
    )


@app.route("/")
def inicio():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")

        user = Usuario.query.filter_by(usuario=usuario).first()

        if user and user.activo and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Usuario o contraseña incorrectos", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/perfil/seguridad", methods=["GET", "POST"])
@login_required
def seguridad_perfil():
    if request.method == "POST":
        actual = request.form.get("password_actual") or ""
        nueva = request.form.get("password_nueva") or ""
        confirmacion = request.form.get("password_confirmacion") or ""

        if not check_password_hash(current_user.password_hash, actual):
            flash("La contraseña actual no es correcta.", "error")
        elif len(nueva) < 10:
            flash("La contraseña nueva debe tener al menos 10 caracteres.", "error")
        elif nueva != confirmacion:
            flash("La confirmación no coincide con la contraseña nueva.", "error")
        elif nueva == actual:
            flash("La contraseña nueva debe ser diferente de la actual.", "error")
        else:
            current_user.password_hash = generate_password_hash(nueva)
            db.session.commit()
            session.clear()
            flash("Contraseña actualizada. Inicia sesión nuevamente.", "success")
            return redirect(url_for("login"))

    return render_template("seguridad_perfil.html")


@app.route("/dashboard")
@login_required
def dashboard():

    actualizar_cuotas_vencidas()

    deudores_query = Deudor.query
    prestamos_query = Prestamo.query.join(Deudor)
    pagos_query = Pago.query.join(Prestamo).join(Deudor)
    if not current_user.es_admin:
        deudores_query = deudores_query.filter(Deudor.usuario_id == current_user.id)
        prestamos_query = prestamos_query.filter(Deudor.usuario_id == current_user.id)
        pagos_query = pagos_query.filter(Deudor.usuario_id == current_user.id)

    deudores = deudores_query.count()
    prestamos = prestamos_query.all()
    pagos = pagos_query.all()

    total_prestado = sum(p.monto for p in prestamos)

    capital_pendiente = sum(p.saldo_capital for p in prestamos)

    total_pagado = sum(p.monto for p in pagos)

    intereses_ganados = sum(p.interes_pagado for p in pagos)

    prestamos_activos = sum(p.estado == "activo" for p in prestamos)
    prestamos_pagados = sum(p.estado == "pagado" for p in prestamos)
    prestamos_atrasados = sum(p.estado == "atrasado" for p in prestamos)

    if current_user.es_admin:
        cuentas = CuentaContable.query.all()
        caja = SimpleNamespace(saldo=sum(c.saldo for c in cuentas if c.slug.startswith("caja_menor")))
        banco = SimpleNamespace(saldo=sum(c.saldo for c in cuentas if c.slug.startswith("banco")))
        prestamistas_resumen = []
        for usuario in Usuario.query.filter_by(rol="prestamista").order_by(Usuario.nombre).all():
            cartera = [p for cliente in usuario.deudores for p in cliente.prestamos]
            recaudos = [pago for prestamo in cartera for pago in prestamo.pagos]
            prestamistas_resumen.append({
                "usuario": usuario,
                "clientes": len(usuario.deudores),
                "prestamos": len(cartera),
                "total_prestado": sum(p.monto for p in cartera),
                "capital_pendiente": sum(p.saldo_capital for p in cartera),
                "total_recaudado": sum(p.monto for p in recaudos),
                "atrasados": sum(p.estado == "atrasado" for p in cartera),
            })
    else:
        caja, banco = obtener_cuentas_contables()
        prestamistas_resumen = []

    return render_template(
        "dashboard.html",
        deudores=deudores,
        total_prestado=total_prestado,
        capital_pendiente=capital_pendiente,
        total_pagado=total_pagado,
        intereses_ganados=intereses_ganados,
        prestamos_activos=prestamos_activos,
        prestamos_pagados=prestamos_pagados,
        prestamos_atrasados=prestamos_atrasados,
        caja=caja,
        banco=banco,
        prestamistas_resumen=prestamistas_resumen,
    )


@app.route("/cuentas", methods=["GET", "POST"])
@login_required
def cuentas():
    if current_user.es_admin:
        # Garantiza al menos las cuentas propias del administrador.
        obtener_cuentas_contables()
        cuentas = CuentaContable.query.order_by(CuentaContable.usuario_id, CuentaContable.nombre).all()
    else:
        obtener_cuentas_contables()
        cuentas = CuentaContable.query.filter_by(usuario_id=current_user.id).order_by(CuentaContable.nombre).all()

    if request.method == "POST":
        if not current_user.es_admin:
            flash("Los prestamistas no pueden recargar saldos directamente. El capital debe transferirlo el administrador.", "error")
            return redirect(url_for("cuentas"))

        cuenta_id = int(request.form.get("cuenta_id"))
        monto = float(request.form.get("monto"))
        descripcion = request.form.get("descripcion") or "Inyección de capital"

        if monto <= 0:
            flash("El monto debe ser mayor a cero.", "error")
            return redirect(url_for("cuentas"))

        cuenta = CuentaContable.query.get_or_404(cuenta_id)
        if cuenta.usuario_id != current_user.id:
            flash("No puedes inyectar saldo directamente en una cuenta de un prestamista. Usa Transferir a prestamista.", "error")
            return redirect(url_for("cuentas"))
        ajustar_saldo_cuenta(
            cuenta,
            monto,
            descripcion,
            "inyeccion"
        )
        db.session.commit()

        flash(f"Se agregó ${monto:,.0f} a {cuenta.nombre}.", "success")
        return redirect(url_for("cuentas"))

    # admin helper: transferir a prestamista
    transfer_link = None
    if current_user.es_admin:
        transfer_link = url_for('transferir_prestamista')

    cuentas_inyectables = [
        cuenta for cuenta in cuentas
        if current_user.es_admin
        and cuenta.usuario_id == current_user.id
        and not cuenta.slug.startswith("ganancia")
    ]
    cuentas_propias = {
        cuenta.slug.split(f"_{current_user.id}")[0]: cuenta
        for cuenta in CuentaContable.query.filter_by(usuario_id=current_user.id).all()
    }
    return render_template(
        "cuentas.html",
        cuentas=cuentas,
        cuentas_inyectables=cuentas_inyectables,
        cuentas_propias=cuentas_propias,
    )


@app.route("/cuentas/<int:cuenta_id>/movimientos")
@login_required
def movimientos_cuenta(cuenta_id):
    cuenta = CuentaContable.query.get_or_404(cuenta_id)
    if not current_user.es_admin and cuenta.usuario_id != current_user.id:
        abort(404)

    movimientos_asc = CuentaMovimiento.query.filter_by(cuenta_id=cuenta.id).order_by(
        CuentaMovimiento.fecha.asc(),
        CuentaMovimiento.id.asc(),
    ).all()
    saldo_calculado = (cuenta.saldo or 0) - sum(movimiento.monto for movimiento in movimientos_asc)
    saldos_resultantes = {}
    for movimiento in movimientos_asc:
        saldo_calculado += movimiento.monto
        saldos_resultantes[movimiento.id] = saldo_calculado

    movimientos = list(reversed(movimientos_asc))
    return render_template(
        "movimientos_cuenta.html",
        cuenta=cuenta,
        movimientos=movimientos,
        saldos_resultantes=saldos_resultantes,
    )


@app.route("/cuentas/transferencia-interna", methods=["POST"])
@login_required
def transferencia_interna():
    origen_slug = request.form.get("cuenta_origen")
    destino_slug = request.form.get("cuenta_destino")
    if {origen_slug, destino_slug} != {"banco", "caja_menor"}:
        flash("Selecciona Banco y Caja menor como cuentas diferentes.", "error")
        return redirect(url_for("cuentas"))
    try:
        monto = dinero(request.form.get("monto"))
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("cuentas"))
    if monto <= 0:
        flash("El monto debe ser mayor a cero.", "error")
        return redirect(url_for("cuentas"))

    origen = obtener_cuenta(origen_slug, current_user)
    destino = obtener_cuenta(destino_slug, current_user)
    bloqueadas = {
        cuenta.id: cuenta for cuenta in CuentaContable.query.filter(
            CuentaContable.id.in_(sorted([origen.id, destino.id])),
            CuentaContable.usuario_id == current_user.id,
        ).order_by(CuentaContable.id).with_for_update().all()
    }
    origen = bloqueadas.get(origen.id)
    destino = bloqueadas.get(destino.id)
    if not origen or not destino or dinero(origen.saldo or 0) < monto:
        disponible = origen.saldo if origen else 0
        db.session.rollback()
        flash(f"Saldo insuficiente en la cuenta de origen: disponible ${disponible:,.2f}.", "error")
        return redirect(url_for("cuentas"))

    descripcion = f"Transferencia interna {origen.nombre} → {destino.nombre}"
    ajustar_saldo_cuenta(origen, -monto, descripcion, "transferencia_interna")
    ajustar_saldo_cuenta(destino, monto, descripcion, "transferencia_interna")
    db.session.commit()
    flash(f"Se transfirieron ${float(monto):,.2f} de {origen.nombre} a {destino.nombre}.", "success")
    return redirect(url_for("cuentas"))


@app.route("/prestamistas")
@admin_required
def prestamistas():
    lista = Usuario.query.filter(Usuario.rol == "prestamista").order_by(Usuario.nombre).all()
    return render_template("prestamistas.html", prestamistas=lista)


@app.route("/prestamistas/<int:usuario_id>")
@admin_required
def detalle_prestamista(usuario_id):
    prestamista = Usuario.query.filter_by(id=usuario_id, rol="prestamista").first_or_404()
    clientes = Deudor.query.filter_by(usuario_id=prestamista.id).order_by(Deudor.creado_en.desc()).all()
    cartera = [prestamo for cliente in clientes for prestamo in cliente.prestamos]
    pagos = [pago for prestamo in cartera for pago in prestamo.pagos]
    cuentas = CuentaContable.query.filter_by(usuario_id=prestamista.id).order_by(CuentaContable.nombre).all()
    metricas = {
        "clientes": len(clientes),
        "prestamos": len(cartera),
        "total_prestado": sum(p.monto for p in cartera),
        "capital_pendiente": sum(p.saldo_capital for p in cartera),
        "total_recaudado": sum(p.monto for p in pagos),
        "intereses": sum(p.interes_pagado for p in pagos),
        "atrasados": sum(p.estado == "atrasado" for p in cartera),
    }
    return render_template(
        "detalle_prestamista.html",
        prestamista=prestamista,
        clientes=clientes,
        cuentas=cuentas,
        metricas=metricas,
    )


@app.route("/prestamistas/nuevo", methods=["GET", "POST"])
@admin_required
def nuevo_prestamista():
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        usuario = (request.form.get("usuario") or "").strip().lower()
        password = request.form.get("password") or ""

        if not nombre or not usuario or len(password) < 6:
            flash("Completa los datos y usa una contraseña de al menos 6 caracteres.", "error")
        elif Usuario.query.filter_by(usuario=usuario).first():
            flash("Ese nombre de usuario ya está registrado.", "error")
        else:
            prestamista = Usuario(
                nombre=nombre,
                usuario=usuario,
                password_hash=generate_password_hash(password),
                rol="prestamista",
                activo=True,
            )
            db.session.add(prestamista)
            db.session.commit()
            obtener_cuentas_contables(prestamista)
            flash("Prestamista creado correctamente.", "success")
            return redirect(url_for("prestamistas"))

    return render_template("prestamista_form.html", prestamista=None)


@app.route("/prestamistas/<int:usuario_id>/editar", methods=["GET", "POST"])
@admin_required
def editar_prestamista(usuario_id):
    prestamista = Usuario.query.filter_by(id=usuario_id, rol="prestamista").first_or_404()
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        usuario = (request.form.get("usuario") or "").strip().lower()
        password = request.form.get("password") or ""
        repetido = Usuario.query.filter(Usuario.usuario == usuario, Usuario.id != prestamista.id).first()

        if not nombre or not usuario:
            flash("Nombre y usuario son obligatorios.", "error")
        elif repetido:
            flash("Ese nombre de usuario ya está registrado.", "error")
        elif password and len(password) < 6:
            flash("La nueva contraseña debe tener al menos 6 caracteres.", "error")
        else:
            prestamista.nombre = nombre
            prestamista.usuario = usuario
            prestamista.activo = request.form.get("activo") == "on"
            if password:
                prestamista.password_hash = generate_password_hash(password)
            db.session.commit()
            flash("Prestamista actualizado correctamente.", "success")
            return redirect(url_for("prestamistas"))

    return render_template("prestamista_form.html", prestamista=prestamista)


@app.route("/deudores")
@login_required
def deudores():
    query = Deudor.query
    if not current_user.es_admin:
        query = query.filter_by(usuario_id=current_user.id)
    lista = query.order_by(Deudor.creado_en.desc()).all()
    return render_template("deudores.html", deudores=lista)


@app.route("/deudores/nuevo", methods=["GET", "POST"])
@login_required
def nuevo_deudor():
    if request.method == "POST":
        deudor = Deudor(
            usuario_id=current_user.id,
            nombre=request.form.get("nombre") or None,
            telefono=request.form.get("telefono") or None,
            referencia=request.form.get("referencia"),
            nota=request.form.get("nota")
        )

        db.session.add(deudor)
        db.session.commit()

        flash("Deudor registrado correctamente", "success")
        return redirect(url_for("deudores"))

    return render_template("nuevo_deudor.html")


@app.route("/deudor/<int:deudor_id>")
@login_required
def detalle_deudor(deudor_id):
    deudor = deudor_visible_o_404(deudor_id)

    def clave_orden(prestamo):
        estado = (prestamo.estado or "activo").strip().lower()
        # Activos y atrasados son cartera vigente; pagados siempre van al final.
        return 2 if estado == "pagado" else 1 if estado == "refinanciado" else 0

    prestamos_recientes = sorted(
        deudor.prestamos,
        key=lambda p: (p.creado_en or datetime.min, p.id),
        reverse=True,
    )
    prestamos_ordenados = sorted(prestamos_recientes, key=clave_orden)
    return render_template(
        "detalle_deudor.html",
        deudor=deudor,
        prestamos_ordenados=prestamos_ordenados,
    )


@app.route("/deudores/editar/<int:deudor_id>", methods=["GET", "POST"])
@login_required
def editar_deudor(deudor_id):
    deudor = deudor_visible_o_404(deudor_id)

    if request.method == "POST":
        deudor.nombre = request.form.get("nombre") or None
        deudor.telefono = request.form.get("telefono") or None
        deudor.referencia = request.form.get("referencia")
        deudor.nota = request.form.get("nota")

        db.session.commit()

        flash("Deudor actualizado correctamente", "success")
        return redirect(url_for("deudores"))

    return render_template("nuevo_deudor.html", deudor=deudor)


@app.route("/deudores/eliminar/<int:deudor_id>", methods=["POST"])
@login_required
def eliminar_deudor(deudor_id):
    deudor = deudor_visible_o_404(deudor_id)

    ids = [prestamo.id for prestamo in deudor.prestamos]
    tiene_historial = any(prestamo.pagos for prestamo in deudor.prestamos)
    tiene_historial = tiene_historial or (ids and CuentaMovimiento.query.filter(
        CuentaMovimiento.prestamo_id.in_(ids)
    ).first() is not None)
    tiene_historial = tiene_historial or any(
        cuota.liquidado for prestamo in deudor.prestamos for cuota in prestamo.cuotas
    )
    if tiene_historial:
        flash("No se puede eliminar un cliente con pagos o movimientos contables. Conserva el historial financiero.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=deudor.id))

    for prestamo in deudor.prestamos:
        if prestamo.capital_administrador:
            prestamo.capital_administrador.estado = "disponible"

    db.session.delete(deudor)
    db.session.commit()

    flash("Deudor eliminado correctamente", "success")
    return redirect(url_for("deudores"))


@app.route("/prestamo/nuevo/<int:deudor_id>", methods=["GET", "POST"])
@login_required
def nuevo_prestamo(deudor_id):
    deudor = deudor_visible_o_404(deudor_id)
    propietario = deudor.propietario
    cuentas = obtener_cuentas_contables(propietario)
    capitales_admin = CapitalPrestamista.query.filter_by(
        prestamista_id=propietario.id,
        estado="disponible",
    ).order_by(CapitalPrestamista.creado_en.desc()).all()

    def mostrar_formulario():
        return render_template(
            "nuevo_prestamo.html",
            deudor=deudor,
            cuentas=cuentas,
            capitales_admin=capitales_admin,
        )

    if request.method == "POST":
        monto = float(request.form.get("monto"))
        numero_cuotas = int(request.form.get("numero_cuotas"))
        dia_pago = int(request.form.get("dia_pago"))
        interes_mensual = float(request.form.get("interes_mensual", 7.0))
        monto_caja = float(request.form.get("monto_caja_menor") or 0)
        monto_banco = float(request.form.get("monto_banco") or 0)
        cuenta_slug = request.form.get("cuenta_desembolso") or "caja_menor"
        origen_capital = request.form.get("origen_capital")
        capital_admin_id = request.form.get("capital_prestamista_id", type=int)
        capital_admin = None

        if monto <= 0:
            flash("El monto del préstamo debe ser mayor a cero.", "error")
            return mostrar_formulario()

        if origen_capital not in ("propio", "administrador"):
            flash("Selecciona si el préstamo usa capital propio o del administrador.", "error")
            return mostrar_formulario()
        if origen_capital == "administrador" and not capital_admin_id:
            flash("Selecciona el capital entregado por el administrador.", "error")
            return mostrar_formulario()
        if origen_capital == "propio":
            capital_admin_id = None

        if numero_cuotas <= 0 or interes_mensual < 0:
            flash("El número de cuotas debe ser mayor a cero y la tasa no puede ser negativa.", "error")
            return mostrar_formulario()

        if capital_admin_id:
            capital_admin = CapitalPrestamista.query.filter_by(
                id=capital_admin_id,
                prestamista_id=propietario.id,
                estado="disponible",
            ).with_for_update().first_or_404()
            if abs(capital_admin.monto - monto) > 0.01:
                flash("El préstamo al cliente debe usar el mismo capital entregado por el administrador.", "error")
                return mostrar_formulario()
            if capital_admin.plazo_meses and capital_admin.plazo_meses != numero_cuotas:
                flash("El número de cuotas debe coincidir con el plazo del capital del administrador.", "error")
                return mostrar_formulario()
            if interes_mensual < capital_admin.tasa_admin:
                flash("La tasa del cliente no puede ser menor que la tasa del administrador.", "error")
                return mostrar_formulario()

        try:
            calculo_cuota = calcular_distribucion_liquidacion(
                capital_inicial=monto,
                numero_cuotas=numero_cuotas,
                tasa_admin=capital_admin.tasa_admin if capital_admin else 0,
                tasa_cliente=interes_mensual,
            )
        except ValueError as error:
            flash(str(error), "error")
            return mostrar_formulario()

        if monto_caja < 0 or monto_banco < 0:
            flash("Los montos de origen no pueden ser negativos.", "error")
            return mostrar_formulario()

        sources = []
        total_fuentes = monto_caja + monto_banco

        if total_fuentes == 0:
            cuenta = obtener_cuenta(cuenta_slug, propietario)

            if not cuenta:
                flash("Selecciona una cuenta válida para el desembolso.", "error")
                return mostrar_formulario()

            sources = [(cuenta, monto)]
        else:
            if abs(total_fuentes - monto) > 0.01:
                flash("La suma de los orígenes debe ser igual al monto total del préstamo.", "error")
                return mostrar_formulario()

            if monto_caja > 0:
                caja = obtener_cuenta("caja_menor", propietario)
                if not caja:
                    flash("No se encontró la cuenta Caja menor.", "error")
                    return mostrar_formulario()
                sources.append((caja, monto_caja))

            if monto_banco > 0:
                banco = obtener_cuenta("banco", propietario)
                if not banco:
                    flash("No se encontró la cuenta Banco.", "error")
                    return mostrar_formulario()
                sources.append((banco, monto_banco))

        for cuenta, cantidad in sources:
            cuenta_bloqueada_actual = cuenta_bloqueada(cuenta.id, propietario.id)
            if not cuenta_bloqueada_actual:
                flash("No se encontró una de las cuentas seleccionadas.", "error")
                db.session.rollback()
                return mostrar_formulario()
            cuenta = cuenta_bloqueada_actual
            if cuenta.saldo < cantidad:
                flash(f"Saldo insuficiente en {cuenta.nombre}: disponible ${cuenta.saldo:,.0f}.", "error")
                db.session.rollback()
                return mostrar_formulario()

        # Sustituir las instancias por sus filas bloqueadas antes de descontar.
        sources = [(cuenta_bloqueada(cuenta.id, propietario.id), cantidad) for cuenta, cantidad in sources]

        prestamo = Prestamo(
            deudor_id=deudor.id,
            monto=monto,
            interes_mensual=interes_mensual,
            numero_cuotas=numero_cuotas,
            dia_pago=dia_pago,
            saldo_capital=monto,
            estado="activo",
            cuenta_desembolso_id=sources[0][0].id if len(sources) == 1 else None,
            capital_prestamista_id=capital_admin.id if capital_admin else None,
        )

        if capital_admin:
            capital_admin.estado = "colocado"

        db.session.add(prestamo)
        db.session.commit()

        for cuenta, cantidad in sources:
            ajustar_saldo_cuenta(
                cuenta,
                -cantidad,
                f"Desembolso préstamo #{prestamo.id}",
                "desembolso",
                prestamo_id=prestamo.id
            )
        db.session.commit()

        capital_cuota = calculo_cuota["capital_mensual"]
        interes_cuota = calculo_cuota["interes_admin"] + calculo_cuota["ganancia_prestamista"]
        total_cuota = calculo_cuota["cuota_cliente"]

        hoy = date.today()

        for i in range(1, numero_cuotas + 1):
            mes = hoy.month + i
            year = hoy.year + (mes - 1) // 12
            month = ((mes - 1) % 12) + 1

            try:
                fecha_vencimiento = date(year, month, dia_pago)
            except ValueError:
                fecha_vencimiento = date(year, month, 28)

            cuota = Cuota(
                prestamo_id=prestamo.id,
                numero=i,
                fecha_vencimiento=fecha_vencimiento,
                capital=capital_cuota,
                interes=interes_cuota,
                total=total_cuota,
                estado="pendiente"
            )

            db.session.add(cuota)

        db.session.commit()

        flash("Préstamo creado correctamente con cuotas mensuales", "success")
        return redirect(url_for("detalle_deudor", deudor_id=deudor.id))

    return mostrar_formulario()


@app.route("/pago/cuota/<int:cuota_id>", methods=["POST"])
@login_required
def pagar_cuota(cuota_id):
    cuota = cuota_visible_o_404(cuota_id)
    db.session.refresh(cuota, with_for_update=True)
    prestamo = cuota.prestamo

    tipo_pago = request.form.get("tipo_pago")
    try:
        monto_d = dinero(request.form.get("monto"))
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
    if monto_d <= 0:
        flash("El monto del pago debe ser mayor a cero.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
    monto = float(monto_d)
    nota = request.form.get("nota")
    cuenta_slug = request.form.get("cuenta_destino") or "caja_menor"
    cuenta_destino = obtener_cuenta(cuenta_slug, prestamo.deudor.propietario)

    if not cuenta_destino:
        flash("Selecciona una cuenta destino válida para este pago.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
    cuenta_destino = cuenta_bloqueada(cuenta_destino.id, prestamo.deudor.usuario_id)

    restante_capital = max(como_float(dinero(cuota.capital) - dinero(cuota.pagado_capital or 0)), 0)
    restante_interes = max(como_float(dinero(cuota.interes) - dinero(cuota.pagado_interes or 0)), 0)
    restante_total = como_float(dinero(restante_capital) + dinero(restante_interes))
    if restante_total <= 0:
        flash("Esta cuota ya no tiene valores pendientes.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

    capital_pagado = 0
    interes_pagado = 0

    if tipo_pago == "cuota_completa":
        if abs(monto - restante_total) > 0.009:
            flash(f"Para pagar la cuota completa debes registrar exactamente ${restante_total:,.2f}.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
        capital_pagado = restante_capital
        interes_pagado = restante_interes

        # Validar que no supere el saldo pendiente del préstamo
        if capital_pagado > prestamo.saldo_capital:
            flash(f"Error: Intenta pagar ${capital_pagado:,.0f} de capital pero solo hay ${prestamo.saldo_capital:,.0f} pendiente.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

        cuota.pagado_capital = cuota.capital
        cuota.pagado_interes = cuota.interes
        cuota.estado = "pagada"

    elif tipo_pago == "solo_interes":
        if restante_interes <= 0:
            flash("El interés de esta cuota ya fue pagado.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
        if abs(monto - restante_interes) > 0.009:
            flash(f"El pago de solo interés debe ser exactamente ${restante_interes:,.2f}.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
        interes_pagado = restante_interes
        cuota.pagado_interes = como_float(dinero(cuota.pagado_interes or 0) + dinero(interes_pagado))
        cuota.estado = "solo_interes"

        def avanzar_mes(fecha, meses=1):
            total_meses = fecha.month - 1 + meses
            year = fecha.year + total_meses // 12
            month = total_meses % 12 + 1
            day = fecha.day
            last_day = monthrange(year, month)[1]
            if day > last_day:
                day = last_day
            return date(year, month, day)

        cuotas_restantes = Cuota.query.filter(
            Cuota.prestamo_id == prestamo.id,
            Cuota.numero >= cuota.numero
        ).order_by(Cuota.numero.asc()).all()

        nueva = avanzar_mes(cuota.fecha_vencimiento, 1)

        for c in cuotas_restantes:
            c.fecha_vencimiento = nueva
            nueva = avanzar_mes(nueva, 1)

    elif tipo_pago == "abono_capital":
        capital_pagado = monto
        
        # Validar que no supere el saldo pendiente del préstamo
        if capital_pagado > restante_capital or capital_pagado > prestamo.saldo_capital:
            flash(f"Error: Intenta pagar ${capital_pagado:,.0f} de capital pero solo hay ${prestamo.saldo_capital:,.0f} pendiente.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
        
        cuota.pagado_capital = como_float(dinero(cuota.pagado_capital or 0) + dinero(capital_pagado))
        cuota.estado = "pagada" if cuota.pagado_capital >= cuota.capital and cuota.pagado_interes >= cuota.interes else "parcial"

    elif tipo_pago == "abono_parcial":
        if monto > restante_total:
            flash(f"El abono no puede superar el pendiente de la cuota (${restante_total:,.2f}).", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

        if monto <= restante_interes:
            interes_pagado = monto
            cuota.pagado_interes += monto
        else:
            interes_pagado = restante_interes
            capital_pagado = monto - restante_interes
            
            # Validar que el capital a pagar no supere el saldo del préstamo
            if capital_pagado > prestamo.saldo_capital:
                flash(f"Error: Intenta pagar ${capital_pagado:,.0f} de capital pero solo hay ${prestamo.saldo_capital:,.0f} pendiente.", "error")
                return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
            
            cuota.pagado_interes = cuota.interes
            cuota.pagado_capital += capital_pagado

        cuota.estado = "parcial"

        if cuota.pagado_capital >= cuota.capital and cuota.pagado_interes >= cuota.interes:
            cuota.estado = "pagada"
    else:
        flash("Selecciona un tipo de pago válido.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

    capital_pagado = como_float(capital_pagado)
    interes_pagado = como_float(interes_pagado)
    if abs(monto - como_float(dinero(capital_pagado) + dinero(interes_pagado))) > 0.009:
        flash("El monto debe coincidir con la suma aplicada a capital e interés.", "error")
        db.session.rollback()
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

    pago = Pago(
        prestamo_id=prestamo.id,
        cuota_id=cuota.id,
        tipo_pago=tipo_pago,
        monto=monto,
        capital_pagado=capital_pagado,
        interes_pagado=interes_pagado,
        nota=nota,
        cuenta_destino_id=cuenta_destino.id
    )

    db.session.add(pago)
    db.session.flush()

    ajustar_saldo_cuenta(
        cuenta_destino,
        monto,
        f"Pago de préstamo #{prestamo.id}",
        "deposito",
        prestamo_id=prestamo.id,
        pago_id=pago.id
    )

    # Recalcular saldo y estado del préstamo desde cero
    recalcular_prestamo(prestamo)

    db.session.commit()

    flash("Pago registrado correctamente", "success")
    return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))


@app.route("/cuota/editar/<int:cuota_id>", methods=["GET", "POST"])
@login_required
def editar_cuota(cuota_id):
    cuota = cuota_visible_o_404(cuota_id)
    if cuota.liquidado:
        flash("Una cuota liquidada no puede modificarse.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=cuota.prestamo_id))
    if cuota.prestamo.capital_administrador:
        flash("Las cuotas financiadas con capital del administrador no pueden editarse manualmente.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=cuota.prestamo_id))
    pagos_existentes = Pago.query.filter_by(cuota_id=cuota.id).count()

    if pagos_existentes > 0:
        flash("No se puede editar esta cuota porque ya tiene pagos registrados.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=cuota.prestamo_id))

    if request.method == "POST":
        cuota.fecha_vencimiento = date.fromisoformat(request.form.get("fecha_vencimiento"))
        cuota.capital = float(request.form.get("capital"))
        cuota.interes = float(request.form.get("interes"))
        cuota.total = cuota.capital + cuota.interes
        cuota.estado = "pendiente"
        # pagado_capital / pagado_interes se quedan en 0
        # (bloqueamos edición si ya hay pagos)

        prestamo = cuota.prestamo

        # Recalcular monto del préstamo como suma de capitales de todas las cuotas
        prestamo.monto = sum(c.capital for c in prestamo.cuotas)
        prestamo.numero_cuotas = len(prestamo.cuotas)

        recalcular_prestamo(prestamo)

        db.session.commit()
        flash("Cuota actualizada y saldos recalculados correctamente", "success")
        return redirect(url_for("detalle_prestamo", prestamo_id=cuota.prestamo_id))

    return render_template("editar_cuota.html", cuota=cuota)


@app.route("/prestamo/<int:prestamo_id>")
@login_required
def detalle_prestamo(prestamo_id):
    prestamo = prestamo_visible_o_404(prestamo_id)

    show_all = request.args.get("show_all") == "1"

    if show_all:
        cuotas = Cuota.query.filter_by(
            prestamo_id=prestamo.id
        ).order_by(Cuota.numero.asc()).all()
    else:
        cuotas = Cuota.query.filter(
            Cuota.prestamo_id == prestamo.id,
            Cuota.estado != "pagada"
        ).order_by(Cuota.numero.asc()).all()

    pagos = Pago.query.filter_by(
        prestamo_id=prestamo.id
    ).order_by(Pago.fecha_pago.desc()).all()

    return render_template(
        "detalle_prestamo.html",
        prestamo=prestamo,
        cuotas=cuotas,
        pagos=pagos,
        cuentas=obtener_cuentas_contables(prestamo.deudor.propietario)
    )


@app.route("/pago/editar/<int:pago_id>", methods=["GET", "POST"])
@login_required
def editar_pago(pago_id):
    pago = pago_visible_o_404(pago_id)
    db.session.refresh(pago, with_for_update=True)
    prestamo = pago.prestamo
    cuota = pago.cuota

    if cuota and cuota.liquidado:
        flash("El pago no puede editarse porque su cuota ya fue liquidada.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

    if request.method == "POST":
        try:
            monto_nuevo = dinero(request.form.get("monto"))
            capital_nuevo = dinero(request.form.get("capital_pagado", 0))
            interes_nuevo = dinero(request.form.get("interes_pagado", 0))
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("editar_pago", pago_id=pago.id))
        if monto_nuevo <= 0 or capital_nuevo < 0 or interes_nuevo < 0:
            flash("Los valores del pago no pueden ser negativos y el total debe ser mayor a cero.", "error")
            return redirect(url_for("editar_pago", pago_id=pago.id))
        if monto_nuevo != capital_nuevo + interes_nuevo:
            flash("El monto total debe ser igual a capital más interés.", "error")
            return redirect(url_for("editar_pago", pago_id=pago.id))

        cuenta = cuenta_bloqueada(pago.cuenta_destino_id, prestamo.deudor.usuario_id)
        movimiento = CuentaMovimiento.query.filter_by(pago_id=pago.id).with_for_update().first()
        if not cuenta or not movimiento:
            flash("No se encontró el movimiento contable asociado; el pago no fue modificado.", "error")
            db.session.rollback()
            return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))
        diferencia = monto_nuevo - dinero(pago.monto)
        if dinero(cuenta.saldo or 0) + diferencia < 0:
            flash("La cuenta no tiene saldo suficiente para reducir este pago.", "error")
            db.session.rollback()
            return redirect(url_for("editar_pago", pago_id=pago.id))

        pago.monto = float(monto_nuevo)
        pago.capital_pagado = float(capital_nuevo)
        pago.interes_pagado = float(interes_nuevo)
        pago.nota = request.form.get("nota")

        # Reconstruir pagado_capital y pagado_interes de la cuota
        # sumando TODOS sus pagos (incluyendo el que acabamos de editar)
        if cuota:
            todos_pagos = Pago.query.filter_by(cuota_id=cuota.id).all()

            cuota.pagado_capital = sum(p.capital_pagado or 0 for p in todos_pagos)
            cuota.pagado_interes = sum(p.interes_pagado or 0 for p in todos_pagos)

            # Validar que no se superen los límites de la cuota
            if cuota.pagado_capital > cuota.capital:
                flash(f"Error: Intenta pagar ${cuota.pagado_capital:,.0f} de capital pero la cuota solo es ${cuota.capital:,.0f}.", "error")
                return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

            if cuota.pagado_interes > cuota.interes:
                flash(f"Error: Intenta pagar ${cuota.pagado_interes:,.0f} de interés pero la cuota solo es ${cuota.interes:,.0f}.", "error")
                return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

            cuenta.saldo = como_float(dinero(cuenta.saldo or 0) + diferencia)
            movimiento.monto = float(monto_nuevo)

            # Normalizar por si los valores superan lo esperado
            cuota.pagado_capital = min(cuota.pagado_capital, cuota.capital)
            cuota.pagado_interes = min(cuota.pagado_interes, cuota.interes)

            # Recalcular estado de la cuota
            if cuota.pagado_capital >= cuota.capital and cuota.pagado_interes >= cuota.interes:
                cuota.estado = "pagada"
            elif cuota.pagado_capital == 0 and cuota.pagado_interes > 0:
                cuota.estado = "solo_interes"
            elif cuota.pagado_capital > 0 or cuota.pagado_interes > 0:
                cuota.estado = "parcial"
            else:
                cuota.estado = "pendiente"

        # Recalcular saldo y estado del préstamo desde cero
        recalcular_prestamo(prestamo)

        db.session.commit()
        flash("Pago actualizado y saldos recalculados correctamente", "success")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

    return render_template("editar_pago.html", pago=pago)


@app.route("/prestamo/editar/<int:prestamo_id>", methods=["GET", "POST"])
@login_required
def editar_prestamo(prestamo_id):
    prestamo = prestamo_visible_o_404(prestamo_id)

    if request.method == "POST":
        monto_nuevo = float(request.form.get("monto"))
        numero_cuotas_nuevo = int(request.form.get("numero_cuotas"))
        dia_pago = int(request.form.get("dia_pago"))
        interes_mensual = float(request.form.get("interes_mensual", prestamo.interes_mensual))

        pagos_existentes = Pago.query.filter_by(prestamo_id=prestamo.id).count()

        cambia_estructura = (
            monto_nuevo != prestamo.monto or
            numero_cuotas_nuevo != prestamo.numero_cuotas
        )

        if prestamo.capital_administrador:
            capital_admin = prestamo.capital_administrador
            if abs(monto_nuevo - capital_admin.monto) > 0.01 or numero_cuotas_nuevo != capital_admin.plazo_meses:
                flash("Monto y plazo deben conservar el acuerdo de capital del administrador.", "error")
                return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))
            if interes_mensual < capital_admin.tasa_admin:
                flash("La tasa del cliente no puede ser menor que la tasa del administrador.", "error")
                return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

        if pagos_existentes > 0 and cambia_estructura:
            flash(
                "No se puede cambiar monto o número de cuotas porque ya existen pagos registrados.",
                "error"
            )
            return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

        prestamo.interes_mensual = interes_mensual
        prestamo.dia_pago = dia_pago

        if pagos_existentes == 0:
            # Reconstruir cuotas desde cero
            prestamo.monto = monto_nuevo
            prestamo.numero_cuotas = numero_cuotas_nuevo

            Cuota.query.filter_by(prestamo_id=prestamo.id).delete()

            capital_cuota = monto_nuevo / numero_cuotas_nuevo
            interes_cuota = monto_nuevo * (interes_mensual / 100)
            total_cuota = capital_cuota + interes_cuota
            hoy = date.today()

            for i in range(1, numero_cuotas_nuevo + 1):
                mes = hoy.month + i
                year = hoy.year + (mes - 1) // 12
                month = ((mes - 1) % 12) + 1

                try:
                    fecha_vencimiento = date(year, month, dia_pago)
                except ValueError:
                    fecha_vencimiento = date(year, month, 28)

                db.session.add(Cuota(
                    prestamo_id=prestamo.id,
                    numero=i,
                    fecha_vencimiento=fecha_vencimiento,
                    capital=capital_cuota,
                    interes=interes_cuota,
                    total=total_cuota,
                    estado="pendiente"
                ))

            db.session.flush()  # para que prestamo.cuotas esté actualizado antes de recalcular

        else:
            # Solo cambió interés o día de pago:
            # actualizar interés en cuotas que aún no están pagadas
            for c in prestamo.cuotas:
                if c.estado not in ("pagada",):
                    c.interes = prestamo.monto * (interes_mensual / 100)
                    c.total = c.capital + c.interes

        recalcular_prestamo(prestamo)

        db.session.commit()
        flash("Préstamo actualizado y saldos recalculados correctamente", "success")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))

    return render_template("nuevo_prestamo.html", deudor=prestamo.deudor, prestamo=prestamo, cuentas=obtener_cuentas_contables(prestamo.deudor.propietario))


@app.route("/notificaciones")
@login_required
def notificaciones():
    hoy, manana, cuotas_urgentes = obtener_cuotas_urgentes()

    cuotas_manana = [c for c in cuotas_urgentes if c.fecha_vencimiento == manana]
    cuotas_vencidas = [c for c in cuotas_urgentes if c.fecha_vencimiento <= hoy and c.fecha_vencimiento != manana]

    def construir_avisos(cuotas):
        deudores_map = {}

        for cuota in cuotas:
            prestamo = cuota.prestamo
            deudor = prestamo.deudor

            if deudor.id not in deudores_map:
                deudores_map[deudor.id] = {
                    "deudor": deudor,
                    "cuotas": [],
                    "monto_cobrar": 0,
                    "cuotas_pendientes": sum(
                        1 for p in deudor.prestamos
                        for c in p.cuotas
                        if c.estado not in ("pagada",)
                    ),
                    "saldo_total": sum(
                        p.saldo_capital for p in deudor.prestamos
                    ),
                    "prioridad": "baja",
                }

            deudores_map[deudor.id]["cuotas"].append(cuota)
            pendiente_cuota = (cuota.capital - cuota.pagado_capital) + (cuota.interes - cuota.pagado_interes)
            deudores_map[deudor.id]["monto_cobrar"] += pendiente_cuota

            if cuota.fecha_vencimiento < hoy:
                deudores_map[deudor.id]["prioridad"] = "alta"
            elif cuota.fecha_vencimiento == hoy:
                deudores_map[deudor.id]["prioridad"] = "media"
            elif cuota.fecha_vencimiento == manana:
                deudores_map[deudor.id]["prioridad"] = "baja"

        avisos = list(deudores_map.values())
        avisos.sort(key=lambda aviso: {"alta": 0, "media": 1, "baja": 2}[aviso["prioridad"]])
        return avisos

    avisos_manana = construir_avisos(cuotas_manana)
    avisos_vencidas = construir_avisos(cuotas_vencidas)

    return render_template(
        "notificaciones.html",
        avisos_manana=avisos_manana,
        avisos_vencidas=avisos_vencidas,
        manana=manana,
        hoy=hoy,
    )


@app.route("/prestamo/refinanciar/<int:prestamo_id>", methods=["GET", "POST"])
@login_required
def refinanciar_prestamo(prestamo_id):
    prestamo_anterior = prestamo_visible_o_404(prestamo_id)
    deudor = prestamo_anterior.deudor

    if prestamo_anterior.capital_administrador:
        flash("Un préstamo con capital del administrador no puede refinanciarse desde este flujo.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo_id))

    if prestamo_anterior.estado in ("pagado", "refinanciado"):
        flash("Este préstamo no puede refinanciarse.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo_id))

    if request.method == "POST":
        try:
            monto_nuevo = como_float(request.form.get("monto"))
            numero_cuotas = int(request.form.get("numero_cuotas"))
            dia_pago = int(request.form.get("dia_pago"))
            interes_mensual = float(request.form.get("interes_mensual", 7.0))
        except (ValueError, TypeError):
            flash("Revisa el monto, las cuotas, la tasa y el día de pago.", "error")
            return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor, cuentas=obtener_cuentas_contables(deudor.propietario))

        if monto_nuevo <= 0 or numero_cuotas <= 0 or not 1 <= dia_pago <= 31 or not 0 <= interes_mensual <= 100:
            flash("Los datos del refinanciamiento no son válidos.", "error")
            return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor, cuentas=obtener_cuentas_contables(deudor.propietario))

        saldo_pendiente = prestamo_anterior.saldo_capital

        if monto_nuevo < saldo_pendiente:
            flash(
                f"El nuevo monto (${monto_nuevo:,.0f}) debe ser mayor o igual "
                f"al saldo pendiente (${saldo_pendiente:,.0f}).",
                "error"
            )
            return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor, cuentas=obtener_cuentas_contables(deudor.propietario))

        efectivo = como_float(dinero(monto_nuevo) - dinero(saldo_pendiente))
        cuenta = None
        if efectivo > 0:
            cuenta_slug = request.form.get("cuenta_desembolso")
            cuenta_encontrada = obtener_cuenta(cuenta_slug, deudor.propietario)
            if not cuenta_encontrada:
                flash("Selecciona una cuenta válida para entregar el dinero adicional.", "error")
                return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor, cuentas=obtener_cuentas_contables(deudor.propietario))
            cuenta = cuenta_bloqueada(cuenta_encontrada.id, deudor.usuario_id)
            if dinero(cuenta.saldo or 0) < dinero(efectivo):
                flash(f"Saldo insuficiente en {cuenta.nombre}: disponible ${cuenta.saldo:,.2f}.", "error")
                db.session.rollback()
                return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor, cuentas=obtener_cuentas_contables(deudor.propietario))

        # Cerrar la obligación anterior sin inventar pagos ni recaudos.
        for cuota in prestamo_anterior.cuotas:
            if cuota.estado != "pagada":
                cuota.estado = "refinanciada"

        prestamo_anterior.saldo_capital = 0
        prestamo_anterior.estado = "refinanciado"

        # Crear nuevo préstamo
        nuevo_prestamo = Prestamo(
            deudor_id=deudor.id,
            monto=monto_nuevo,
            interes_mensual=interes_mensual,
            numero_cuotas=numero_cuotas,
            dia_pago=dia_pago,
            saldo_capital=monto_nuevo,
            estado="activo"
        )
        db.session.add(nuevo_prestamo)
        db.session.flush()

        if cuenta and efectivo > 0:
            ajustar_saldo_cuenta(
                cuenta,
                -efectivo,
                f"Efectivo adicional refinanciación #{prestamo_anterior.id} → #{nuevo_prestamo.id}",
                "refinanciacion",
                prestamo_id=nuevo_prestamo.id,
            )

        capital_cuota = monto_nuevo / numero_cuotas
        interes_cuota = monto_nuevo * (interes_mensual / 100)
        total_cuota = capital_cuota + interes_cuota
        hoy = date.today()

        for i in range(1, numero_cuotas + 1):
            mes = hoy.month + i
            year = hoy.year + (mes - 1) // 12
            month = ((mes - 1) % 12) + 1
            try:
                fecha_vencimiento = date(year, month, dia_pago)
            except ValueError:
                fecha_vencimiento = date(year, month, 28)

            db.session.add(Cuota(
                prestamo_id=nuevo_prestamo.id,
                numero=i,
                fecha_vencimiento=fecha_vencimiento,
                capital=capital_cuota,
                interes=interes_cuota,
                total=total_cuota,
                estado="pendiente"
            ))

        db.session.commit()

        flash(
            f"Refinanciamiento exitoso. Saldo absorbido: ${saldo_pendiente:,.0f}. "
            f"Efectivo entregado al cliente: ${efectivo:,.0f}. "
            f"Nuevo préstamo #{nuevo_prestamo.id} por ${monto_nuevo:,.0f}.",
            "success"
        )
        return redirect(url_for("detalle_deudor", deudor_id=deudor.id))

    return render_template(
        "refinanciar_prestamo.html",
        prestamo=prestamo_anterior,
        deudor=deudor,
        cuentas=obtener_cuentas_contables(deudor.propietario),
    )


@app.route("/prestamo/eliminar/<int:prestamo_id>", methods=["POST"])
@login_required
def eliminar_prestamo(prestamo_id):
    prestamo = prestamo_visible_o_404(prestamo_id)
    deudor_id = prestamo.deudor_id

    tiene_movimientos = CuentaMovimiento.query.filter_by(prestamo_id=prestamo.id).first() is not None
    if prestamo.pagos or tiene_movimientos or any(cuota.liquidado for cuota in prestamo.cuotas):
        flash("No se puede eliminar un préstamo con pagos o movimientos contables. Conserva el historial financiero.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo.id))
    if prestamo.capital_administrador:
        prestamo.capital_administrador.estado = "disponible"

    db.session.delete(prestamo)
    db.session.commit()

    flash("Préstamo eliminado correctamente", "success")
    return redirect(url_for("detalle_deudor", deudor_id=deudor_id))


if __name__ == "__main__":
    with app.app_context():
        asegurar_esquema()
        crear_admin()
        asignar_datos_existentes_al_admin()

    app.run(debug=True)
