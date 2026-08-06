import os
import hmac
import secrets
from functools import wraps
from types import SimpleNamespace
from datetime import date, timedelta
from calendar import monthrange
from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
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
)

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

    if not caja:
        caja = CuentaContable(nombre="Caja menor", slug=f"caja_menor{sufijo}", saldo=0.0, usuario_id=usuario.id)
        db.session.add(caja)

    if not banco:
        banco = CuentaContable(nombre="Banco", slug=f"banco{sufijo}", saldo=0.0, usuario_id=usuario.id)
        db.session.add(banco)

    if not caja.id or not banco.id:
        db.session.commit()

    return [caja, banco]


def obtener_cuenta(slug, usuario=None):
    usuario = usuario or current_user
    cuenta = CuentaContable.query.filter_by(usuario_id=usuario.id, slug=slug).first()
    if cuenta:
        return cuenta
    sufijo = "" if usuario.es_admin else f"_{usuario.id}"
    return CuentaContable.query.filter_by(usuario_id=usuario.id, slug=f"{slug}{sufijo}").first()


def ajustar_saldo_cuenta(cuenta, monto, descripcion, tipo, prestamo_id=None, pago_id=None):
    cuenta.saldo = (cuenta.saldo or 0) + monto

    movimiento = CuentaMovimiento(
        cuenta_id=cuenta.id,
        prestamo_id=prestamo_id,
        pago_id=pago_id,
        tipo=tipo,
        monto=monto,
        descripcion=descripcion,
    )

    db.session.add(movimiento)


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
        cuentas = obtener_cuentas_contables()

    if request.method == "POST":
        cuenta_id = int(request.form.get("cuenta_id"))
        monto = float(request.form.get("monto"))
        descripcion = request.form.get("descripcion") or "Inyección de capital"

        if monto <= 0:
            flash("El monto debe ser mayor a cero.", "error")
            return redirect(url_for("cuentas"))

        cuenta = CuentaContable.query.get_or_404(cuenta_id)
        if not current_user.es_admin and cuenta.usuario_id != current_user.id:
            abort(404)
        ajustar_saldo_cuenta(
            cuenta,
            monto,
            descripcion,
            "inyeccion"
        )
        db.session.commit()

        flash(f"Se agregó ${monto:,.0f} a {cuenta.nombre}.", "success")
        return redirect(url_for("cuentas"))

    return render_template("cuentas.html", cuentas=cuentas)


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
    return render_template("detalle_deudor.html", deudor=deudor)


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

    if request.method == "POST":
        monto = float(request.form.get("monto"))
        numero_cuotas = int(request.form.get("numero_cuotas"))
        dia_pago = int(request.form.get("dia_pago"))
        interes_mensual = float(request.form.get("interes_mensual", 7.0))
        monto_caja = float(request.form.get("monto_caja_menor") or 0)
        monto_banco = float(request.form.get("monto_banco") or 0)
        cuenta_slug = request.form.get("cuenta_desembolso") or "caja_menor"

        if monto <= 0:
            flash("El monto del préstamo debe ser mayor a cero.", "error")
            return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)

        if monto_caja < 0 or monto_banco < 0:
            flash("Los montos de origen no pueden ser negativos.", "error")
            return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)

        sources = []
        total_fuentes = monto_caja + monto_banco

        if total_fuentes == 0:
            cuenta = obtener_cuenta(cuenta_slug, propietario)

            if not cuenta:
                flash("Selecciona una cuenta válida para el desembolso.", "error")
                return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)

            sources = [(cuenta, monto)]
        else:
            if abs(total_fuentes - monto) > 0.01:
                flash("La suma de los orígenes debe ser igual al monto total del préstamo.", "error")
                return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)

            if monto_caja > 0:
                caja = obtener_cuenta("caja_menor", propietario)
                if not caja:
                    flash("No se encontró la cuenta Caja menor.", "error")
                    return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)
                sources.append((caja, monto_caja))

            if monto_banco > 0:
                banco = obtener_cuenta("banco", propietario)
                if not banco:
                    flash("No se encontró la cuenta Banco.", "error")
                    return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)
                sources.append((banco, monto_banco))

        for cuenta, cantidad in sources:
            if cuenta.saldo < cantidad:
                flash(f"Saldo insuficiente en {cuenta.nombre}: disponible ${cuenta.saldo:,.0f}.", "error")
                return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)

        prestamo = Prestamo(
            deudor_id=deudor.id,
            monto=monto,
            interes_mensual=interes_mensual,
            numero_cuotas=numero_cuotas,
            dia_pago=dia_pago,
            saldo_capital=monto,
            estado="activo",
            cuenta_desembolso_id=sources[0][0].id if len(sources) == 1 else None
        )

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

        capital_cuota = monto / numero_cuotas
        interes_cuota = monto * (interes_mensual / 100)
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

    return render_template("nuevo_prestamo.html", deudor=deudor, cuentas=cuentas)


@app.route("/pago/cuota/<int:cuota_id>", methods=["POST"])
@login_required
def pagar_cuota(cuota_id):
    cuota = cuota_visible_o_404(cuota_id)
    prestamo = cuota.prestamo

    tipo_pago = request.form.get("tipo_pago")
    monto = float(request.form.get("monto"))
    nota = request.form.get("nota")
    cuenta_slug = request.form.get("cuenta_destino") or "caja_menor"
    cuenta_destino = obtener_cuenta(cuenta_slug, prestamo.deudor.propietario)

    if not cuenta_destino:
        flash("Selecciona una cuenta destino válida para este pago.", "error")
        return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

    capital_pagado = 0
    interes_pagado = 0

    if tipo_pago == "cuota_completa":
        capital_pagado = cuota.capital - cuota.pagado_capital
        interes_pagado = cuota.interes - cuota.pagado_interes

        # Validar que no supere el saldo pendiente del préstamo
        if capital_pagado > prestamo.saldo_capital:
            flash(f"Error: Intenta pagar ${capital_pagado:,.0f} de capital pero solo hay ${prestamo.saldo_capital:,.0f} pendiente.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

        cuota.pagado_capital = cuota.capital
        cuota.pagado_interes = cuota.interes
        cuota.estado = "pagada"

    elif tipo_pago == "solo_interes":
        interes_pagado = cuota.interes
        cuota.pagado_interes += interes_pagado
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
        if capital_pagado > prestamo.saldo_capital:
            flash(f"Error: Intenta pagar ${capital_pagado:,.0f} de capital pero solo hay ${prestamo.saldo_capital:,.0f} pendiente.", "error")
            return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))
        
        cuota.pagado_capital += capital_pagado
        if cuota.pagado_capital > cuota.capital:
            cuota.pagado_capital = cuota.capital

    elif tipo_pago == "abono_parcial":
        restante_interes = cuota.interes - cuota.pagado_interes

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
    prestamo = pago.prestamo
    cuota = pago.cuota

    if request.method == "POST":
        pago.monto = float(request.form.get("monto"))
        pago.capital_pagado = float(request.form.get("capital_pagado", 0))
        pago.interes_pagado = float(request.form.get("interes_pagado", 0))
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

    if prestamo_anterior.estado in ("pagado", "refinanciado"):
        flash("Este préstamo no puede refinanciarse.", "error")
        return redirect(url_for("detalle_prestamo", prestamo_id=prestamo_id))

    if request.method == "POST":
        monto_nuevo = float(request.form.get("monto"))
        numero_cuotas = int(request.form.get("numero_cuotas"))
        dia_pago = int(request.form.get("dia_pago"))
        interes_mensual = float(request.form.get("interes_mensual", 7.0))

        saldo_pendiente = prestamo_anterior.saldo_capital

        if monto_nuevo < saldo_pendiente:
            flash(
                f"El nuevo monto (${monto_nuevo:,.0f}) debe ser mayor o igual "
                f"al saldo pendiente (${saldo_pendiente:,.0f}).",
                "error"
            )
            return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor)

        # Cerrar préstamo anterior
        for cuota in prestamo_anterior.cuotas:
            if cuota.estado != "pagada":
                cuota.pagado_capital = cuota.capital
                cuota.pagado_interes = cuota.interes
                cuota.estado = "pagada"

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

        efectivo = monto_nuevo - saldo_pendiente
        flash(
            f"Refinanciamiento exitoso. Saldo absorbido: ${saldo_pendiente:,.0f}. "
            f"Efectivo entregado al cliente: ${efectivo:,.0f}. "
            f"Nuevo préstamo #{nuevo_prestamo.id} por ${monto_nuevo:,.0f}.",
            "success"
        )
        return redirect(url_for("detalle_deudor", deudor_id=deudor.id))

    return render_template("refinanciar_prestamo.html", prestamo=prestamo_anterior, deudor=deudor)


@app.route("/prestamo/eliminar/<int:prestamo_id>", methods=["POST"])
@login_required
def eliminar_prestamo(prestamo_id):
    prestamo = prestamo_visible_o_404(prestamo_id)
    deudor_id = prestamo.deudor_id

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
