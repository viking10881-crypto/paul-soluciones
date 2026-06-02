import os
from datetime import date
from calendar import monthrange
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from models import db, Usuario, Deudor, Prestamo, Cuota, Pago

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "clave-secreta-dev")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///prestamos_paul.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


def crear_admin():
    admin = Usuario.query.filter_by(usuario="admin").first()

    if not admin:
        nuevo_admin = Usuario(
            nombre="Administrador",
            usuario="admin",
            password_hash=generate_password_hash("admin123")
        )

        db.session.add(nuevo_admin)
        db.session.commit()

        print("✅ Usuario admin creado: admin / admin123")


def actualizar_cuotas_vencidas():
    hoy = date.today()

    cuotas_vencidas = Cuota.query.filter(
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

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Usuario o contraseña incorrectos", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    actualizar_cuotas_vencidas()

    deudores = Deudor.query.count()

    prestamos = Prestamo.query.all()

    pagos = Pago.query.all()

    total_prestado = sum(p.monto for p in prestamos)

    capital_pendiente = sum(p.saldo_capital for p in prestamos)

    total_pagado = sum(p.monto for p in pagos)

    intereses_ganados = sum(p.interes_pagado for p in pagos)

    prestamos_activos = Prestamo.query.filter_by(
        estado="activo"
    ).count()

    prestamos_pagados = Prestamo.query.filter_by(
        estado="pagado"
    ).count()

    prestamos_atrasados = Prestamo.query.filter_by(
        estado="atrasado"
    ).count()

    return render_template(
        "dashboard.html",
        deudores=deudores,
        total_prestado=total_prestado,
        capital_pendiente=capital_pendiente,
        total_pagado=total_pagado,
        intereses_ganados=intereses_ganados,
        prestamos_activos=prestamos_activos,
        prestamos_pagados=prestamos_pagados,
        prestamos_atrasados=prestamos_atrasados
    )


@app.route("/deudores")
@login_required
def deudores():
    lista = Deudor.query.order_by(Deudor.creado_en.desc()).all()
    return render_template("deudores.html", deudores=lista)


@app.route("/deudores/nuevo", methods=["GET", "POST"])
@login_required
def nuevo_deudor():
    if request.method == "POST":
        deudor = Deudor(
            nombre=request.form.get("nombre"),
            cedula=request.form.get("cedula"),
            telefono=request.form.get("telefono"),
            direccion=request.form.get("direccion"),
            correo=request.form.get("correo"),
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
    deudor = Deudor.query.get_or_404(deudor_id)
    return render_template("detalle_deudor.html", deudor=deudor)


@app.route("/deudores/editar/<int:deudor_id>", methods=["GET", "POST"])
@login_required
def editar_deudor(deudor_id):
    deudor = Deudor.query.get_or_404(deudor_id)

    if request.method == "POST":
        deudor.nombre = request.form.get("nombre")
        deudor.cedula = request.form.get("cedula")
        deudor.telefono = request.form.get("telefono")
        deudor.direccion = request.form.get("direccion")
        deudor.correo = request.form.get("correo")
        deudor.referencia = request.form.get("referencia")
        deudor.nota = request.form.get("nota")

        db.session.commit()

        flash("Deudor actualizado correctamente", "success")
        return redirect(url_for("deudores"))

    return render_template("nuevo_deudor.html", deudor=deudor)


@app.route("/deudores/eliminar/<int:deudor_id>", methods=["POST"])
@login_required
def eliminar_deudor(deudor_id):
    deudor = Deudor.query.get_or_404(deudor_id)

    db.session.delete(deudor)
    db.session.commit()

    flash("Deudor eliminado correctamente", "success")
    return redirect(url_for("deudores"))


@app.route("/prestamo/nuevo/<int:deudor_id>", methods=["GET", "POST"])
@login_required
def nuevo_prestamo(deudor_id):
    deudor = Deudor.query.get_or_404(deudor_id)

    if request.method == "POST":
        monto = float(request.form.get("monto"))
        numero_cuotas = int(request.form.get("numero_cuotas"))
        dia_pago = int(request.form.get("dia_pago"))
        interes_mensual = float(request.form.get("interes_mensual", 7.0))

        prestamo = Prestamo(
            deudor_id=deudor.id,
            monto=monto,
            interes_mensual=interes_mensual,
            numero_cuotas=numero_cuotas,
            dia_pago=dia_pago,
            saldo_capital=monto,
            estado="activo"
        )

        db.session.add(prestamo)
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

    return render_template("nuevo_prestamo.html", deudor=deudor)


@app.route("/pago/cuota/<int:cuota_id>", methods=["POST"])
@login_required
def pagar_cuota(cuota_id):
    cuota = Cuota.query.get_or_404(cuota_id)
    prestamo = cuota.prestamo

    tipo_pago = request.form.get("tipo_pago")
    monto = float(request.form.get("monto"))
    nota = request.form.get("nota")

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
        nota=nota
    )

    db.session.add(pago)

    # Recalcular saldo y estado del préstamo desde cero
    recalcular_prestamo(prestamo)

    db.session.commit()

    flash("Pago registrado correctamente", "success")
    return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))


@app.route("/cuota/editar/<int:cuota_id>", methods=["GET", "POST"])
@login_required
def editar_cuota(cuota_id):
    cuota = Cuota.query.get_or_404(cuota_id)
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
    prestamo = Prestamo.query.get_or_404(prestamo_id)

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
        pagos=pagos
    )


@app.route("/pago/editar/<int:pago_id>", methods=["GET", "POST"])
@login_required
def editar_pago(pago_id):
    pago = Pago.query.get_or_404(pago_id)
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
    prestamo = Prestamo.query.get_or_404(prestamo_id)

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

    return render_template("nuevo_prestamo.html", deudor=prestamo.deudor, prestamo=prestamo)


@app.route("/prestamo/eliminar/<int:prestamo_id>", methods=["POST"])
@login_required
def eliminar_prestamo(prestamo_id):
    prestamo = Prestamo.query.get_or_404(prestamo_id)
    deudor_id = prestamo.deudor_id

    db.session.delete(prestamo)
    db.session.commit()

    flash("Préstamo eliminado correctamente", "success")
    return redirect(url_for("detalle_deudor", deudor_id=deudor_id))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        crear_admin()

    app.run(debug=True)