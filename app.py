import os
from datetime import date
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
        cuota.pagado_capital = cuota.capital
        cuota.pagado_interes = cuota.interes
        cuota.estado = "pagada"
        prestamo.saldo_capital -= capital_pagado

    elif tipo_pago == "solo_interes":
        interes_pagado = cuota.interes
        cuota.pagado_interes += interes_pagado
        cuota.estado = "solo_interes"

    elif tipo_pago == "abono_capital":
        capital_pagado = monto
        prestamo.saldo_capital -= capital_pagado

    elif tipo_pago == "abono_parcial":
        restante_interes = cuota.interes - cuota.pagado_interes

        if monto <= restante_interes:
            interes_pagado = monto
            cuota.pagado_interes += monto
        else:
            interes_pagado = restante_interes
            capital_pagado = monto - restante_interes
            cuota.pagado_interes = cuota.interes
            cuota.pagado_capital += capital_pagado
            prestamo.saldo_capital -= capital_pagado

        cuota.estado = "parcial"

        if cuota.pagado_capital >= cuota.capital and cuota.pagado_interes >= cuota.interes:
            cuota.estado = "pagada"

    if prestamo.saldo_capital <= 0:
        prestamo.saldo_capital = 0
        prestamo.estado = "pagado"

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
    db.session.commit()

    flash("Pago registrado correctamente", "success")
    return redirect(url_for("detalle_deudor", deudor_id=prestamo.deudor_id))

@app.route("/prestamo/<int:prestamo_id>")
@login_required
def detalle_prestamo(prestamo_id):
    prestamo = Prestamo.query.get_or_404(prestamo_id)

    cuotas = Cuota.query.filter_by(
        prestamo_id=prestamo.id
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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        crear_admin()

    app.run(debug=True)