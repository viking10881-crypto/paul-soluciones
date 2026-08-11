from decimal import Decimal, ROUND_HALF_UP


CENTAVOS = Decimal("0.01")


def dinero(valor):
    return Decimal(str(valor or 0)).quantize(CENTAVOS, rounding=ROUND_HALF_UP)


def calcular_distribucion_liquidacion(
    capital_inicial,
    numero_cuotas,
    tasa_admin,
    tasa_cliente,
    capital_cuota=None,
):
    """Calcula una cuota con interés fijo sobre el capital inicial."""
    capital = dinero(capital_inicial)
    cuotas = int(numero_cuotas or 0)
    admin_pct = dinero(tasa_admin)
    cliente_pct = dinero(tasa_cliente)

    if capital <= 0 or cuotas <= 0:
        raise ValueError("El capital y el número de cuotas deben ser mayores a cero.")
    if admin_pct < 0 or cliente_pct < 0:
        raise ValueError("Las tasas no pueden ser negativas.")
    if cliente_pct < admin_pct:
        raise ValueError("La tasa del cliente no puede ser menor que la tasa del administrador.")

    capital_mes = dinero(capital_cuota) if capital_cuota is not None else dinero(capital / cuotas)
    interes_admin = dinero(capital * admin_pct / 100)
    tasa_prestamista = dinero(cliente_pct - admin_pct)
    ganancia_prestamista = dinero(capital * tasa_prestamista / 100)
    total_admin = dinero(capital_mes + interes_admin)
    pago_cliente = dinero(total_admin + ganancia_prestamista)
    interes_cliente = dinero(interes_admin + ganancia_prestamista)

    return {
        "capital_inicial": float(capital),
        "capital_mensual": float(capital_mes),
        "tasa_admin": float(admin_pct),
        "interes_admin": float(interes_admin),
        "tasa_cliente": float(cliente_pct),
        "tasa_prestamista": float(tasa_prestamista),
        "ganancia_prestamista": float(ganancia_prestamista),
        "interes_cliente": float(interes_cliente),
        "admin_total": float(total_admin),
        "cuota_cliente": float(pago_cliente),
        "total_admin_final": float(dinero(total_admin * cuotas)),
        "ganancia_admin_total": float(dinero(interes_admin * cuotas)),
        "ganancia_prestamista_total": float(dinero(ganancia_prestamista * cuotas)),
        "total_cliente_final": float(dinero(pago_cliente * cuotas)),
    }
