import pytest

from servicios_liquidacion import calcular_distribucion_liquidacion


def test_distribucion_base_ocho_por_ciento():
    datos = calcular_distribucion_liquidacion(250_000, 5, 6, 8)
    assert datos["capital_mensual"] == 50_000
    assert datos["interes_admin"] == 15_000
    assert datos["ganancia_prestamista"] == 5_000
    assert datos["admin_total"] == 65_000
    assert datos["cuota_cliente"] == 70_000
    assert datos["total_admin_final"] == 325_000
    assert datos["ganancia_prestamista_total"] == 25_000
    assert datos["total_cliente_final"] == 350_000


def test_margen_cambia_con_la_tasa_del_cliente():
    datos = calcular_distribucion_liquidacion(250_000, 5, 6, 10)
    assert datos["tasa_prestamista"] == 4
    assert datos["ganancia_prestamista"] == 10_000
    assert datos["interes_admin"] == 15_000
    assert datos["cuota_cliente"] == 75_000


def test_no_permite_tasa_cliente_menor_que_tasa_admin():
    with pytest.raises(ValueError):
        calcular_distribucion_liquidacion(250_000, 5, 8, 6)
