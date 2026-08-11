# Administrador de préstamos

Aplicación Flask para administrar clientes, préstamos, cuotas, pagos y cuentas de caja/banco.

## Roles

- **Administrador:** visualiza toda la operación y administra las cuentas de acceso de los prestamistas.
- **Prestamista:** utiliza el mismo flujo financiero, limitado a sus clientes, préstamos, pagos, cuentas y notificaciones.

Al iniciar la aplicación por primera vez se crea el usuario `admin` con contraseña temporal `admin123`. Cámbiala antes de usar el sistema en producción.

## Seguridad

- Copia `.env.example` como `.env` y configura una `SECRET_KEY` larga y privada.
- En producción con HTTPS establece `SESSION_COOKIE_SECURE=true`.
- Cada formulario usa un token CSRF y las sesiones tienen cookies `HttpOnly` y `SameSite=Lax`.
- Cada usuario puede cambiar su contraseña desde **Cambiar contraseña**.

## Liquidación de capital

El administrador puede entregar capital a un prestamista indicando monto, plazo y tasa mensual. El prestamista vincula ese capital a un préstamo de cliente y define la tasa total del cliente. Cuando una cuota queda totalmente pagada, la liquidación distribuye el capital y el interés del administrador, y separa automáticamente el margen del prestamista. Todos los porcentajes se calculan sobre el capital inicial, no sobre el saldo restante.
