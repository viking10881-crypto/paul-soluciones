#!/usr/bin/env python3
"""
Reproducción automatizada del flujo de login para depuración.

Uso:
  python scripts/repro_login.py --url http://127.0.0.1:5000 --user admin --password admin123

Muestra paso a paso las cabeceras, cookies y fragmentos de respuesta.
"""
import re
import argparse
import requests


def extraer_csrf(html):
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
    return m.group(1) if m else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', default='http://127.0.0.1:5000', help='Base URL del servidor')
    p.add_argument('--user', required=True, help='Usuario para login')
    p.add_argument('--password', required=True, help='Contraseña para login')
    args = p.parse_args()

    s = requests.Session()
    login_url = args.url.rstrip('/') + '/login'

    print('1) GET /login')
    r = s.get(login_url, allow_redirects=True)
    print('Status:', r.status_code)
    print('URL after redirects:', r.url)
    print('Response headers:\n', '\n'.join(f'{k}: {v}' for k,v in r.headers.items()))
    print('\nCookies set by server (session cookies):')
    for c in s.cookies:
        print(' -', c.name, c.value)

    csrf = extraer_csrf(r.text)
    print('\nCSRF token extracted from form:', bool(csrf))
    if csrf:
        print('csrf_token=', csrf)
    else:
        print('No se encontró token CSRF en el HTML. Si la app usa otro mecanismo, revisa el template.')

    print('\n2) POST /login (intentando iniciar sesión)')
    payload = {
        'usuario': args.user,
        'password': args.password,
    }
    if csrf:
        payload['csrf_token'] = csrf

    r2 = s.post(login_url, data=payload, allow_redirects=True)
    print('Status:', r2.status_code)
    print('Final URL after redirects:', r2.url)
    print('Redirect history:', [h.status_code for h in r2.history])
    print('\nResponse headers:\n', '\n'.join(f'{k}: {v}' for k,v in r2.headers.items()))
    print('\nCookies now in session:')
    for c in s.cookies:
        print(' -', c.name, c.value)

    # Buscar mensajes flash en el HTML
    alerts = re.findall(r'<div class="alert [^">]+">\s*([^<]+)\s*</div>', r2.text)
    if alerts:
        print('\nMensajes mostrados en la página:')
        for a in alerts:
            print(' -', a.strip())
    else:
        print('\nNo se encontraron mensajes flash en la respuesta.')

    # Mostrar un fragmento del body para inspección
    print('\n--- fragmento de cuerpo (primeros 800 chars) ---\n')
    print(r2.text[:800])


if __name__ == '__main__':
    main()
