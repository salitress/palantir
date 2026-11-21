# MEJORAS.md — pendientes, decisiones de diseño e ideas propuestas

Este documento recoge:

1. **Decisiones de diseño** sobre lo que palantir **a propósito NO hace** (y por qué), al
   que apuntan varios comentarios del código (`ver MEJORAS.md`).
2. **Ideas propuestas** (del audit) para futuras versiones. Son **solo propuestas**: no están
   implementadas. **Todas son de SOLO LECTURA / detección** — ninguna añade post-explotación
   (volcado de LSASS, robo de credenciales del disco, ejecución de exploits activos), que queda
   deliberadamente fuera del alcance de palantir.

---

## 1. Decisiones de diseño ("Pendiente")

palantir es una herramienta de **reconocimiento y enumeración de solo lectura** para labs de
pentest autorizados (HTB/CPTS/OSCP). La línea roja es clara: **detecta y sugiere, pero nunca
ejecuta un paso activo/destructivo por su cuenta.**

### Lo que queda como paso MANUAL a propósito (nunca encadenado)

- **Volcado de NTDS / `secretsdump` / DCSync real.** Cuando palantir confirma un derecho (p. ej.
  DCSync viable por una ACL, o Zerologon vulnerable), **deja el comando como next-step manual**,
  no lo ejecuta. Volcar el NTDS, resetear la contraseña de la cuenta de máquina de un DC
  (Zerologon) o hacer un DCSync son acciones de **alto impacto y potencialmente destructivas**
  (Zerologon deja la cuenta de máquina con contraseña vacía hasta restaurarla) — el operador debe
  lanzarlas conscientemente. (Referenciado en `palantir.py`: `_surface_acl_abuse`, el bloque de
  Zerologon de `fp_smb`, `_creds_enum`.)
- **Explotación activa (Metasploit / PoCs de RCE).** EternalBlue, SMBGhost, mod_copy, etc. se
  **detectan** (comprobación de solo lectura) y se sugiere el comando; nunca se lanza el exploit.
- **Password spraying con listas.** Cruzar `--user-list`×`--pass-list` sí es spraying real y por eso
  pide confirmación (`confirm_creds_spray`) y comprueba antes la política de bloqueo; el resto de la
  Fase 5d es **1 intento por cuenta** (reutilización de una credencial ya válida), no fuerza bruta.
- **Nada que escriba en el objetivo** (subir webshell por PUT/WebDAV, `davtest`, mod_copy…): se
  sugiere, nunca se ejecuta.

### Fuera de alcance de forma permanente

- **Post-explotación**: volcado de LSASS, robo de credenciales del sistema de ficheros, pivoting
  activo, persistencia. palantir termina donde empieza la post-explotación.

---

## 2. Ideas propuestas (solo propuesta, SOLO LECTURA)

Recogidas en la super-auditoría. Cada una es de **solo lectura / detección** y reutiliza en su
mayoría salida que palantir **ya captura** (banners de nxc, XML de nmap, `whatweb`, `searchsploit
-j`…), así que casi ninguna añade tráfico nuevo contra el objetivo. Marcadas con *(parcial)* las
que una corrección reciente del audit ya cubre en parte.

### Motor de escaneo

- **Detectar escaneos truncados desde `<runstats>`/`<host><status>` del XML de nmap** y marcar el
  informe como parcial (en vez de leer un host-timeout como "nada más que ver").
- **Persistir los puertos "flapping" (vistos en Fase 1 pero no en Fase 2)** en findings.json y el
  HTML, en vez de descartarlos en silencio.
- **Registrar el tipo de escaneo efectivo por objetivo** (`-sS`/`-sT`, si saltó el auto-fallback a
  connect scan) para que el informe sea reproducible.
- **Imprimir la línea de build/OS de Windows detectada** (`smb-os-discovery`/`rdp-ntlm-info`) cuando
  se conoce. *(parcial: `_detect_win_build` ya lee el host-script tras el fix #64.)*

### Web

- **Parsear `Sitemap:` de robots.txt** (ahora solo se miran `Disallow`/`Allow`).
- **Sacar los redirects interesantes de ffuf** (`redirectlocation`) como hits web.
- **Follow-up dedicado de `.git` expuesto** (detección + next-step `git-dumper`).
  *(parcial: el fix #6 ya vincula `git-dumper` al hallazgo de `.git`.)*
- **Alimentar `guess_extensions`/matching de producto conocido con lo que detecta `whatweb`.**
  *(parcial: el fix #8 ya pasa `whatweb` a `guess_extensions`.)*

### SMB / nxc

- **Marcar SMBv1 habilitado** desde el banner `(SMBv1:...)` que nxc ya imprime.
- **Sacar "Maximum password age"** de `--pass-pol` (contraseñas que no caducan nunca).
- **Marcar NTLM aún habilitado en el DC** desde el banner LDAP `(NTLM:...)`.
- **Sacar cuentas de equipo (`$`) y grupos del RID cycling**, no solo `SidTypeUser` (en una sección
  aparte, para no contaminar la lista de usuarios roasteables). *(parcial: el fix #18 ya filtra `$`
  de la lista de usuarios; faltaría listarlas aparte.)*
- **Reportar el marcador `(Guest)` (guest-mapping) como hallazgo propio.** *(hecho en los fixes
  #17/#46/#53: ya se anota el guest-mapping como `media`.)*

### LDAP

- **Superficie de coerce + relay-a-LDAP (RBCD / Shadow Credentials)** usando el flag de signing LDAP
  que ya se recoge. *(relacionado con el fix #26, que deja de filtrar `_ldap_signing_disabled`; la
  combinación coerce+relay-a-LDAP sigue sin materializarse.)*
- **Enumerar la membresía anónima de Domain/Enterprise Admins** cuando el bind anónimo lee
  (`--groups "Domain Admins"`). *(parcial: el fix #27 corrige la nota; faltaría la consulta.)*
- **Listar cuentas de equipo pre-Windows-2000 (`userAccountControl=4128`) en el camino anónimo.**
- **Reportar el channel binding de LDAPS** independientemente del signing.

### Kerberos

- **Capturar los hashes `$krb5asrep$` que kerbrute ya vuelca** durante `userenum` (ahora se
  descartan). *(relacionado con el fix #30, que ya detecta las cuentas sin pre-auth.)*
- **Reportar la cobertura de kerbrute** desde su línea `Done! Tested N ...` (cuántas se probaron).

### Otros protocolos

- **DNS: reintentar NS/AXFR contra el DC escaneado** cuando el resolver del sistema no da name
  servers.
- **SMTP: marcar AUTH ofrecido sin STARTTLS** (envío de credenciales en claro).
- **VNC: sacar `(No Auth:True)` del banner** aunque no haya `(Pwn3d!)`. *(hecho en el fix #48.)*
- **Redis: sacar `redis_version` del INFO** ya capturado, para cruzar con CVEs conocidas.

### Credenciales por defecto / aportadas

- **Tras un login válido de MySQL/PostgreSQL, comprobar el nivel de privilegio (solo lectura)**
  (`SHOW GRANTS`, `@@secure_file_priv`, `pg_roles.rolsuper`) para confirmar la ruta de RCE sugerida.
- **Resaltar nombres de tabla de alto valor** (users, creds, secrets…) en la salida del DB-enum.
- **Consultar la política de bloqueo antes de abanicar una cuenta por todos los protocolos** en el
  camino 1-a-1 (ya existe `_probe_lockout_policy`).
- **Marcar la reutilización de contraseña entre protocolos** como hallazgo de higiene explícito.
- **Detectar reutilización de hash NT entre cuentas locales** de un SAM ya volcado (`_parse_nxc_sam`
  ya devuelve el hash por cuenta — solo lectura sobre datos ya recogidos).

### brutespray

- **Detectar la versión mayor de brutespray** (v1 wrapper de THC vs v2 Go) antes de invocarlo.
- **Incluir `udp.gnmap` en el comando de una sola pasada** cuando hay un servicio UDP crackeable
  (SNMP). *(parcial: el fix #60 ya lo avisa en el texto.)*
- **Reportar qué servicios footprinteados crackeables NO tienen camino de credenciales automatizado.**
  *(parcial: el fix #63 ya añade `mongodb`; `oracle` no lo cubre brutespray.)*

### searchsploit

- **Sacar los códigos CVE/MSB junto a cada EDB-ID** desde el campo `Codes` de `searchsploit -j`.
- **Marcar el estado `Verified` de exploit-db** para priorizar exploits confirmados.
- **Imprimir la línea build/OS de Windows** en el informe cuando se conoce (ver "Motor de escaneo").

### Informe / lógica

- **Etiquetar los comandos de quick-win como dirigidos vs genéricos** (para que se vea cuál explota
  el hallazgo concreto y cuál es un re-escaneo general). *(el fix #1/#6 ya prioriza el comando
  vinculado; faltaría la etiqueta visible.)*
- **Self-test de desarrollo que afirme que cada tipo de hallazgo crítico/alto tiene un comando
  emparejado** (regresión para la clase de bug de asociación del audit).
- **Detectar y colapsar next-steps casi-duplicados entre protocolos también en el cuerpo del
  informe** (no solo en Quick Wins). *(el fix #68 ya deduplica en Quick Wins por el comando sin
  comentario.)*
