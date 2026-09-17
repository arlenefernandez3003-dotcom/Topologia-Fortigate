# FortiGate — DPI, WAF Anti-SQLi con Cuarentena y Segmentación Web/DB

### Arlene Fernández Herrera · Matrícula: 2025-0730

**Seguridad de Redes · ITLA**

---

## 🎥 Video Demostrativo

**[▶ Ver video de demostración](https://youtu.be/REEMPLAZAR-CON-TU-ID)**

---

## 📋 Tabla de Contenido

1. [Objetivo del Laboratorio](#1-objetivo-del-laboratorio)
2. [Topología y Direccionamiento](#2-topología-y-direccionamiento)
   - [Diagrama de Topología](#21-diagrama-de-topología)
   - [Tabla de Interfaces y VLANs](#22-tabla-de-interfaces-y-vlans)
   - [Tabla de Dispositivos](#23-tabla-de-dispositivos)
3. [Configuración del Switch](#3-configuración-del-switch)
4. [Configuraciones del FortiGate por la GUI](#4-configuraciones-del-fortigate-por-la-gui)
   - [4.0 Acceso Inicial — CLI](#40-acceso-inicial--cli)
   - [4.1 Configuración de Interfaces](#41-configuración-de-interfaces)
   - [4.2 DHCP en VLAN10 (Usuarios)](#42-dhcp-en-vlan10-usuarios)
   - [4.3 Ruta por Defecto](#43-ruta-por-defecto)
   - [4.4 NAT — Acceso a Internet](#44-nat--acceso-a-internet)
   - [4.5 Política 1 — Usuarios → WEB-Server (443)](#45-política-1--usuarios--web-server-443)
   - [4.6 Política 2 — Bloqueo Usuarios → DB-Server (3306)](#46-política-2--bloqueo-usuarios--db-server-3306)
   - [4.7 Activar DPI (SSL/SSH Inspection)](#47-activar-dpi-sslssh-inspection)
   - [4.8 Detección de SQL Injection con Cuarentena del Atacante](#48-detección-de-sql-injection-con-cuarentena-del-atacante)
   - [4.9 Segmentación WEB-Server ↔ DB-Server (solo 3306)](#49-segmentación-web-server--db-server-solo-3306)
   - [4.10 Filtrado de Aplicaciones — Bloqueo de Descargas .exe](#410-filtrado-de-aplicaciones--bloqueo-de-descargas-exe)
   - [4.11 Rate Limiting Anti-DoS](#411-rate-limiting-anti-dos)
5. [Pruebas de Inyección de Payloads Maliciosos](#5-pruebas-de-inyección-de-payloads-maliciosos)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Estructura del Repositorio](#8-estructura-del-repositorio)


---

## 1. Objetivo del Laboratorio

Esta práctica implementa un **FortiGate como firewall perimetral y de segmentación interna**, configurado íntegramente por GUI, con inspección profunda de tráfico (DPI) y protección activa contra ataques de aplicación web. La topología separa tres segmentos: una red de usuarios en VLAN 10, un servidor web público (HTTPS) y un servidor de base de datos aislado, de forma que:

* Los usuarios solo pueden llegar al **WEB-Server** por **HTTPS (443)** — el acceso al **DB-Server (3306)** está explícitamente bloqueado.
* El **DPI (Deep Packet Inspection)** está activo sobre el tráfico hacia el servidor web, permitiendo inspeccionar el contenido de las sesiones HTTPS en busca de patrones de ataque.
* Una regla de **IPS/WAF detecta intentos de SQL Injection** dirigidos al WEB-Server, **bloquea la petición** y **coloca al atacante en cuarentena** (baneo temporal de su IP a nivel de FortiGate), de modo que no pueda volver a intentar el ataque durante el periodo definido.
* El **WEB-Server solo puede iniciar comunicación con el DB-Server por el puerto 3306** — cualquier otro tráfico entre ambos servidores queda denegado, incluso siendo ambos parte de la misma LAN de servidores.
* Se bloquean las **descargas de archivos `.exe`** desde tráfico web mediante File Filter, para reducir el riesgo de malware entrando por HTTP/HTTPS.
* Se aplica **rate limiting** sobre el tráfico entrante para mitigar ataques de denegación de servicio (DoS) dirigidos al WEB-Server.

Se documenta también la configuración de VLAN y seguridad básica en el switch de acceso, y se demuestra el funcionamiento de cada control inyectando tráfico real (incluyendo payloads de SQL Injection) y revisando los logs correspondientes.

---

## 2. Topología y Direccionamiento

> Direccionamiento derivado de la matrícula **2025-0730** → base `20.25.30.0/24`, consistente con el laboratorio anterior de FortiGate.

### 2.1 Diagrama de Topología

```
                              [ INTERNET ]
                                   │
                              192.168.1.2 (ISP Gateway)
                                   │
                          ┌────────┴────────┐
                          │    FortiGate    │
                          │  port1 : WAN    │ 192.168.1.10/24
                          │  port2.10: VLAN10│ 20.25.30.1/25   (Usuarios)
                          │  port3  : SRV   │ 20.25.30.129/28 (Servidores)
                          └────┬────────┬───┘
                               │        │
                     (trunk)   │        │
                          ┌────┴────┐   │ port3
                          │  SW1    │   │
                          │ VLAN 10 │   └───────────┬──────────────┐
                          └────┬────┘               │              │
                     ┌─────────┴─────────┐    ┌──────┴──────┐ ┌────┴──────┐
                     │                   │    │ WEB-Server  │ │ DB-Server │
                ┌────┴───┐          ┌────┴───┐│20.25.30.130 │ │20.25.30.131│
                │  PC1   │          │  PC2   ││  (HTTPS)    │ │ (MySQL)   │
                │ (DHCP) │          │ (DHCP) │└─────────────┘ └───────────┘
                └────────┘          └────────┘
                VLAN 10 — 20.25.30.0/25        LAN Servidores — 20.25.30.128/28

  Políticas de seguridad aplicadas:
  ┌───────────────────────────────────────────────────────────────────┐
  │ VLAN10 → Internet     : NAT                                       │
  │ VLAN10 → WEB-Server   : Solo HTTPS (443) — ALLOW                  │
  │ VLAN10 → DB-Server    : Puerto 3306      — DENY (explícito)       │
  │ WEB-Server → DB-Server: Solo puerto 3306 — ALLOW (nada más)       │
  │ Internet → WEB-Server : DPI + IPS/WAF Anti-SQLi + cuarentena      │
  │ VLAN10 → Internet     : File Filter bloqueo .exe                  │
  │ Internet → WEB-Server : DoS Policy / rate limiting                │
  └───────────────────────────────────────────────────────────────────┘
```

### 2.2 Tabla de Interfaces y VLANs

| Interfaz | Alias | Rol | Dirección IP | Máscara | Notas |
|---|---|---|---|---|---|
| **port1** | WAN | WAN | 192.168.1.10 | /24 | Gateway ISP: 192.168.1.2 |
| **port2** | TRUNK-SW1 | LAN (trunk 802.1Q) | — | — | Enlace troncal hacia SW1 |
| **port2.10** | VLAN10-USUARIOS | LAN (VLAN interface) | 20.25.30.1 | /25 | Gateway de VLAN 10 |
| **port3** | LAN-SERVIDORES | LAN | 20.25.30.129 | /28 | Gateway de la LAN de servidores |

### 2.3 Tabla de Dispositivos

| Dispositivo | Interfaz | Dirección IP | Máscara | Gateway | Método | Rol |
|---|---|---|---|---|---|---|
| **FortiGate** | port1 | 192.168.1.10 | /24 | 192.168.1.2 | Estática | Firewall — WAN |
| **FortiGate** | port2.10 | 20.25.30.1 | /25 | — | Estática | Gateway VLAN 10 (Usuarios) |
| **FortiGate** | port3 | 20.25.30.129 | /28 | — | Estática | Gateway LAN Servidores |
| **SW1** | trunk / VLAN10 | — | — | — | — | Switch de acceso, VLAN 10 + seguridad básica |
| **PC1** | eth0 | 20.25.30.2 (rango) | /25 | 20.25.30.1 | **DHCP** | Cliente de usuario 1 (VLAN 10) |
| **PC2** | eth0 | 20.25.30.3 (rango) | /25 | 20.25.30.1 | **DHCP** | Cliente de usuario 2 (VLAN 10) |
| **WEB-Server** | eth0 | 20.25.30.130 | /28 | 20.25.30.129 | **Estática** | Servidor HTTPS público |
| **DB-Server** | eth0 | 20.25.30.131 | /28 | 20.25.30.129 | **Estática** | Base de datos MySQL (3306) |

> El rango DHCP disponible en VLAN 10 es `20.25.30.2 – 20.25.30.126`. Ambos servidores usan IP estática porque las políticas de FortiGate (WEB→DB, cuarentena, DoS Policy) referencian sus IPs directamente.

---

## 3. Configuración del Switch

**Creación de VLAN 10 y asignación de puertos de acceso:**

```bash
vlan database
 vlan 10 name USUARIOS
exit

interface range fa0/1 - 2
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 spanning-tree bpduguard enable
exit
```

**Enlace troncal hacia el FortiGate (port2):**

```bash
interface fa0/24
 switchport mode trunk
 switchport trunk allowed vlan 10
exit
```

**Seguridad básica de red (port security + hardening):**

```bash
interface range fa0/1 - 2
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
exit

! Deshabilitar puertos no utilizados
interface range fa0/3 - 23
 shutdown
exit

! Deshabilitar protocolos innecesarios en puertos de acceso
interface range fa0/1 - 2
 no cdp enable
exit
```

> Ver evidencia: [00_switch_vlan_seguridad.png](screenshots/00_switch_vlan_seguridad.png)

---

## 4. Configuraciones del FortiGate por la GUI

> Toda la configuración del FortiGate se realiza por GUI, salvo el acceso inicial (ver 4.0), que requiere CLI únicamente para levantar la interfaz de administración.

### 4.0 Acceso Inicial — CLI

```bash
config system interface
    edit "port1"
        set mode static
        set ip 192.168.1.10 255.255.255.0
        set allowaccess https ssh ping
        set role wan
    next
end
```

Acceder luego desde el navegador a `https://192.168.1.10` con las credenciales por defecto (`admin` / contraseña vacía) y definir una contraseña segura al primer inicio de sesión.

> Ver evidencia: [01_cli_acceso_inicial.png](screenshots/01_cli_acceso_inicial.png)

### 4.1 Configuración de Interfaces

**Ruta:** `Network → Interfaces`

**port1 — WAN:**

| Campo | Valor |
|---|---|
| Role | `WAN` |
| Addressing mode | `Manual` |
| IP/Netmask | `192.168.1.10 / 255.255.255.0` |
| Administrative access | `HTTPS, SSH, Ping` |

**port2 — Trunk hacia SW1:** dejar sin IP, solo como interfaz física base para la VLAN.

**port2.10 — Crear interfaz VLAN:** `Network → Interfaces → Create New → VLAN`

| Campo | Valor |
|---|---|
| Interface Name | `VLAN10-USUARIOS` |
| Interface | `port2` |
| VLAN ID | `10` |
| Role | `LAN` |
| Addressing mode | `Manual` |
| IP/Netmask | `20.25.37.1 / 255.255.255.128` |
| Administrative access | `Ping` |

**port3 — LAN Servidores:**

| Campo | Valor |
|---|---|
| Role | `LAN` |
| Addressing mode | `Manual` |
| IP/Netmask | `20.25.37.129 / 255.255.255.240` |
| Administrative access | `Ping` |

> Ver evidencia: [02_interfaces_vlan.png](screenshots/02_interfaces_vlan.png)

### 4.2 DHCP en VLAN10 (Usuarios)

**Ruta:** `Network → Interfaces → VLAN10-USUARIOS → Edit → DHCP Server → Create New`

| Campo | Valor |
|---|---|
| Status | `Enable` |
| Address Range | `20.25.37.2 – 20.25.37.126` |
| Netmask | `255.255.255.128` |
| Default Gateway | `20.25.37.1` |
| DNS Server | `8.8.8.8` / `8.8.4.4` |
| Lease Time | `1 day` |

> Ver evidencia: [03_dhcp_vlan10.png](screenshots/03_dhcp_vlan10.png)

### 4.3 Ruta por Defecto

**Ruta:** `Network → Static Routes → Create New`

| Campo | Valor |
|---|---|
| Destination | `0.0.0.0 / 0.0.0.0` |
| Gateway | `192.168.1.2` |
| Interface | `port1` |
| Distance | `10` |

> Ver evidencia: [04_ruta_default.png](screenshots/04_ruta_default.png)

### 4.4 NAT — Acceso a Internet

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `VLAN10-to-Internet` |
| Incoming Interface | `VLAN10-USUARIOS` |
| Outgoing Interface | `port1 (WAN)` |
| Source | `all` |
| Destination | `all` |
| Service | `ALL` |
| Action | `ACCEPT` |
| NAT | ✅ Enable — `Use Outgoing Interface Address` |

> Ver evidencia: [05_nat_internet.png](screenshots/05_nat_internet.png)

### 4.5 Política 1 — Usuarios → WEB-Server (443)

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `VLAN10-to-WebServer-HTTPS` |
| Incoming Interface | `VLAN10-USUARIOS` |
| Outgoing Interface | `port3 (LAN-SERVIDORES)` |
| Source | `all` |
| Destination | `WEB-Server (20.25.37.130)` |
| Service | `HTTPS` |
| Action | `ACCEPT` |
| NAT | ❌ Disabled |
| Log Allowed Traffic | `All Sessions` |
| SSL Inspection | `deep-inspection` *(ver 4.7)* |

> Esta política debe quedar **por encima** de la política 2, y por encima de cualquier política ALL entre estos segmentos.

> Ver evidencia: [06_politica_https_webserver.png](screenshots/06_politica_https_webserver.png)

### 4.6 Política 2 — Bloqueo Usuarios → DB-Server (3306)

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `VLAN10-to-DBServer-BLOCK` |
| Incoming Interface | `VLAN10-USUARIOS` |
| Outgoing Interface | `port3 (LAN-SERVIDORES)` |
| Source | `all` |
| Destination | `DB-Server (20.25.37.131)` |
| Service | `MYSQL (3306)` |
| Action | `DENY` |
| Log Violation Traffic | `Enable` |

> Aunque el implicit deny de FortiGate ya bloquearía este tráfico, se crea explícitamente para tenerlo **loggeado y documentado** como evidencia de la política de segmentación.

> Ver evidencia: [07_politica_bloqueo_db.png](screenshots/07_politica_bloqueo_db.png)

### 4.7 Activar DPI (SSL/SSH Inspection)

El DPI en FortiGate para tráfico HTTPS se implementa mediante un perfil de **inspección SSL** (`deep-inspection`), que descifra el tráfico para poder aplicarle IPS, WAF y Application Control antes de reenviarlo.

**Ruta:** `Security Profiles → SSL/SSH Inspection`

| Campo | Valor |
|---|---|
| Profile | `deep-inspection` (perfil predeterminado, clonar como `DPI-WEBSERVER`) |
| Inspection method | `Full SSL Inspection` |
| CA Certificate | Certificado de FortiGate (o el emitido para el lab) |

**Aplicar el perfil a la política `VLAN10-to-WebServer-HTTPS`** (sección 4.5) → Security Profiles → SSL Inspection: `DPI-WEBSERVER`.

> **Nota:** la inspección SSL descifra tráfico HTTPS del cliente; en un entorno real requiere distribuir el certificado de la CA del FortiGate en los equipos cliente para evitar advertencias de certificado no confiable. En el lab se acepta la advertencia manualmente para efectos de la demostración.

> Ver evidencia: [08_dpi_ssl_inspection.png](screenshots/08_dpi_ssl_inspection.png)

### 4.8 Detección de SQL Injection con Cuarentena del Atacante

La detección de SQL Injection se implementa con un **perfil IPS** que incluye las firmas de la categoría *Web Application Attacks* orientadas a SQLi, configurado para **bloquear** y **poner en cuarentena** la IP de origen.

**Paso 1 — Crear el perfil IPS:**

**Ruta:** `Security Profiles → Intrusion Prevention → Create New`

| Campo | Valor |
|---|---|
| Name | `IPS-ANTI-SQLI` |
| IPS Signatures → Add Signature | Filtrar por `SQL Injection` |
| Action | `Block` |
| Packet Logging | `Enable` |
| **Quarantine** | `Attacker's IP address` |
| Quarantine Duration | `5 minutes` *(ajustado para demo; en producción usar un valor mayor)* |

> El campo **Quarantine** es lo que hace que, además de bloquear el paquete que dispara la firma, FortiGate agregue automáticamente la IP de origen a la lista de cuarentena (`Dashboard → Quarantine` / `System → Quarantine Monitor`), bloqueando **todo** su tráfico posterior durante la duración configurada.

**Paso 2 — Aplicar el perfil IPS a la política del WEB-Server:**

Editar `VLAN10-to-WebServer-HTTPS` (o, si el ataque simulado viene desde Internet, la política equivalente `Internet-to-WebServer`) → Security Profiles:

| Campo | Valor |
|---|---|
| Intrusion Prevention | ✅ `IPS-ANTI-SQLI` |

> Ver evidencia: [09_ips_sqli_cuarentena.png](screenshots/09_ips_sqli_cuarentena.png)

### 4.9 Segmentación WEB-Server ↔ DB-Server (solo 3306)

Ambos servidores están en la misma LAN de servidores (`port3`), por lo que FortiGate no puede filtrar tráfico intra-VLAN salvo que se fuerce con **políticas intra-interfaz** (`Intra-zone traffic` en modo NAT/route con la misma interfaz de entrada y salida), o alternativamente separando cada servidor en su propia VLAN. Para este lab se separa cada servidor en su propia sub-interfaz VLAN sobre `port3`, de forma que el tráfico entre ellos sí pase por el firewall:

**Ruta:** `Network → Interfaces → Create New → VLAN` (dos interfaces adicionales sobre `port3`)

| Interfaz | VLAN ID | IP/Netmask |
|---|---|---|
| `VLAN20-WEB` | 20 | `20.25.37.129/28` (WEB-Server) |
| `VLAN30-DB`  | 30 | `20.25.37.145/28` (DB-Server) *(sub-red adicional /28 reservada para este segmento)* |

**Política — WEB-Server → DB-Server, solo 3306:**

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `WebServer-to-DBServer-3306-only` |
| Incoming Interface | `VLAN20-WEB` |
| Outgoing Interface | `VLAN30-DB` |
| Source | `WEB-Server (20.25.37.130)` |
| Destination | `DB-Server` |
| Service | `MYSQL (3306)` |
| Action | `ACCEPT` |
| Log Allowed Traffic | `All Sessions` |

> No se crea ninguna política adicional ALL entre `VLAN20-WEB` y `VLAN30-DB`, de forma que el **implicit deny** de FortiGate bloquea automáticamente cualquier otro puerto/protocolo entre ambos servidores.

> Ver evidencia: [10_politica_web_db_3306.png](screenshots/10_politica_web_db_3306.png)

### 4.10 Filtrado de Aplicaciones — Bloqueo de Descargas .exe

**Ruta:** `Security Profiles → File Filter → Create New`

| Campo | Valor |
|---|---|
| Name | `FILE-FILTER-EXE` |
| Filter → Add | |
| Protocol | `HTTP, HTTPS` |
| File Type | `exe` |
| Action | `Block` |

**Aplicar el perfil a la política de salida a Internet** (`VLAN10-to-Internet`, sección 4.4) → Security Profiles:

| Campo | Valor |
|---|---|
| File Filter | ✅ `FILE-FILTER-EXE` |

> Requiere que la política tenga también un perfil de **SSL Inspection** activo (sección 4.7) para poder inspeccionar descargas `.exe` sobre HTTPS, no solo HTTP.

> Ver evidencia: [11_file_filter_exe.png](screenshots/11_file_filter_exe.png)

### 4.11 Rate Limiting Anti-DoS

El rate limiting se implementa con dos mecanismos complementarios de FortiGate:

**Paso 1 — DoS Policy (anomalías de volumen/paquetes) en la interfaz WAN:**

**Ruta:** `Policy & Objects → DoS Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `DOS-RATE-LIMIT-WAN` |
| Incoming Interface | `port1 (WAN)` |
| Source Address | `all` |
| Destination Address | `WEB-Server (20.25.37.130)` |
| Service | `HTTPS` |

| Anomaly | Action | Threshold (lab) |
|---|---|---|
| `tcp_syn_flood` | `Block` | `100` |
| `tcp_port_scan` | `Block` | `5` |
| `http_flood` (si disponible en la versión de FortiOS) | `Block` | `50` |

**Paso 2 — Traffic Shaping por política (limitación de ancho de banda / sesiones por IP origen):**

**Ruta:** `Policy & Objects → Traffic Shapers → Create New (Per-IP Shaper)`

| Campo | Valor |
|---|---|
| Name | `SHAPER-WEBSERVER-PER-IP` |
| Max bandwidth | `2 Mbps` por IP origen |
| Max concurrent sessions | `20` por IP origen |

Aplicar el shaper en la política que permite tráfico hacia el WEB-Server desde Internet, en la pestaña **Traffic Shaping**.

> Ver evidencia: [12_dos_rate_limiting.png](screenshots/12_dos_rate_limiting.png)

---

## 5. Pruebas de Inyección de Payloads Maliciosos

Para validar la regla de la sección 4.8, se inyectan payloads de SQL Injection contra el formulario de login/búsqueda del WEB-Server desde una máquina externa (simulando un atacante en Internet o en la VLAN de usuarios, según lo que se quiera demostrar):

```
' OR '1'='1' --
' UNION SELECT username, password FROM users --
admin' --
1' AND SLEEP(5) --
```

**Resultado esperado:**

1. El primer payload dispara la firma IPS de SQL Injection → la petición es bloqueada.
2. La IP de origen del atacante queda automáticamente en `Dashboard → Quarantine Monitor` (o `System → Quarantine`).
3. Cualquier intento posterior desde esa misma IP (incluso tráfico legítimo) es bloqueado mientras dure la cuarentena.
4. El evento queda registrado en `Log & Report → Security Events → Attack` con la firma disparada, la IP origen y la acción `Blocked` + `Quarantined`.

> Ver evidencia: [13_payload_sqli_bloqueado.png](screenshots/13_payload_sqli_bloqueado.png), [14_ip_en_cuarentena.png](screenshots/14_ip_en_cuarentena.png)

---

## 6. Capturas de Pantalla

Las capturas de evidencia de cada punto de configuración se encuentran en [`screenshots/`](screenshots/), numeradas según el orden de esta guía (00 a 14 en configuración, más las de verificación final: DHCP leases, acceso HTTPS exitoso, bloqueo a DB-Server, bloqueo de descarga `.exe`, y logs de `Forward Traffic` / `Security Events`).

---


---

## 8. Estructura del Repositorio

```
/
├── README.md                  ← este documento
├── screenshots/                ← capturas numeradas de cada configuración
├── running-configs/
│   ├── fortigate-running-config.conf
│   └── switch-running-config.txt
├── scripts/
│   └── sqli-payloads.txt       ← payloads usados en la sección 5
└── entregable/
    └── ArleneFernandez_20250730_P2.txt
```


---


