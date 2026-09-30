# Enredo

**Analizador de red local que se abre en tu navegador.** Descubre los equipos de tu
red, su fabricante, nombre y puertos abiertos — todo **en tu propio ordenador**, sin
base de datos y sin enviar nada a Internet. Exporta los resultados en el formato
`.enredo` (cifrado para ti, o censurado para compartir) e **importa y compara** redes
tuyas o de amigos.

## Requisitos
- [Node.js](https://nodejs.org) 18 o superior.
- No necesita permisos de administrador. No instala drivers ni captura paquetes.

## Instalación y uso
```bash
# 1) Descarga o clona este repositorio y entra en la carpeta
cd enredo/app

# 2) Arranca
npm start        # o:  node server.js

# 3) Se abre tu navegador en http://127.0.0.1:4599
#    Pulsa "Escanear mi red".
```

## Qué hace
- **Descubre equipos** de tu subred: ping-sweep (ICMP, sin admin) + caché ARP.
- **Fabricante** por MAC (base OUI incluida; ampliable con `npm run oui:update`).
- **Nombre** por DNS inverso. **Puertos** abiertos por conexión TCP.
- **Tu equipo**: interfaz, puerta de enlace, DNS y, si lo permites, IP pública y Wi-Fi.
- **Exportar**:
  - *Para compartir* → `.enredo` **censurado**: sin IPs, MACs ni nombres. Seguro para el foro.
  - *Privado* → `.enredo` **cifrado** con tu contraseña (AES-256). Si se pierde, es ilegible sin la clave.
- **Importar y comparar** varios `.enredo`.

## El formato `.enredo`
Un archivo de texto con cabecera `ENREDO1` + los datos empaquetados (gzip+base64), o
cifrados (AES-GCM) en el modo privado. Solo Enredo lo interpreta. Renombrar un archivo
no protege nada: lo que protege es **quitar los datos privados** (modo compartir) y el
**cifrado** (modo privado).

## Privacidad
El servidor escucha solo en `127.0.0.1`. Ningún dato sale de tu equipo, salvo —si lo
dejas marcado— una consulta a un servicio público para saber tu IP pública. No hay
cuentas, ni cookies, ni base de datos.

## Uso responsable
Escanea únicamente **tu propia red** o redes para las que tengas permiso explícito.

## Cobertura de fabricantes
Incluye un set de fabricantes comunes. Para la base completa de IEEE:
```bash
npm run oui:update
```

## Licencia
MIT.
