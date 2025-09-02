# nimwatch
Nimwatch monitorea la integridad de tus archivos en linux como haría la conocida herramienta tr1pw1r3 

## 🚀 Descripción
Monitor combinado para:
- 🗂️ **Integridad de archivos** (hash SHA256, detecta nuevos, eliminados y cambiados)
- 🔒 **Detección de nuevos puertos TCP en LISTEN** (IPv4/IPv6, con alertas en rojo 🚨)

## 📂 Formato de la Base de Datos
`path|mtime|hash` (compatible con versiones previas)

## 🛠️ Uso
1. Compilar: `nim c -d:release nimwatch2.nim`
2. Ejecutar:
   - `./nimwatch2` ➡️ Pregunta intervalo, monitorea `$HOME`
   - `./nimwatch2 <directorio> <intervalo_seg>` ➡️ Especifica directorio e intervalo
   - `./nimwatch2 <intervalo>` ➡️ Usa `$HOME` con intervalo dado
   - `./nimwatch2 <directorio>` ➡️ Pregunta intervalo, usa directorio dado

## 📦 Requisitos
- Instalar: `nimble install nimcrypto`

## 👤 Autor
- **Base**: hackermexico
- **Extensión**: Detección de puertos

## 🛡️ Funcionalidades
- **Archivos**:
  - 🕵️‍♂️ Escanea directorios recursivamente
  - 🔍 Calcula hash SHA256 para verificar integridad
  - 🚫 Excluye directorios como `.cache/`, `.npm/`, etc.
  - 📝 Guarda estado en `/tmp/nimwatch.db`
  - 📊 Reporta nuevos, cambiados y eliminados
- **Puertos**:
  - 🌐 Monitorea puertos TCP en LISTEN (IPv4/IPv6)
  - ⚠️ Alerta sobre nuevos puertos detectados

## ⏰ Ciclo de Monitoreo
- Escanea cada `<intervalo>` segundos
- Compara con estado previo
- Guarda nuevo estado
- Muestra resúmenes y alertas en colores 🎨

## 🖥️ Ejemplo de Salida
- 🆕 `[FILE NUEVO] /ruta/archivo`
- 🔄 `[FILE CAMBIADO] /ruta/archivo`
- 🗑️ `[FILE ELIMINADO] /ruta/archivo`
- 🚨 `[WARNING PORT] Nuevo puerto LISTEN: 8080`
- ✅ `[OK] Chequeo completado 2025-09-02T17:38:00`

## 📝 Notas
- Usa colores en la terminal para destacar cambios (🟥 rojo, 🟨 amarillo, 🟪 magenta, 🟦 cian, 🟩 verde)
- Persiste datos en `/tmp/nimwatch.db`
- Ordena puertos nuevos para mejor legibilidad
