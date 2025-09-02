# nimwatch2.nim
# Monitor combinado:
#   - Integridad de archivos (hash SHA256 + nuevos + eliminados + cambiados)
#   - Detección de nuevos PUERTOS TCP en LISTEN (ipv4/ipv6) => WARNING en rojo
#
# Formato DB: path|mtime|hash  (compatible con versiones previas)
#
# Uso:
#   nim c -d:release nimwatch2.nim
#   ./nimwatch2                (pregunta intervalo, monitorea $HOME)
#   ./nimwatch2 <dir> <intervalo_seg>
#
# Si pasas 1 argumento numérico => intervalo usando $HOME.
# Si pasas 1 argumento no numérico => directorio (preguntará intervalo).
# Si pasas 2 argumentos: dir y número intervalo.
#
# Requiere: nimble install nimcrypto
#
# Autor base: hackermexico
# Extensión: + puertos

import os, strutils, times, tables, sets
import nimcrypto
import terminal
import algorithm          # <-- añadido para sort() sobre seq

# ---------------- Tipos ----------------
type
  FileState = object
    mtime: int64
    hash: string
  FileMap = Table[string, FileState]

# ---------------- Constantes ----------------
const
  DB_FILE  = "/tmp/nimwatch.db"
  EXCLUDES = @[".cache/", ".npm/", ".local/share/", ".mozilla/", ".thumbnails/"]

# ---------------- Utilidades exclusiones ----------------
proc excluded(p: string): bool =
  for e in EXCLUDES:
    if p.contains(e): return true
  false

# ---------------- MTime seguro ----------------
proc safeMTime(p: string): int64 =
  try:
    let fi = getFileInfo(p)
    when compiles(fi.modificationTime):
      fi.modificationTime.toUnix()
    elif compiles(fi.lastWriteTime):
      fi.lastWriteTime.toUnix()
    else: 0
  except:
    0

# ---------------- Hash archivo ----------------
proc fileSha256(p: string): string =
  try:
    var ctx: sha256
    ctx.init()
    let f = open(p, fmRead)
    defer: f.close()
    var buf: array[8192, byte]
    while true:
      let n = f.readBytes(buf, 0, buf.len)
      if n == 0: break
      ctx.update(buf[0 ..< n])
    let dg = finish(ctx)
    toHex(dg.data)
  except:
    ""

# ---------------- Escaneo archivos ----------------
proc scanFiles(root: string): FileMap =
  result = initTable[string, FileState]()
  for p in walkDirRec(root):
    if excluded(p): continue
    if fileExists(p):
      result[p] = FileState(mtime: safeMTime(p), hash: fileSha256(p))

# ---------------- Persistencia ----------------
proc saveMap(m: FileMap) =
  var lines: seq[string] = @[]
  lines.setLen(m.len)
  var i = 0
  for k,v in m:
    lines[i] = k & "|" & $v.mtime & "|" & v.hash
    inc i
  writeFile(DB_FILE, lines.join("\n"))

proc loadMap(): FileMap =
  result = initTable[string, FileState]()
  if not fileExists(DB_FILE): return
  for line in readFile(DB_FILE).splitLines:
    let parts = line.split("|")
    if parts.len == 3:
      try:
        result[parts[0]] = FileState(mtime: parseInt(parts[1]), hash: parts[2])
      except: discard

# ---------------- Construir baseline ----------------
proc baseline(root: string): FileMap =
  styledEcho(fgCyan, "[*] Creando baseline...", resetStyle)
  let m = scanFiles(root)
  saveMap(m)
  styledEcho(fgGreen, "[*] Baseline lista (", $m.len, " archivos)", resetStyle)
  m

# ---------------- Comparación archivos ----------------
proc compareFiles(prev, cur: FileMap) =
  var newC, chgC, delC = 0
  for k,v in cur:
    if k in prev:
      if v.hash != prev[k].hash:
        inc chgC
        styledEcho(fgRed, "[FILE CAMBIADO] ", resetStyle, k)
    else:
      inc newC
      styledEcho(fgYellow, "[FILE NUEVO] ", resetStyle, k)
  for k in prev.keys:
    if k notin cur:
      inc delC
      styledEcho(fgRed, "[FILE ELIMINADO] ", resetStyle, k)
  styledEcho(fgMagenta, "[RESUMEN FILES] nuevos=", $newC, " cambiados=",
             $chgC, " eliminados=", $delC, " total=", $cur.len, resetStyle)

# ---------------- Puertos LISTEN ----------------
proc parseProcNet(path: string; s: var HashSet[int]) =
  if not fileExists(path): return
  for line in lines(path):
    if line.startsWith("sl"): continue
    let cols = line.splitWhitespace()
    if cols.len < 4: continue
    let state = cols[3]
    if state != "0A": continue   # 0A = LISTEN
    let localAddr = cols[1]
    let parts = localAddr.split(":")
    if parts.len != 2: continue
    let hexPort = parts[1]
    try:
      let port = parseHexInt(hexPort)
      s.incl(port)
    except: discard

proc getListeningTcpPorts(): HashSet[int] =
  result = initHashSet[int]()
  parseProcNet("/proc/net/tcp", result)
  parseProcNet("/proc/net/tcp6", result)

# ---------------- Comparar puertos ----------------
proc comparePorts(prev, cur: HashSet[int]) =
  var newPorts: seq[int] = @[]
  for p in cur:
    if p notin prev:
      newPorts.add p
  if newPorts.len > 0:
    newPorts.sort()    # requiere import algorithm
    for p in newPorts:
      styledEcho(fgRed, "[WARNING PORT] Nuevo puerto LISTEN: ", $p, resetStyle)

# ---------------- Intervalo ----------------
proc askInterval(): int =
  echo "Intervalo (segundos) [Enter=60]: "
  let s = readLine(stdin).strip()
  if s.len == 0: return 60
  try: parseInt(s) except: 60

# ---------------- Argumentos ----------------
proc parseArgs(): (string, int) =
  var root = getHomeDir()
  var interval = -1
  let a = commandLineParams()
  if a.len == 1:
    if a[0].allCharsInSet({'0'..'9'}):
      interval = parseInt(a[0])
    else:
      root = a[0]
  elif a.len >= 2:
    root = a[0]
    try: interval = parseInt(a[1]) except: interval = -1
  (root, interval)

# ---------------- Monitor loop ----------------
proc monitor(root: string, intervalInput: int) =
  styledEcho(fgCyan, "[*] Directorio monitoreado: ", root, resetStyle)
  var prevFiles = loadMap()
  if prevFiles.len == 0:
    prevFiles = baseline(root)
  else:
    styledEcho(fgCyan, "[*] Baseline previa cargada (", $prevFiles.len, " archivos)", resetStyle)

  var prevPorts = getListeningTcpPorts()
  styledEcho(fgCyan, "[*] Puertos iniciales LISTEN: ", $prevPorts.len, resetStyle)

  var interval = intervalInput
  if interval <= 0: interval = askInterval()

  while true:
    sleep(interval * 1000)

    # Archivos
    let curFiles = scanFiles(root)
    compareFiles(prevFiles, curFiles)
    saveMap(curFiles)
    prevFiles = curFiles

    # Puertos
    let curPorts = getListeningTcpPorts()
    comparePorts(prevPorts, curPorts)
    prevPorts = curPorts

    styledEcho(fgGreen, "[OK] Chequeo completado ", $now(), resetStyle)

# ---------------- Main ----------------
when isMainModule:
  let (root, iv) = parseArgs()
  monitor(root, iv)
