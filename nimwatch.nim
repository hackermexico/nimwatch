# nimwatch.nim
# Monitor MUY simple de integridad (SHA256) que COMPILA en Nim 2.2.x (y 1.4+).
# - Baseline inicial: guarda hash y mtime de archivos.
# - Cada ciclo: detecta nuevos / cambiados / eliminados.
# - Exclusiones simples por substring.
# - Sin colores, sin 'access', sin Option, sin flush.

import os, strutils, times, tables
import nimcrypto          # necesitas: nimble install nimcrypto (si no lo tienes)

type
  FileState = object
    mtime: int64     # epoch (segundos)
    hash: string
  FileMap = Table[string, FileState]

const
  DB_FILE  = "/tmp/nimwatch.db"
  EXCLUDES = @[".cache/", ".npm/", ".local/share/", ".mozilla/", ".thumbnails/"]

# -------- Utilidades --------
proc excluded(p: string): bool =
  for e in EXCLUDES:
    if p.contains(e): return true
  false

proc safeMTime(p: string): int64 =
  try:
    let fi = getFileInfo(p)
    when compiles(fi.modificationTime):
      fi.modificationTime.toUnix()
    elif compiles(fi.lastWriteTime):
      fi.lastWriteTime.toUnix()
    else:
      0
  except:
    0

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

# -------- Persistencia --------
# Línea: path|mtime|hash
proc saveMap(m: FileMap) =
  var lines: seq[string] = @[]
  for k,v in m: lines.add k & "|" & $v.mtime & "|" & v.hash
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

# -------- Escaneo --------
proc scan(root: string): FileMap =
  var m = initTable[string, FileState]()
  for p in walkDirRec(root):
    if excluded(p): continue
    if fileExists(p):
      m[p] = FileState(mtime: safeMTime(p), hash: fileSha256(p))
  m

# -------- Baseline --------
proc buildBaseline(root: string): FileMap =
  echo "[*] Creando baseline..."
  let m = scan(root)
  saveMap(m)
  echo "[*] Baseline con ", m.len, " archivos."
  m

# -------- Comparación --------
proc compareAndReport(prev, cur: FileMap) =
  # Archivos nuevos / cambiados
  for k, v in cur:
    if k in prev:
      let pv = prev[k]
      if v.hash != pv.hash:
        echo "[CAMBIADO] ", k
    else:
      echo "[NUEVO] ", k
  # Eliminados
  for k in prev.keys:
    if k notin cur:
      echo "[ELIMINADO] ", k

# -------- Intervalo --------
proc askInterval(): int =
  echo "Intervalo (segundos) [Enter=60]: "
  let s = readLine(stdin).strip()
  if s.len == 0: return 60
  try: parseInt(s) except: 60

# -------- Monitor --------
proc monitor(root: string, interval: int) =
  var prev = loadMap()
  if prev.len == 0:
    prev = buildBaseline(root)
  else:
    echo "[*] Baseline previa cargada: ", prev.len, " archivos."
  while true:
    sleep(interval * 1000)
    let cur = scan(root)
    compareAndReport(prev, cur)
    saveMap(cur)
    echo "[OK] Chequeo ", now()
    prev = cur

when isMainModule:
  let home = getHomeDir()
  echo "Directorio monitoreado: ", home
  let interval = askInterval()
  monitor(home, interval)
