> **Descontinuado.** `backend/tools/burp.py` agora fala com a extensão
> oficial **MCP Server** da PortSwigger (BApp Store) via Model Context
> Protocol, em vez desta ponte Java própria. Veja a seção "Extra — Burp
> Suite" no `README.md` da raiz do projeto. Este diretório fica só de
> referência histórica (Community, sem MCP nativo, foi o motivo de existir).

# Cyber Bridge — extensão Burp Suite (legado)

Ponte local entre o Burp Suite (Community, sem REST API/AI nativos — esses
são recursos Pro-only) e o backend Python do `cybersecurity-ai`. Expõe uma
API HTTP mínima em `127.0.0.1` (porta dinâmica) protegida por token, sem
nenhuma dependência externa: só a Montoya API (já embutida em
`burpsuite.jar`) e um servidor HTTP próprio sobre `java.net.ServerSocket`
(`com.sun.net.httpserver` não é visível pro classloader de extensões do Burp).

## Build

```bash
./build.sh
```

Gera `cyber-bridge.jar`. Requer JDK 17+ (usa `switch` com pattern matching)
e o `burpsuite.jar` instalado em `/usr/share/burpsuite/burpsuite.jar`
(ajustável via `BURP_JAR=/caminho/outro.jar ./build.sh`).

## Carregar no Burp

1. Abra o Burp Suite → **Extensions** → **Add**
2. Extension type: **Java**
3. Extension file: selecione `cyber-bridge.jar`
4. Confira em **Output** que apareceu a linha
   `Cyber Bridge listening on 127.0.0.1:<porta>`

## Descoberta

Ao carregar, a extensão escreve `~/.cyber-ai-burp-bridge.json`:

```json
{"port": 41231, "token": "‹uuid›"}
```

O backend Python (`backend/tools/burp.py`) lê esse arquivo a cada chamada —
não precisa reconfigurar nada se você reiniciar o Burp (porta/token mudam,
o arquivo é reescrito). Se a extensão for descarregada, o arquivo é
apagado e as ferramentas do lado Python retornam erro claro.

## Endpoints

Todos exigem header `X-Cyber-Token: <token do arquivo de descoberta>`
(exceto `/health`).

- `GET /health` — `{"status": "ok"}`, sem auth (só confirma que está de pé).
- `GET /proxy/history?limit=50` — últimas N requisições do Proxy history
  (id, method, url, host, port, statusCode, mimeType, time).
- `POST /http/send` — envia uma requisição HTTP através do Burp (mesmo
  motor que o Repeater usa). Body:
  ```json
  {"url": "https://alvo/rota", "method": "GET", "headers": {}, "body": ""}
  ```
  Retorna `{"statusCode": ..., "headers": {...}, "body": "..."}`.

## Modelo de segurança

A extensão é transporte burro — não decide o que é seguro. Todo o gate de
confirmação humana continua no lado Python (`security/safety.py`,
`tools/confirm.py`), igual a `nmap_scan`/`packet_capture`. `/http/send`
manda requisição pra QUALQUER host que você passar: só use contra alvos
que você tem autorização de testar.
