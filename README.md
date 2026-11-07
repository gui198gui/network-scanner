# netscan 🔎

Scanner e monitor de rede em **Python**, feito só com a biblioteca standard (não precisa de `pip install`).

Faz três coisas:

| Comando    | O que faz |
|------------|-----------|
| `discover` | Descobre os hosts ativos numa rede (ping sweep em paralelo), com DNS reverso e scan de portas opcionais |
| `ports`    | Testa portas TCP abertas num host e identifica o serviço habitual de cada porta |
| `monitor`  | Faz ping periódico a uma lista de hosts e regista em CSV sempre que um host cai ou volta |

> ⚠️ Usa esta ferramenta apenas em redes tuas ou onde tenhas autorização para o fazer.

## Requisitos

- Python 3.9 ou superior
- Windows, Linux ou macOS (usa o comando `ping` do sistema)

## Utilização

```bash
# Descobrir hosts ativos na rede de casa
python netscan.py discover 192.168.1.0/24

# ... com hostnames e portas comuns, e guardar em CSV
python netscan.py discover 192.168.1.0/24 -r -p common -o resultados.csv

# Testar portas num host (portas comuns por omissão)
python netscan.py ports 192.168.1.1
python netscan.py ports scanme.nmap.org -p 1-1024

# Monitorizar hosts a cada 5 segundos e registar quedas
python netscan.py monitor 192.168.1.1 8.8.8.8 -i 5 -l quedas.csv
python netscan.py monitor -f hosts.example.txt -l quedas.csv
```

Ajuda de cada comando: `python netscan.py <comando> -h`

### Exemplo de saída

```
[2026-11-07 21:05:08] A procurar hosts ativos em 192.168.1.0/24 (254 endereços, 64 threads)...

IP                 Latência  Hostname                       Portas abertas
--------------------------------------------------------------------------------
192.168.1.1          3.6 ms  router.home                    53/DNS, 80/HTTP, 443/HTTPS

1 host(s) ativo(s) de 254.
```

```
[2026-11-07 21:05:08] UP   192.168.1.1 (3.4 ms)
[2026-11-07 21:05:08] DOWN 192.168.1.50
[2026-11-07 21:07:18] UP   192.168.1.50 (5.1 ms)  <-- mudou de estado
```

## Como funciona

- **Ping sweep:** `ipaddress` gera os endereços da rede e um `ThreadPoolExecutor` faz os pings em paralelo, chamando o `ping` do sistema (`-n` no Windows, `-c` no Linux/macOS).
- **Scan de portas:** é um *TCP connect scan*: tenta abrir uma ligação (`socket.connect_ex`) a cada porta. Se a ligação for aceite, a porta está aberta.
- **Monitor:** guarda o último estado de cada host e só escreve no log quando o estado muda (UP → DOWN ou DOWN → UP).
- **Exportação:** os resultados podem ser guardados em `.json` ou `.csv`.

## Testes

```bash
python -m unittest discover -s tests -v
```

## Ideias para evoluir

- Ler o endereço MAC e o fabricante (tabela ARP)
- Alertas por email ou Telegram quando um host cai
- Interface web simples com o histórico do monitor

## Autor

**Guilherme Martins**, estudante de Engenharia Informática no IPCB.
[LinkedIn](https://www.linkedin.com/in/guilherme-martins-158279309/) · [GitHub](https://github.com/gui198gui)
