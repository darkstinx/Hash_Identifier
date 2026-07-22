# 🔍 Hash Identifier

Herramienta de línea de comandos desarrollada en Python que identifica el tipo de hash a partir de su prefijo, longitud y juego de caracteres. Diseñada para agilizar el reconocimiento de hashes durante pruebas de penetración y CTFs.

---

## ¿Cómo funciona?

El script analiza el hash introducido en tres fases:

1. **Detección de prefijo** — identifica marcadores como `$1$`, `$2a$`, `{SHA}`, `pbkdf2_sha256$`, etc.
2. **Análisis de longitud y caracteres** — determina si el hash usa hexadecimal, base64, decimal u otro alfabeto.
3. **Comparación con la base de datos** — devuelve los posibles tipos de hash junto con los modos de Hashcat y los formatos de John the Ripper listos para usar.

---

## Hashes soportados

| Tipo                   | Hashcat mode      | John format              |
|------------------------|-------------------|--------------------------|
| CRC32                  | 11500             | crc32                    |
| MySQL323               | 200               | mysql                    |
| MD5 / NTLM / MD4       | 0 / 1000 / 900    | raw-md5 / nt / raw-md4   |
| SHA1                   | 100               | raw-sha1                 |
| MySQL 4.1+ (SHA1)      | 300               | mysql-sha1               |
| SHA224                 | 1300              | raw-sha224               |
| SHA256                 | 1400              | raw-sha256               |
| SHA384                 | 10800             | raw-sha384               |
| SHA512                 | 1700              | raw-sha512               |
| MD5 crypt (Unix)       | 500               | md5crypt                 |
| SHA256 crypt (Unix)    | 7400              | sha256crypt              |
| SHA512 crypt (Unix)    | 1800              | sha512crypt              |
| bcrypt                 | 3200              | bcrypt                   |
| phpBB3 / WordPress     | 400               | phpass                   |
| Django PBKDF2-SHA256   | 10000             | django                   |
| LDAP SSHA              | 111               | ssha                     |
| LDAP SHA1              | 101               | nsldap                   |

---

## Instalación

```bash
git clone https://github.com/darkstinx/HashIdentifier
cd HashIdentifier
pip install -r requirements.txt
```

---

## Uso

```bash
# Pasando el hash como argumento
python3 hash_identifier.py <hash>

# Leyendo desde stdin
echo "<hash>" | python3 hash_identifier.py
```

### Ejemplos

```bash
python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```
```
🔍 Hash Identifier
Identificador de tipos de hash · v1.0

   Hash         5f4dcc3b5aa765d61d8327deb882cf99
   Longitud     32
   Prefijo      (ninguno detectado)
   Caracteres   hexadecimal

──────────── Posibles tipos detectados (1) ────────────
┌──────────────────┬──────────────────┬──────────────────────────┐
│ Tipo de hash     │ Hashcat mode     │ John format              │
├──────────────────┼──────────────────┼──────────────────────────┤
│ MD5 / NTLM / MD4 │ 0 / 1000 / 900  │ raw-md5 / nt / raw-md4  │
└──────────────────┴──────────────────┴──────────────────────────┘
```

```bash
python3 hash_identifier.py '$2a$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Vamk8PHm3Q6y1b2'
```
```
🔍 Hash Identifier
Identificador de tipos de hash · v1.0

   Hash         $2a$12$GhvMmNVjRW29ulnudl...
   Longitud     60
   Prefijo      $2a$
   Caracteres   otro

──────────── Posibles tipos detectados (1) ────────────
┌──────────────────┬──────────────────┬──────────────┐
│ Tipo de hash     │ Hashcat mode     │ John format  │
├──────────────────┼──────────────────┼──────────────┤
│ bcrypt           │ 3200             │ bcrypt       │
└──────────────────┴──────────────────┴──────────────┘
```

---

## Requisitos

- Python 3.10+
- [rich](https://github.com/Textualize/rich)

---

## Tecnologías

| Componente | Detalle |
|------------|---------|
| Lenguaje   | Python 3.10+ |
| Interfaz   | rich |
| Detección  | Regex + análisis de longitud y charset |
| Entorno    | Linux (probado en Kali Linux) |

---

## Autor

**Ignacio González Domínguez**  
[GitHub](https://github.com/darkstinx) · [LinkedIn](https://www.linkedin.com/in/ignacio-gonzalez-dominguez/) · [Portfolio](https://darkstinx.github.io)
