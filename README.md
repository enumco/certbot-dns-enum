# certbot-dns-enum

[enum](https://enum.co) DNS Authenticator plugin for [Certbot](https://certbot.eff.org).

This plugin automates the process of completing a `dns-01` challenge by creating, and subsequently removing, TXT records using the enum API. It supports wildcard certificates.

## Installation

```sh
pip install certbot-dns-enum
```

## Credentials

The plugin uses the API key of an enum service account. Create a service account with an API key using [enumctl](https://docs.enum.co/cli/installation/):

```sh
enumctl service-accounts create certbot --key certbot --expires-in 1y
```

Store the API key and the ID of the project containing your DNS zone in a credentials file:

```ini
# enum API credentials used by Certbot
dns_enum_api_key = enum_sk_...
dns_enum_project_id = proj-...
```

The API key can manage all DNS zones in its project. Protect the file like a password, for example with `chmod 600`. Certbot warns if the file is readable by other users.

## Arguments

| Argument | Description |
|---|---|
| `--authenticator dns-enum` | Select the enum authenticator plugin (required) |
| `--dns-enum-credentials` | Path to the credentials INI file (required) |
| `--dns-enum-propagation-seconds` | Seconds to wait for DNS changes to propagate before asking the ACME server to verify the record (default: 30) |

## Examples

Certificate for `example.com`:

```sh
certbot certonly \
  --authenticator dns-enum \
  --dns-enum-credentials ~/.secrets/certbot/enum.ini \
  -d example.com
```

Wildcard certificate for `example.com` and `*.example.com`:

```sh
certbot certonly \
  --authenticator dns-enum \
  --dns-enum-credentials ~/.secrets/certbot/enum.ini \
  -d example.com \
  -d '*.example.com'
```
