# MikroTik Node Server

A minimal Node.js API service to talk to MikroTik routers via the RouterOS API.

## Setup

```bash
npm install
cp .env.example .env
npm run dev
```

## API

POST `/api/mikrotik/command`

Body:

```json
{
  "host": "192.168.88.1",
  "user": "admin",
  "password": "secret",
  "port": 8728,
  "command": "/interface/print",
  "args": []
}
```

Note: In production, send a `routerId` and resolve credentials server-side.

Convenience Endpoints (POST)

- `/api/mikrotik/interfaces` → `/interface/print`
- `/api/mikrotik/ip-addresses` → `/ip/address/print`
- `/api/mikrotik/ppp-secrets` → `/ppp/secret/print`
- GET `/health` → { status, port }

## Build single-file executables

```bash
npm run build:exe
```

Outputs binaries in `dist/` for Linux, macOS and Windows.


