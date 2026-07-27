# AdminZero CTF — Break The Wall 🛡️

> 7 security layers. One flag. Can you extract it?

Built by **GlitchGo** + **AdminZero** | [@issak]

---

## Stack
- **Backend** → Node.js + Express + SQLite (Railway)
- **Frontend** → Pure HTML/CSS/JS (Netlify)
- **Core** → `node-sql-parser` AST engine

## Security Layers
| Layer | Name | What it does |
|---|---|---|
| L1 | Rate Limiter | 8 req/min per IP |
| L2 | Encoding Detector | Blocks hex, unicode, URL encoding |
| L3 | Keyword Blacklist | Blocks dangerous SQL keywords |
| L4 | Complexity Scorer | Rejects deep/complex AST trees |
| L5 | AST Parser | Rejects invalid SQL syntax |
| L6 | Intent Validator | SELECT only, whitelisted tables |
| L7 | Query Reconstructor | Never runs original string |

## Deploy Steps → See DEPLOY.md
