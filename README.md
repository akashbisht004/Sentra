# Sentra

## Architecture Diagram

```
Frontend
   │
   │ email + password
   ▼
Developer's Backend
   │
   ▼
 SENTRA
   │
   ├── validate
   ├── hash/verify password
   ├── authentication logic
   ├── create/verify tokens
   └── authorization
   │
   ▼
 UserAdapter
   │
   ▼
Developer's DB
```