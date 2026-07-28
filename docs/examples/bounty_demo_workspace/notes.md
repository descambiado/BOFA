# Analyst Notes

- `beta.acme.test` parece una superficie menos trillada que el dominio principal.
- `workspace`, `tenant_id`, `debug` y `return` merecen revision manual.
- Hay una hipotesis razonable de authz inconsistente entre `/api/v2/admin/export` y endpoints internos.
- `admin.js` y `app.bundle.js` son buenos candidatos para seguir con `js_api_diff` o `surface_regression`.
