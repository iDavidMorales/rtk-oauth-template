# Routicket OAuth Template

Plantilla mínima para integrar **Inicio de sesión con Routicket** en aplicaciones de terceros.

El objetivo es ofrecer una experiencia parecida a **Continuar con Facebook / Google / X**:

1. La aplicación redirige al usuario a Routicket.
2. Routicket muestra la pantalla de autorización de la aplicación.
3. El usuario acepta o cancela.
4. Routicket devuelve un `authorization_code` temporal.
5. El backend de la aplicación intercambia ese código por un `access_token`.
6. La aplicación consulta el perfil del usuario con el token.

La plantilla usa **OAuth 2.0 Authorization Code + PKCE (S256)** y está pensada para ejecutarse como **Cloudflare Worker**, aunque el mismo flujo puede adaptarse a Node.js, PHP, Python, Vercel Functions u otros backends.

## Datos básicos obtenidos

Una vez autorizado el acceso, el ejemplo consulta:

`GET https://routicket.com/oauth/userinfo.php`

con:

```http
Authorization: Bearer ACCESS_TOKEN
Accept: application/json
```

El perfil normalizado que usa esta plantilla contiene:

```json
{
  "id": 123,
  "name": "David Morales",
  "email": "usuario@example.com",
  "photo": "https://routicket.com/.../avatar.jpg"
}
```

## Endpoints OAuth de Routicket

| Función | URL |
| --- | --- |
| Autorizar aplicación | `https://routicket.com/oauth/authorize.php` |
| Intercambiar código por token | `https://routicket.com/oauth/token.php` |
| Obtener perfil | `https://routicket.com/oauth/userinfo.php` |

## Flujo completo

```text
Usuario
  |
  | click "Continuar con Routicket"
  v
Aplicación /oauth/login
  |
  | genera state + code_verifier + code_challenge
  v
routicket.com/oauth/authorize.php
  |
  | muestra nombre de la aplicación y permisos solicitados
  | [Autorizar] [Cancelar]
  v
Aplicación /oauth/callback?code=...&state=...
  |
  | POST authorization_code + code_verifier
  v
routicket.com/oauth/token.php
  |
  | access_token
  v
routicket.com/oauth/userinfo.php
  |
  | id + nombre + correo + foto
  v
Aplicación autenticada
```

## Seguridad

La plantilla implementa:

- `state` aleatorio para proteger contra CSRF.
- PKCE con `code_verifier` y `code_challenge` SHA-256.
- El `code_verifier` se guarda temporalmente durante 10 minutos.
- El `access_token` nunca se expone al navegador.
- La aplicación consulta el perfil desde el backend.
- Cierre de sesión local eliminando token y perfil guardados.

> En producción se recomienda asociar tokens y sesiones a cada usuario/navegador mediante cookies de sesión seguras o almacenamiento por sesión. El almacenamiento KV global de este ejemplo está simplificado deliberadamente para que el flujo OAuth sea fácil de entender.

## Estructura

```text
rtk-oauth-template/
├─ public/
│  └─ index.html       # Login + visualización del perfil
├─ worker.js           # OAuth, callback, userinfo, status y logout
├─ wrangler.jsonc      # Configuración Cloudflare Worker
├─ .dev.vars.example   # Variables locales de ejemplo
└─ README.md
```

## Configuración

### 1. Registrar la aplicación en Routicket

La aplicación debe contar con un `client_id` y una URL de retorno permitida.

Ejemplo:

```text
CLIENT_ID=mi_aplicacion
REDIRECT_URI=https://mi-app.example.com/oauth/callback
```

La URL configurada en Routicket debe coincidir exactamente con la que envía la aplicación durante OAuth.

### 2. Crear KV en Cloudflare

```bash
npx wrangler kv namespace create OAUTH_KV
```

Después copia el ID generado dentro de `wrangler.jsonc`.

### 3. Configurar variables

En producción configura:

```text
RTK_CLIENT_ID
RTK_REDIRECT_URI
APP_URL
```

Para desarrollo local puedes copiar `.dev.vars.example` como `.dev.vars`.

### 4. Ejecutar

```bash
npm install -g wrangler
wrangler dev
```

### 5. Publicar

```bash
wrangler deploy
```

## Rutas del ejemplo

### `GET /oauth/login`

Inicia OAuth. Genera PKCE y redirige a la página de autorización de Routicket.

### `GET /oauth/callback`

Recibe `code` y `state`, verifica el flujo PKCE, obtiene el token y posteriormente consulta `/oauth/userinfo.php`.

### `GET /oauth/status`

Devuelve si existe una sesión de Routicket y el perfil normalizado.

Ejemplo:

```json
{
  "ok": true,
  "connected": true,
  "profile": {
    "id": 123,
    "name": "David Morales",
    "email": "usuario@example.com",
    "photo": "https://..."
  }
}
```

### `POST /oauth/logout`

Elimina token, refresh token y perfil guardados por la aplicación.

## Botón de login

La aplicación solamente necesita enviar al usuario a:

```html
<a href="/oauth/login">Continuar con Routicket</a>
```

La pantalla de autorización **no debe simularse dentro de la aplicación cliente**. Debe mostrarse desde `routicket.com/oauth/authorize.php`, para que el usuario pueda identificar claramente que está autorizando una aplicación externa.

## Permisos / scopes recomendados

Para este template básico basta con un scope de perfil, por ejemplo:

```text
profile email
```

La pantalla de autorización debería informar claramente que la app solicita acceso a:

- Nombre del usuario.
- Foto de perfil.
- Correo electrónico.
- Identificador único de Routicket.

Una aplicación que posteriormente necesite información adicional debería solicitar scopes adicionales de forma explícita.

## Ejemplo real utilizado como referencia

Esta plantilla está basada en el flujo OAuth usado por `iDavidMorales/dexter-to-do`, pero elimina toda la lógica específica de tareas, sincronización y Dexter Agent para quedar como un ejemplo reutilizable por terceros.

## Resultado esperado para desarrolladores

Un desarrollador puede clonar este repositorio, cambiar solamente:

```text
RTK_CLIENT_ID
RTK_REDIRECT_URI
APP_URL
```

y tener una demostración funcional de **Login con Routicket** y lectura del perfil del usuario.

## Licencia

Puedes utilizar esta plantilla como base para aplicaciones que se integren con Routicket.
