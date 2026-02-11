# authx-auth

Reusable AuthX authentication package for Laravel apps.

It provides:
- a custom Socialite driver (`authx`)
- built-in auth routes and controller actions (login/register/forgot-password redirect to AuthX)
- local session logout route
- admin-email allowlist middleware alias (`admin`)

## Requirements

- PHP `^8.4`
- Laravel `^12.0`
- `laravel/socialite` `^5.24` (installed automatically as a dependency)

## Installation

```bash
composer require salehhub/authx-auth
```

The service provider is auto-discovered.

Publish config:

```bash
php artisan vendor:publish --tag=authx-auth-config
```

## Configuration

Set these variables in your `.env`:

```env
AUTHX_CLIENT_ID=your-client-id
AUTHX_CLIENT_SECRET=your-client-secret
AUTHX_REDIRECT_URI="${APP_URL}/auth/callback"
AUTHX_URL=http://localhost:8000
AUTHX_VERIFY_SSL=true
AUTHX_POST_LOGIN_REDIRECT_ROUTE=dashboard
AUTHX_PREVENT_NON_ADMIN_USER_CREATION=false

# Comma-separated admin allowlist
ADMIN_EMAILS=admin@example.com,owner@example.com
```

## What This Package Registers

### Routes

The package loads these web routes:

- `GET /login` -> redirects to `auth.redirect`
- `GET /register` -> redirects to `auth.redirect`
- `GET /forgot-password` -> redirects to `auth.redirect`
- `GET /auth/redirect` -> starts AuthX OAuth flow
- `GET /auth/callback` -> handles OAuth callback, logs in/upserts user
- `POST /logout` -> logs user out of local Laravel session

### Middleware Alias

- `admin` -> `AuthxAuth\Http\Middleware\EnsureUserIsAdmin`

Use it on protected routes:

```php
Route::middleware(['auth', 'admin'])->group(function () {
    Route::get('/dashboard', fn () => view('dashboard'))->name('dashboard');
});
```

## User Model Notes

On callback, the package updates/creates a user by email using your configured `auth.providers.users.model`.

It always sets:
- `name` (falls back to email if AuthX name is missing)

It conditionally sets these fields only if the user table has matching columns:
- `authx_id`
- `avatar`
- `email_verified_at` (from AuthX `/api/user.email_verified_at`; if absent, `/api/user.email_verified=true` sets it to current time; otherwise stored as `null`)

If you want these values persisted, add nullable columns:

```php
Schema::table('users', function (Blueprint $table) {
    $table->unsignedBigInteger('authx_id')->nullable()->index();
    $table->string('avatar')->nullable();
});
```

## Redirect Behavior

After successful callback, the user is redirected to:

```php
redirect()->intended(route(config('authx-auth.post_login_redirect_route', 'dashboard')))
```

Default route name is `dashboard`. You can override it with `AUTHX_POST_LOGIN_REDIRECT_ROUTE`.

## Admin Allowlist Behavior

When a signed-in user is not in `ADMIN_EMAILS`, the `admin` middleware:
- logs out the user
- invalidates the session
- returns HTTP `403` with message: `Only admin users can access this application.`

If you set `AUTHX_PREVENT_NON_ADMIN_USER_CREATION=true`, non-admin users are rejected during OAuth callback before any `users` table write happens.

## License

MIT
