<?php

namespace AuthxAuth;

class AuthxAuthConfig
{
    /**
     * @return list<string>
     */
    public function adminEmails(): array
    {
        $emails = config('authx-auth.admin_emails', []);

        return is_array($emails) ? $emails : [];
    }

    public function preventNonAdminUserCreation(): bool
    {
        return filter_var(
            config('authx-auth.prevent_non_admin_user_creation', false),
            FILTER_VALIDATE_BOOL
        );
    }

    public function rememberUser(): bool
    {
        return filter_var(
            config('authx-auth.remember_user', true),
            FILTER_VALIDATE_BOOL
        );
    }

    public function postLoginRedirectRoute(): string
    {
        return (string) config('authx-auth.post_login_redirect_route', 'dashboard');
    }

    /**
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    public function userModel(): string
    {
        return (string) config('auth.providers.users.model');
    }

    public function authxUrl(): string
    {
        return (string) config('authx-auth.authx.url', 'http://localhost:8000');
    }

    public function authxLogoutUrl(): string
    {
        $logoutUrl = config('authx-auth.authx.logout_url');

        if (is_string($logoutUrl) && filled($logoutUrl)) {
            return $logoutUrl;
        }

        return rtrim($this->authxUrl(), '/').'/logout';
    }

    public function logoutFromAuthx(): bool
    {
        return filter_var(
            config('authx-auth.authx.logout_from_authx', true),
            FILTER_VALIDATE_BOOL
        );
    }

    public function verifySsl(): bool
    {
        return filter_var(
            config('authx-auth.authx.verify_ssl', true),
            FILTER_VALIDATE_BOOL
        );
    }

    public function clientId(): ?string
    {
        return config('authx-auth.authx.client_id');
    }

    public function clientSecret(): ?string
    {
        return config('authx-auth.authx.client_secret');
    }

    public function redirectUri(): ?string
    {
        return config('authx-auth.authx.redirect');
    }
}
