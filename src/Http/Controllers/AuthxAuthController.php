<?php

namespace AuthxAuth\Http\Controllers;

use AuthxAuth\AdminEmailAllowlist;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Facades\Socialite;

class AuthxAuthController
{
    public function __construct(
        protected AdminEmailAllowlist $adminEmailAllowlist,
    ) {}

    /**
     * Redirect the user to AuthX.
     */
    public function redirect(): RedirectResponse
    {
        /** @var RedirectResponse $response */
        $response = Socialite::driver('authx')->redirect();

        return $response;
    }

    /**
     * Handle the AuthX OAuth callback and sign the user in.
     */
    public function callback(Request $request): RedirectResponse
    {
        $authxUser = Socialite::driver('authx')->user();
        $rawUser = is_array($authxUser->user ?? null) ? $authxUser->user : [];

        $email = $authxUser->getEmail();

        abort_unless(is_string($email) && $email !== '', 422, 'AuthX did not return a valid email address.');

        $name = $authxUser->getName();
        $id = $authxUser->getId();
        $avatar = $authxUser->getAvatar();
        $preventNonAdminUserCreation = filter_var(
            config('authx-auth.prevent_non_admin_user_creation', false),
            FILTER_VALIDATE_BOOL
        );

        if ($preventNonAdminUserCreation && ! $this->adminEmailAllowlist->allows($email)) {
            abort(403, 'Only admin users can access this application.');
        }

        $userModelClass = (string) config('auth.providers.users.model');

        abort_unless(class_exists($userModelClass), 500, 'The users auth provider model is not configured correctly.');

        /** @var class-string<Model> $userModelClass */
        $attributes = [
            'name' => is_string($name) && $name !== '' ? $name : $email,
        ];

        $table = (new $userModelClass)->getTable();
        $columns = Schema::getColumnListing($table);
        /** @var Model|null $existingUser */
        $existingUser = $userModelClass::query()->where('email', $email)->first();

        if (in_array('authx_id', $columns, true)) {
            $attributes['authx_id'] = is_numeric($id) ? (int) $id : null;
        }

        if (in_array('avatar', $columns, true)) {
            $attributes['avatar'] = is_string($avatar) ? $avatar : '';
        }

        if (in_array('email_verified_at', $columns, true)) {
            $attributes['email_verified_at'] = $this->resolveEmailVerifiedAt($rawUser);
        }

        if (in_array('auth_provider', $columns, true)) {
            $attributes['auth_provider'] = $this->resolveAuthProvider($rawUser, $existingUser);
        }

        /** @var Model $user */
        $user = $existingUser ?? new $userModelClass;
        $user->forceFill(array_merge(['email' => $email], $attributes));
        $user->save();

        Auth::guard('web')->login($user, remember: true);
        $request->session()->regenerate();

        $postLoginRedirectRoute = (string) config('authx-auth.post_login_redirect_route', 'dashboard');

        return redirect()->intended(route($postLoginRedirectRoute));
    }

    /**
     * Log the user out of the local application session.
     */
    public function logout(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }

    /**
     * @param  array<string, mixed>  $rawUser
     */
    protected function resolveEmailVerifiedAt(array $rawUser): ?CarbonImmutable
    {
        $authxEmailVerifiedAt = $rawUser['email_verified_at'] ?? null;
        $authxEmailVerified = filter_var(
            $rawUser['email_verified'] ?? null,
            FILTER_VALIDATE_BOOL,
            FILTER_NULL_ON_FAILURE
        );

        if (is_string($authxEmailVerifiedAt) && trim($authxEmailVerifiedAt) !== '') {
            try {
                return CarbonImmutable::parse($authxEmailVerifiedAt);
            } catch (\Throwable) {
                // Ignore invalid timestamps and fallback to email_verified.
            }
        }

        if ($authxEmailVerified === true) {
            return CarbonImmutable::now();
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $rawUser
     */
    protected function resolveAuthProvider(array $rawUser, ?Model $existingUser = null): string
    {
        $providerFromPayload = $rawUser['auth_provider'] ?? null;

        if (is_string($providerFromPayload) && trim($providerFromPayload) !== '') {
            return mb_strtolower(trim($providerFromPayload));
        }

        if ($this->hasExternalProviderId('google', $rawUser, $existingUser)) {
            return 'google';
        }

        return 'authx';
    }

    /**
     * @param  array<string, mixed>  $rawUser
     */
    protected function hasExternalProviderId(string $provider, array $rawUser, ?Model $existingUser): bool
    {
        $column = $provider.'_id';
        $rawValue = $rawUser[$column] ?? null;
        $existingValue = $existingUser?->getAttribute($column);

        return (is_string($rawValue) && trim($rawValue) !== '')
            || is_numeric($rawValue)
            || (is_string($existingValue) && trim($existingValue) !== '')
            || is_numeric($existingValue);
    }
}
