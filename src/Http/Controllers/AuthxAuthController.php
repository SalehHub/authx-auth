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

        if (Schema::hasColumn($table, 'authx_id')) {
            $attributes['authx_id'] = is_numeric($id) ? (int) $id : null;
        }

        if (Schema::hasColumn($table, 'avatar')) {
            $attributes['avatar'] = is_string($avatar) ? $avatar : '';
        }

        if (Schema::hasColumn($table, 'email_verified_at')) {
            $attributes['email_verified_at'] = $this->resolveEmailVerifiedAt($rawUser);
        }

        /** @var Model $user */
        $user = $userModelClass::query()->updateOrCreate(
            ['email' => $email],
            $attributes,
        );

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
}
