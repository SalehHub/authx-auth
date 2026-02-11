<?php

namespace AuthxAuth\Http\Controllers;

use AuthxAuth\AdminEmailAllowlist;
use AuthxAuth\AuthxAuthConfig;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Throwable;

class AuthxAuthController
{
    public function __construct(
        protected AdminEmailAllowlist $adminEmailAllowlist,
        protected AuthxAuthConfig $config,
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

        $name = $authxUser->getName();
        $nickname = $authxUser->getNickname();
        $id = $authxUser->getId();
        $avatar = $authxUser->getAvatar();
        $email = $authxUser->getEmail();
        $emailVerifiedAt = $rawUser['email_verified_at'] ?? null;
        $authProvider = $rawUser['auth_provider'] ?? null;

        abort_if(blank($email), 422, 'AuthX did not return a valid email address.');
        abort_if($this->config->preventNonAdminUserCreation() && ! $this->adminEmailAllowlist->allows($email),403, 'Only admin users can access this application.');

        /** @var class-string<Model> $userModelClass */
        $userModelClass = $this->config->userModel();
        abort_unless(class_exists($userModelClass), 500, 'The users auth provider model is not configured correctly.');

        $table = (new $userModelClass)->getTable();
        $columns = Schema::getColumnListing($table);


        $attributes = [];
        if (in_array('authx_id', $columns, true) && filled($id)) {
            $attributes['authx_id'] =  $id;
        }

        if (in_array('name', $columns, true) ) {
            $attributes['name'] =  filled($name) ? $name : Str::before($email, '@');
        }

        if (in_array('nickname', $columns, true) && filled($nickname)) {
            $attributes['nickname'] =  $nickname;
        }

        if (in_array('avatar', $columns, true) && filled($avatar)) {
            $attributes['avatar'] = $avatar;
        }

        if (in_array('email_verified_at', $columns, true) && filled($emailVerifiedAt)) {
            $attributes['email_verified_at'] = CarbonImmutable::parse($emailVerifiedAt);
        }

        if (in_array('auth_provider', $columns, true) && filled($authProvider) ) {
            $attributes['auth_provider'] = $authProvider;

            $providerIdColumn = $authProvider.'_id';
            $providerIdValue = $rawUser[$providerIdColumn] ?? null;

            if (in_array($providerIdColumn, $columns, true) && filled($providerIdValue)) {
                $attributes[$providerIdColumn] = $providerIdValue;
            }
        }


        /** @var Model|null $existingUser */
        $existingUser = $userModelClass::query()->where('email', $email)->first();


        /** @var Model $user */
        $user = $existingUser ?? new $userModelClass;
        $user->forceFill(array_merge(['email' => $email], $attributes));
        $user->save();

        Auth::guard('web')->login($user, remember: $this->config->rememberUser());
        $request->session()->regenerate();

        return redirect()->intended(route($this->config->postLoginRedirectRoute()));
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

}
