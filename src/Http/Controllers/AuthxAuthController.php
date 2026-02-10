<?php

namespace AuthxAuth\Http\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Facades\Socialite;

class AuthxAuthController
{
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

        $email = $authxUser->getEmail();

        abort_unless(is_string($email) && $email !== '', 422, 'AuthX did not return a valid email address.');

        $name = $authxUser->getName();
        $id = $authxUser->getId();
        $avatar = $authxUser->getAvatar();

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

        /** @var Model $user */
        $user = $userModelClass::query()->updateOrCreate(
            ['email' => $email],
            $attributes,
        );

        Auth::guard('web')->login($user, remember: true);
        $request->session()->regenerate();

        return redirect()->intended(route('dashboard'));
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
