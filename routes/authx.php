<?php

use AuthxAuth\Http\Controllers\AuthxAuthController;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Route;

Route::middleware('web')->group(function (): void {
    Route::get('login', fn (): RedirectResponse => redirect()->route('auth.redirect'))
        ->middleware('guest')
        ->name('login');

    Route::get('register', fn (): RedirectResponse => redirect()->route('auth.redirect'))
        ->middleware('guest')
        ->name('register');

    Route::get('forgot-password', fn (): RedirectResponse => redirect()->route('auth.redirect'))
        ->middleware('guest')
        ->name('password.request');

    Route::get('auth/redirect', [AuthxAuthController::class, 'redirect'])
        ->middleware('guest')
        ->name('auth.redirect');

    Route::get('auth/callback', [AuthxAuthController::class, 'callback'])
        ->middleware('guest')
        ->name('auth.callback');

    Route::post('logout', [AuthxAuthController::class, 'logout'])
        ->middleware('auth')
        ->name('logout');
});
