<?php

namespace AuthxAuth;

use AuthxAuth\Http\Middleware\EnsureUserIsAdmin;
use AuthxAuth\Socialite\AuthxProvider;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;

class AuthxAuthServiceProvider extends ServiceProvider
{
    /**
     * Register package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/authx-auth.php', 'authx-auth');

        $this->app->singleton(AuthxAuthConfig::class, AuthxAuthConfig::class);
        $this->app->singleton(AdminEmailAllowlist::class, AdminEmailAllowlist::class);
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->registerSocialiteDriver();
        $this->registerMiddlewareAlias();
        $this->loadRoutesFrom(__DIR__.'/../routes/authx.php');
        $this->publishes([
            __DIR__.'/../config/authx-auth.php' => config_path('authx-auth.php'),
        ], 'authx-auth-config');
    }

    protected function registerSocialiteDriver(): void
    {
        Socialite::extend('authx', function ($app): AuthxProvider {
            /** @var AuthxAuthConfig $config */
            $config = $app->make(AuthxAuthConfig::class);

            /** @var array<string, mixed> $httpClientOptions */
            $httpClientOptions = [
                'verify' => $config->verifySsl(),
            ];

            return (new AuthxProvider(
                $app['request'],
                $config->clientId(),
                $config->clientSecret(),
                $config->redirectUri(),
                $httpClientOptions,
            ))->setAuthxUrl($config->authxUrl());
        });
    }

    protected function registerMiddlewareAlias(): void
    {
        $this->app['router']->aliasMiddleware('admin', EnsureUserIsAdmin::class);
    }
}
