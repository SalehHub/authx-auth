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
            $config = $app['config']->get('authx-auth.authx', []);

            /** @var array<string, mixed> $httpClientOptions */
            $httpClientOptions = [
                'verify' => filter_var($config['verify_ssl'] ?? true, FILTER_VALIDATE_BOOL),
            ];

            return new AuthxProvider(
                $app['request'],
                $config['client_id'],
                $config['client_secret'],
                $config['redirect'],
                $httpClientOptions,
            );
        });
    }

    protected function registerMiddlewareAlias(): void
    {
        $this->app['router']->aliasMiddleware('admin', EnsureUserIsAdmin::class);
    }
}
