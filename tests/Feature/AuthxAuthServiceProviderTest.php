<?php

namespace AuthxAuth\Tests\Feature;

use AuthxAuth\AuthxAuthServiceProvider;
use AuthxAuth\Socialite\AuthxProvider;
use AuthxAuth\Tests\TestCase;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use PHPUnit\Framework\Attributes\Test;

class AuthxAuthServiceProviderTest extends TestCase
{
    #[Test]
    public function it_registers_admin_middleware_alias(): void
    {
        $middlewares = $this->app['router']->getMiddleware();

        $this->assertArrayHasKey('admin', $middlewares);
    }

    #[Test]
    public function it_registers_authx_socialite_driver(): void
    {
        /** @var SocialiteFactory $factory */
        $factory = $this->app->make(SocialiteFactory::class);

        $driver = $factory->driver('authx');

        $this->assertInstanceOf(AuthxProvider::class, $driver);
    }

    #[Test]
    public function it_registers_publishable_config_path(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuthxAuthServiceProvider::class, 'authx-auth-config');

        $this->assertNotNull($paths);
        $this->assertCount(1, $paths);
    }
}
