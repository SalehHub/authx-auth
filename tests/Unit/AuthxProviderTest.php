<?php

namespace AuthxAuth\Tests\Unit;

use AuthxAuth\Socialite\AuthxProvider;
use AuthxAuth\Tests\TestCase;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Laravel\Socialite\Two\User;
use PHPUnit\Framework\Attributes\Test;

class AuthxProviderTest extends TestCase
{
    #[Test]
    public function it_builds_expected_auth_and_token_urls(): void
    {
        $provider = new ExposedAuthxProvider(
            Request::create('/'),
            'client-id',
            'secret',
            'https://app.example.test/auth/callback'
        );

        $authUrl = $provider->exposedGetAuthUrl('state-123');

        $this->assertStringContainsString('https://authx.example.test/oauth/authorize', $authUrl);
        $this->assertStringContainsString('client_id=client-id', $authUrl);
        $this->assertStringContainsString('scope=user%3Aread', $authUrl);
        $this->assertStringContainsString('state=state-123', $authUrl);
        $this->assertSame('https://authx.example.test/oauth/token', $provider->exposedGetTokenUrl());
    }

    #[Test]
    public function it_maps_authx_user_payload_to_socialite_user(): void
    {
        $provider = new ExposedAuthxProvider(
            Request::create('/'),
            'client-id',
            'secret',
            'https://app.example.test/auth/callback'
        );

        $user = $provider->exposedMapUserToObject([
            'id' => 5,
            'name' => 'Taylor',
            'email' => 'taylor@example.com',
            'avatar' => 'https://cdn.example.test/avatar.png',
        ]);

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame(5, $user->getId());
        $this->assertSame('Taylor', $user->getName());
        $this->assertSame('taylor@example.com', $user->getEmail());
        $this->assertSame('https://cdn.example.test/avatar.png', $user->getAvatar());
    }

    #[Test]
    public function it_fetches_user_payload_from_authx_api(): void
    {
        $provider = new ExposedAuthxProvider(
            Request::create('/'),
            'client-id',
            'secret',
            'https://app.example.test/auth/callback'
        );

        $mock = new MockHandler([
            new Response(200, [], json_encode(['id' => 9, 'email' => 'api@example.com'], JSON_THROW_ON_ERROR)),
        ]);

        $provider->setHttpClient(new Client([
            'handler' => HandlerStack::create($mock),
        ]));

        $payload = $provider->exposedGetUserByToken('token-abc');

        $this->assertSame(['id' => 9, 'email' => 'api@example.com'], $payload);
    }
}

class ExposedAuthxProvider extends AuthxProvider
{
    public function exposedGetAuthUrl(string $state): string
    {
        return $this->getAuthUrl($state);
    }

    public function exposedGetTokenUrl(): string
    {
        return $this->getTokenUrl();
    }

    /**
     * @param  array<string, mixed>  $user
     */
    public function exposedMapUserToObject(array $user): User
    {
        return $this->mapUserToObject($user);
    }

    /**
     * @return array<string, mixed>
     */
    public function exposedGetUserByToken(string $token): array
    {
        return $this->getUserByToken($token);
    }
}
