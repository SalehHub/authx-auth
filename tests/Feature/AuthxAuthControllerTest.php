<?php

namespace AuthxAuth\Tests\Feature;

use AuthxAuth\Tests\Fixtures\RestrictedUser;
use AuthxAuth\Tests\Fixtures\User;
use AuthxAuth\Tests\TestCase;
use Carbon\CarbonImmutable;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Test;

class AuthxAuthControllerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    #[After]
    public function resetCarbon(): void
    {
        CarbonImmutable::setTestNow();
    }

    #[Test]
    public function login_register_and_forgot_password_routes_redirect_to_auth_redirect(): void
    {
        $this->get('/login')->assertRedirect(route('auth.redirect'));
        $this->get('/register')->assertRedirect(route('auth.redirect'));
        $this->get('/forgot-password')->assertRedirect(route('auth.redirect'));
    }

    #[Test]
    public function auth_redirect_route_uses_socialite_redirect(): void
    {
        $provider = Mockery::mock();
        $provider->shouldReceive('redirect')->once()->andReturn(redirect('/oauth/authorize'));
        Socialite::shouldReceive('driver')->once()->with('authx')->andReturn($provider);

        $this->get('/auth/redirect')->assertRedirect('/oauth/authorize');
    }

    #[Test]
    public function callback_creates_or_updates_user_from_authx_payload(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-02-11T12:00:00Z'));

        $this->fakeSocialiteUser(
            mapped: [
                'id' => '17',
                'name' => '',
                'email' => 'admin@example.com',
                'avatar' => 'https://cdn.example.test/avatar.png',
            ],
            raw: [
                'email_verified_at' => '2026-02-10T01:02:03Z',
                'email_verified' => false,
            ],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'admin@example.com')->firstOrFail();

        $this->assertSame('admin@example.com', $user->name);
        $this->assertSame(17, $user->authx_id);
        $this->assertSame('authx', $user->auth_provider);
        $this->assertSame('https://cdn.example.test/avatar.png', $user->avatar);
        $this->assertSame(
            '2026-02-10 01:02:03',
            CarbonImmutable::parse((string) $user->email_verified_at)->utc()->toDateTimeString()
        );
        $this->assertAuthenticatedAs($user);
    }

    #[Test]
    public function callback_uses_email_verified_boolean_when_timestamp_missing(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-02-11T16:30:00Z'));

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 11,
                'name' => 'Jane',
                'email' => 'jane@example.com',
                'avatar' => null,
            ],
            raw: [
                'email_verified' => true,
            ],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'jane@example.com')->firstOrFail();
        $this->assertSame('authx', $user->auth_provider);
        $this->assertSame(
            '2026-02-11 16:30:00',
            CarbonImmutable::parse((string) $user->email_verified_at)->utc()->toDateTimeString()
        );
    }

    #[Test]
    public function callback_updates_non_fillable_attributes_on_restricted_user_model(): void
    {
        config()->set('auth.providers.users.model', RestrictedUser::class);

        $this->fakeSocialiteUser(
            mapped: [
                'id' => '33',
                'name' => 'Restricted',
                'email' => 'restricted@example.com',
                'avatar' => null,
            ],
            raw: [
                'email_verified_at' => '2026-02-10T08:00:00Z',
                'google_id' => 'google-123',
            ],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = RestrictedUser::query()->where('email', 'restricted@example.com')->firstOrFail();
        $this->assertSame(33, $user->authx_id);
        $this->assertSame('google', $user->auth_provider);
        $this->assertSame(
            '2026-02-10 08:00:00',
            CarbonImmutable::parse((string) $user->email_verified_at)->utc()->toDateTimeString()
        );
    }

    #[Test]
    public function callback_rejects_missing_email_from_authx(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 1,
                'name' => 'No Email',
                'email' => null,
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertStatus(422);
    }

    #[Test]
    public function callback_rejects_non_admin_creation_when_enabled(): void
    {
        config()->set('authx-auth.prevent_non_admin_user_creation', true);
        config()->set('authx-auth.admin_emails', ['admin@example.com']);

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 2,
                'name' => 'Blocked',
                'email' => 'blocked@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertForbidden();
        $this->assertSame(0, User::query()->count());
    }

    #[Test]
    public function callback_fails_when_user_model_class_is_invalid(): void
    {
        config()->set('auth.providers.users.model', 'Not\\A\\Real\\Model');

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 3,
                'name' => 'Example',
                'email' => 'example@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertStatus(500);
    }

    #[Test]
    public function logout_route_logs_out_and_redirects_home(): void
    {
        $user = User::query()->create([
            'name' => 'Logout User',
            'email' => 'logout@example.com',
        ]);

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirect('/');
        $this->assertGuest();
    }

    /**
     * @param  array<string, mixed>  $mapped
     * @param  array<string, mixed>  $raw
     */
    private function fakeSocialiteUser(array $mapped, array $raw): void
    {
        $socialiteUser = new SocialiteUser;
        $socialiteUser->setRaw($raw)->map($mapped);

        $provider = Mockery::mock();
        $provider->shouldReceive('user')->once()->andReturn($socialiteUser);

        Socialite::shouldReceive('driver')
            ->once()
            ->with('authx')
            ->andReturn($provider);
    }
}
