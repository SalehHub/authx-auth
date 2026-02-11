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
    public function auth_redirect_route_returns_inertia_external_redirect_response(): void
    {
        $provider = Mockery::mock();
        $provider->shouldReceive('redirect')->once()->andReturn(redirect('https://authx.example.test/oauth/authorize'));
        Socialite::shouldReceive('driver')->once()->with('authx')->andReturn($provider);

        $response = $this->withHeader('X-Inertia', 'true')->get('/auth/redirect');

        $response->assertStatus(409);
        $response->assertHeader('X-Inertia-Location', 'https://authx.example.test/oauth/authorize');
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

        $this->assertSame('admin', $user->name);
        $this->assertSame(17, $user->authx_id);
        $this->assertSame('local', $user->auth_provider);
        $this->assertSame('https://cdn.example.test/avatar.png', $user->avatar);
        $this->assertSame(
            '2026-02-10 01:02:03',
            CarbonImmutable::parse((string) $user->email_verified_at)->utc()->toDateTimeString()
        );
        $this->assertAuthenticatedAs($user);
    }

    #[Test]
    public function callback_does_not_set_email_verified_at_when_timestamp_missing(): void
    {
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
        $this->assertNull($user->email_verified_at);
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
                'auth_provider' => 'google',
                'google_id' => 'google-123',
            ],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = RestrictedUser::query()->where('email', 'restricted@example.com')->firstOrFail();
        $this->assertSame('google', $user->auth_provider);
        $this->assertSame('google-123', $user->google_id);
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
    public function logout_route_logs_out_and_redirects_to_authx_logout_url(): void
    {
        $user = User::query()->create([
            'name' => 'Logout User',
            'email' => 'logout@example.com',
        ]);

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirect('https://authx.example.test/logout');
        $this->assertGuest();
    }

    #[Test]
    public function logout_route_uses_configured_authx_logout_url_when_provided(): void
    {
        config()->set('authx-auth.authx.logout_url', 'https://authx.example.test/custom-logout');

        $user = User::query()->create([
            'name' => 'Logout User',
            'email' => 'logout@example.com',
        ]);

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirect('https://authx.example.test/custom-logout');
        $this->assertGuest();
    }

    #[Test]
    public function logout_route_does_not_redirect_to_authx_when_disabled_in_config(): void
    {
        config()->set('authx-auth.authx.logout_from_authx', false);

        $user = User::query()->create([
            'name' => 'Logout User',
            'email' => 'logout@example.com',
        ]);

        $response = $this->actingAs($user)->post('/logout');

        $response->assertRedirect('/');
        $this->assertGuest();
    }

    #[Test]
    public function logout_route_returns_inertia_external_redirect_response(): void
    {
        $user = User::query()->create([
            'name' => 'Logout User',
            'email' => 'logout@example.com',
        ]);

        $response = $this->withHeader('X-Inertia', 'true')
            ->actingAs($user)
            ->post('/logout');

        $response->assertStatus(409);
        $response->assertHeader('X-Inertia-Location', 'https://authx.example.test/logout');
        $this->assertGuest();
    }

    #[Test]
    public function callback_sets_name_from_payload_when_provided(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 5,
                'name' => 'Taylor Otwell',
                'email' => 'taylor@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'taylor@example.com')->firstOrFail();
        $this->assertSame('Taylor Otwell', $user->name);
    }

    #[Test]
    public function callback_sets_nickname_when_provided(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 6,
                'nickname' => 'taylorotwell',
                'name' => 'Taylor',
                'email' => 'taylor@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'taylor@example.com')->firstOrFail();
        $this->assertSame('taylorotwell', $user->nickname);
    }

    #[Test]
    public function callback_does_not_set_nickname_when_blank(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 7,
                'nickname' => null,
                'name' => 'Jane',
                'email' => 'jane@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'jane@example.com')->firstOrFail();
        $this->assertNull($user->nickname);
    }

    #[Test]
    public function callback_does_not_set_avatar_when_blank(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 8,
                'name' => 'No Avatar',
                'email' => 'noavatar@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'noavatar@example.com')->firstOrFail();
        $this->assertNull($user->avatar);
    }

    #[Test]
    public function callback_does_not_set_authx_id_when_blank(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => null,
                'name' => 'No ID',
                'email' => 'noid@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'noid@example.com')->firstOrFail();
        $this->assertNull($user->authx_id);
    }

    #[Test]
    public function callback_sets_auth_provider_without_provider_id_column(): void
    {
        $this->fakeSocialiteUser(
            mapped: [
                'id' => 9,
                'name' => 'GitHub User',
                'email' => 'github@example.com',
                'avatar' => null,
            ],
            raw: [
                'auth_provider' => 'github',
            ],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'github@example.com')->firstOrFail();
        $this->assertSame('github', $user->auth_provider);
    }

    #[Test]
    public function callback_preserves_existing_user_profile_fields(): void
    {
        User::query()->create([
            'name' => 'Custom Name',
            'nickname' => 'customnick',
            'email' => 'existing@example.com',
            'avatar' => 'https://custom-avatar.test/img.png',
        ]);

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 10,
                'name' => 'AuthX Name',
                'nickname' => 'authxnick',
                'email' => 'existing@example.com',
                'avatar' => 'https://authx-avatar.test/img.png',
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $this->assertSame(1, User::query()->where('email', 'existing@example.com')->count());

        $user = User::query()->where('email', 'existing@example.com')->firstOrFail();
        $this->assertSame('Custom Name', $user->name);
        $this->assertSame('customnick', $user->nickname);
        $this->assertSame('https://custom-avatar.test/img.png', $user->avatar);
    }

    #[Test]
    public function callback_still_updates_authx_id_on_existing_user(): void
    {
        User::query()->create([
            'name' => 'Existing',
            'email' => 'existing@example.com',
            'authx_id' => null,
        ]);

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 42,
                'name' => 'AuthX Name',
                'email' => 'existing@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));

        $user = User::query()->where('email', 'existing@example.com')->firstOrFail();
        $this->assertSame(42, $user->authx_id);
    }

    #[Test]
    public function callback_allows_admin_when_prevention_is_enabled(): void
    {
        config()->set('authx-auth.prevent_non_admin_user_creation', true);
        config()->set('authx-auth.admin_emails', ['admin@example.com']);

        $this->fakeSocialiteUser(
            mapped: [
                'id' => 12,
                'name' => 'Admin',
                'email' => 'admin@example.com',
                'avatar' => null,
            ],
            raw: [],
        );

        $this->get('/auth/callback')->assertRedirect(route('dashboard'));
        $this->assertAuthenticatedAs(User::query()->where('email', 'admin@example.com')->firstOrFail());
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
