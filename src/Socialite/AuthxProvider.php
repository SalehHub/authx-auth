<?php

namespace AuthxAuth\Socialite;

use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User;

class AuthxProvider extends AbstractProvider
{
    /**
     * The scopes being requested.
     *
     * @var array<int, string>
     */
    protected $scopes = ['user:read'];

    /**
     * The separator used to join scopes.
     */
    protected $scopeSeparator = ' ';

    /**
     * The base URL for the AuthX server.
     */
    protected string $authxUrl = '';

    public function setAuthxUrl(string $url): static
    {
        $this->authxUrl = rtrim($url, '/');

        return $this;
    }

    /**
     * Get the authentication URL for the provider.
     */
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(
            $this->authxUrl.'/oauth/authorize',
            $state,
        );
    }

    /**
     * Get the token URL for the provider.
     */
    protected function getTokenUrl(): string
    {
        return $this->authxUrl.'/oauth/token';
    }

    /**
     * Get the raw user for the given access token.
     *
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get(
            $this->authxUrl.'/api/user',
            [
                'headers' => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ],
        );

        /** @var array<string, mixed> $user */
        $user = json_decode((string) $response->getBody(), true);

        return $user;
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['avatar'] ?? null,
        ]);
    }
}
