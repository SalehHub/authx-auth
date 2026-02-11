<?php

namespace AuthxAuth;

class AdminEmailAllowlist
{
    public function __construct(
        protected AuthxAuthConfig $config,
    ) {}

    /**
     * @return list<string>
     */
    public function emails(): array
    {
        $emails = $this->config->adminEmails();

        $normalizedEmails = [];

        foreach ($emails as $email) {
            if (! is_string($email) || $email === '') {
                continue;
            }

            $normalizedEmails[] = mb_strtolower(trim($email));
        }

        return $normalizedEmails;
    }

    public function allows(?string $email): bool
    {
        if (! is_string($email) || $email === '') {
            return false;
        }

        return in_array(mb_strtolower($email), $this->emails(), true);
    }
}
