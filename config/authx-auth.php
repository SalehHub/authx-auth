<?php

return [
    'admin_emails' => array_values(array_filter(array_map(
        fn (string $email): string => trim($email),
        explode(',', (string) env('ADMIN_EMAILS', ''))
    ))),

    'authx' => [
        'client_id' => env('AUTHX_CLIENT_ID'),
        'client_secret' => env('AUTHX_CLIENT_SECRET'),
        'redirect' => env('AUTHX_REDIRECT_URI'),
        'url' => env('AUTHX_URL', 'http://localhost:8000'),
        'verify_ssl' => env('AUTHX_VERIFY_SSL', true),
    ],
];
