<?php

declare(strict_types=1);

use JsonException;

class APIHandler
{
    // In-memory users store with roles
    private const USERS = [
        'alice' => ['password' => 'password1', 'roles' => ['admin', 'editor']],
        'bob' => ['password' => 'password2', 'roles' => ['viewer']],
    ];

    // Token store: token => ['user', 'roles', 'issuedAt', 'expiresAt']
    private static array $tokenStore = [];
    private const TOKEN_LIFETIME = 600; // 10 minutes in seconds
    private const RENEW_WINDOW = 1800;  // 30 minutes in seconds

    public function handleRequest(): void
    {
        header('Content-Type: application/json; charset=utf-8');

        $endpoint = filter_input(INPUT_GET, 'endpoint', FILTER_SANITIZE_STRING) ?: '';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        match ($endpoint) {
            'login' => $this->handleLogin($method),
            default => $this->handleProtected($endpoint, $method),
        };
    }

    /**
     * Public login endpoint. Returns bearer token, expiry, and roles.
     */
    private function handleLogin(string $method): void
    {
        if($method !== 'POST'){
            $this->sendResponse(['error' => 'Method not allowed'], 405);
            return;
        }

        $raw = file_get_contents('php://input');
        try{
            $data = $raw ? json_decode($raw, true, 512, JSON_THROW_ON_ERROR) : [];
        } catch(JsonException $e){
            $this->sendResponse(['error' => 'Invalid JSON'], 400);
            return;
        }

        $user = $data['username'] ?? '';
        $pass = $data['password'] ?? '';

        if(!isset(self::USERS[$user]) || self::USERS[$user]['password'] !== $pass){
            $this->sendResponse(['error' => 'Invalid credentials'], 401);
            return;
        }

        $roles = self::USERS[$user]['roles'];
        $token = bin2hex(random_bytes(16));
        $now = time();
        self::$tokenStore[$token] = [
            'user' => $user,
            'roles' => $roles,
            'issuedAt' => $now,
            'expiresAt' => $now + self::TOKEN_LIFETIME,
        ];

        $this->sendResponse([
            'token' => $token,
            'expiresAt' => self::$tokenStore[$token]['expiresAt'],
            'roles' => $roles,
        ]);
    }

    /**
     * Handle endpoints requiring bearer token auth
     */
    private function handleProtected(string $endpoint, string $method): void
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if(!str_starts_with($auth, 'Bearer ')){
            $this->sendResponse(['error' => 'Missing token'], 401);
            return;
        }

        $token = substr($auth, 7);
        $entry = self::$tokenStore[$token] ?? null;
        if(!$entry){
            $this->sendResponse(['error' => 'Invalid token'], 401);
            return;
        }

        $now = time();
        $issuedAt = $entry['issuedAt'];
        $expiresAt = $entry['expiresAt'];

        // If token expired
        if($now > $expiresAt){
            // Within renewal window?
            if($now <= $issuedAt + self::RENEW_WINDOW){
                // Renew token lifetime
                self::$tokenStore[$token]['issuedAt'] = $now;
                self::$tokenStore[$token]['expiresAt'] = $now + self::TOKEN_LIFETIME;
                // Inform client of renewal
                header('X-Token-Renewed: true');
                header('X-Token-Expires-At: ' . self::$tokenStore[$token]['expiresAt']);
            }
            else{
                unset(self::$tokenStore[$token]);
                $this->sendResponse(['error' => 'Token expired'], 401);
                return;
            }
        }

        $user = $entry['user'];
        $roles = $entry['roles'];

        // Route protected endpoints
        match ($endpoint) {
            'example' => $this->handleExample($method, $user, $roles),
            default => $this->sendResponse(['error' => 'Endpoint not found'], 404),
        };
    }

    private function handleExample(string $method, string $user, array $roles): void
    {
        match ($method) {
            'GET' => $this->sendResponse([
                'message' => "Hello {$user} ({implode(',', $roles)}), this is a GET example",
            ]),
            'POST' => $this->handleExamplePost($user, $roles),
            default => $this->sendResponse(['error' => 'Method not allowed'], 405),
        };
    }

    private function handleExamplePost(string $user, array $roles): void
    {
        $raw = file_get_contents('php://input');
        try{
            $data = $raw ? json_decode($raw, true, 512, JSON_THROW_ON_ERROR) : [];
        } catch(JsonException $e){
            $this->sendResponse(['error' => 'Invalid JSON'], 400);
            return;
        }

        $this->sendResponse([
            'message' => "Hello {$user} ({implode(',', $roles)}), you posted data",
            'data' => $data,
        ]);
    }

    private function sendResponse(array $data, int $status = 200): void
    {
        http_response_code($status);
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
}

// Bootstrap
(new APIHandler())->handleRequest();
