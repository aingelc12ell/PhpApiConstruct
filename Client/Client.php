<?php

declare(strict_types=1);

use JsonException;
use RuntimeException;

class APIClient
{
    private readonly string $baseUrl;
    private ?string $token = null;
    private int $expiresAt = 0; // UNIX timestamp
    private array $roles = [];

    public function __construct(string $baseUrl)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Log in to the API and store token, expiry, and roles
     *
     * @param string $username
     * @param string $password
     * @return array ['token' => string, 'expiresAt' => int, 'roles' => array]
     * @throws RuntimeException on HTTP or JSON errors
     */
    public function login(string $username, string $password): array
    {
        $url = "{$this->baseUrl}?endpoint=login";
        $payload = json_encode(['username' => $username, 'password' => $password], JSON_THROW_ON_ERROR);

        [$body, $headers] = $this->execRequest($url, 'POST', $payload);

        $data = $this->decodeBody($body);
        if(!isset($data['token'], $data['expiresAt'], $data['roles'])){
            throw new RuntimeException('Invalid login response');
        }

        $this->token = $data['token'];
        $this->expiresAt = (int)$data['expiresAt'];
        $this->roles = (array)$data['roles'];

        return ['token' => $this->token, 'expiresAt' => $this->expiresAt, 'roles' => $this->roles];
    }

    /**
     * Check if stored token is expired (client-side)
     */
    public function isTokenExpired(): bool
    {
        return $this->token === null || time() > $this->expiresAt;
    }

    /**
     * Get roles associated with current token
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * GET example endpoint
     */
    public function getExample(): array
    {
        return $this->request('example', 'GET');
    }

    /**
     * POST example endpoint
     */
    public function postExample(array $data): array
    {
        return $this->request('example', 'POST', json_encode($data, JSON_THROW_ON_ERROR));
    }

    /**
     * Generic request to protected endpoints
     *
     * @throws RuntimeException on missing auth, HTTP or JSON errors
     */
    private function request(string $endpoint, string $method, ?string $body = null): array
    {
        if($this->token === null){
            throw new RuntimeException('No token. Please login first.');
        }

        $url = "{$this->baseUrl}?endpoint=" . urlencode($endpoint);
        [$responseBody, $headers] = $this->execRequest($url, $method, $body, $this->token);

        // Handle renewal headers
        if(isset($headers['x-token-renewed']) && $headers['x-token-renewed'] === 'true'){
            if(isset($headers['x-token-expires-at'])){
                $this->expiresAt = (int)$headers['x-token-expires-at'];
            }
        }

        $data = $this->decodeBody($responseBody);
        return $data;
    }

    /**
     * Execute cURL request, return [body, headers]
     *
     * @param string $url
     * @param string $method
     * @param string|null $body
     * @param string|null $bearer
     * @return array [string $body, array $headers]
     */
    private function execRequest(string $url, string $method, ?string $body = null, ?string $bearer = null): array
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HEADER, true);

        $headers = ['Content-Type: application/json'];
        if($bearer !== null){
            $headers[] = 'Authorization: Bearer ' . $bearer;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if($body !== null){
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        if($response === false){
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("cURL error: {$err}");
        }

        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $rawHeaders = substr($response, 0, $headerSize);
        $responseBody = substr($response, $headerSize);
        curl_close($ch);

        // Parse headers
        $headerLines = preg_split('/\r?\n/', $rawHeaders);
        $hdrMap = [];
        foreach($headerLines as $line){
            if(strpos($line, ':') !== false){
                [$key, $val] = explode(':', $line, 2);
                $hdrMap[strtolower(trim($key))] = trim($val);
            }
        }

        // HTTP status
        $statusLine = $headerLines[0] ?? '';
        preg_match('#HTTP/\d+\.\d+\s+(\d+)#', $statusLine, $m);
        $statusCode = isset($m[1]) ? (int)$m[1] : 0;

        $data = $this->decodeBody($responseBody);
        if($statusCode < 200 || $statusCode >= 300){
            $msg = $data['error'] ?? 'Unknown error';
            throw new RuntimeException("API error ({$statusCode}): {$msg}");
        }

        return [$responseBody, $hdrMap];
    }

    /**
     * Decode JSON or throw
     *
     * @throws RuntimeException
     */
    private function decodeBody(string $body): array
    {
        try{
            return $body !== ''
                ? json_decode($body, true, 512, JSON_THROW_ON_ERROR)
                : [];
        } catch(JsonException $e){
            throw new RuntimeException('Invalid JSON response: ' . $e->getMessage());
        }
    }
}

// Usage example:
// $client = new APIClient('https://your-domain.com/path/to/api.php');
// $client->login('alice', 'password1');
// $resp = $client->getExample();
// var_dump($resp);
