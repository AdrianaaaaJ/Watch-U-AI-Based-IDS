<?php

declare(strict_types=1);

final class WazuhService
{
    public static function isConfigured(): bool
    {
        return trim((string) config('wazuh.url')) !== ''
            && trim((string) config('wazuh.username')) !== ''
            && (string) config('wazuh.password') !== '';
    }

    public function testConnection(): string
    {
        if (!self::isConfigured()) {
            return 'Not configured';
        }

        $baseUrl = rtrim(trim((string) config('wazuh.url')), '/');
        $parts = parse_url($baseUrl);
        if (!filter_var($baseUrl, FILTER_VALIDATE_URL)
            || !is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || (isset($parts['path']) && $parts['path'] !== '')) {
            return 'Unreachable';
        }

        $sslOptions = [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ];
        $caBundle = trim((string) config('wazuh.ca_bundle'));
        if ($caBundle !== '') {
            if (!is_file($caBundle) || !is_readable($caBundle)) {
                return 'Unreachable';
            }
            $sslOptions['cafile'] = $caBundle;
        }

        $credentials = (string) config('wazuh.username') . ':' . (string) config('wazuh.password');
        try {
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Authorization: Basic ' . base64_encode($credentials)
                        . "\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\n",
                    'content' => '',
                    'timeout' => 8,
                    'ignore_errors' => true,
                    'follow_location' => 0,
                    'max_redirects' => 0,
                ],
                'ssl' => $sslOptions,
            ]);
            // Never surface the response body: a successful response contains a JWT.
            $response = @file_get_contents($baseUrl . '/security/user/authenticate', false, $context);
            $headers = $http_response_header ?? [];
        } catch (Throwable) {
            return 'Unreachable';
        }

        $statusCode = 0;
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $matches)) {
                $statusCode = (int) $matches[1];
            }
        }
        if ($response === false || $statusCode === 0) {
            return 'Unreachable';
        }

        return self::statusFromResponse($statusCode, $response);
    }

    public static function statusFromResponse(int $statusCode, string $response): string
    {
        if ($statusCode === 401 || $statusCode === 403) {
            return 'Authentication Failed';
        }
        if ($statusCode !== 200) {
            return 'Unreachable';
        }

        $decoded = json_decode($response, true);
        return is_array($decoded) && is_string($decoded['data']['token'] ?? null) && $decoded['data']['token'] !== ''
            ? 'Connected'
            : 'Unreachable';
    }
}
