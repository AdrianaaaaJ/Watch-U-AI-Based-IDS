<?php

declare(strict_types=1);

final class TelegramService
{
    public function send(string $chatId, string $message): array
    {
        $token = (string) config('telegram.token');
        if ($token === '') {
            return [false, 'TELEGRAM_BOT_TOKEN is not configured in .env.'];
        }
        if ($chatId === '') {
            return [false, 'Telegram chat ID is empty.'];
        }

        $url = 'https://api.telegram.org/bot' . rawurlencode($token) . '/sendMessage';
        $payload = json_encode(['chat_id' => $chatId, 'text' => $message, 'parse_mode' => 'HTML'], JSON_THROW_ON_ERROR);
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                'content' => $payload,
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            return [false, 'Telegram request failed. Check network access and the bot token.'];
        }
        $decoded = json_decode($response, true);
        return [!empty($decoded['ok']), !empty($decoded['ok']) ? 'Telegram test alert sent.' : (string) ($decoded['description'] ?? 'Telegram rejected the request.')];
    }
}

