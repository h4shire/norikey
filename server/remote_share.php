<?php

declare(strict_types=1);

header('Content-Type: application/json');

const NORIKEY_RECORD_DIR = __DIR__ . '/../norikey_remote_records';
const NORIKEY_SIGNING_INI = __DIR__ . '/../norikey_remote.ini';
const NORIKEY_NONCE_TTL_SECONDS = 900;
const NORIKEY_MAX_TRACKED_NONCES = 128;

respond_main();

function respond_main(): void
{
    try {
        ensure_record_dir_exists();

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            fail_json('Only POST is supported.', 405);
        }

        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') {
            fail_json('Empty request body.', 400);
        }

        $request = json_decode($raw, true);
        if (!is_array($request)) {
            fail_json('Invalid JSON request body.', 400);
        }

        $action = require_string($request, 'action');

        switch ($action) {
            case 'enroll':
                handle_enroll($request);
                return;

            case 'release':
                handle_release($request);
                return;

            default:
                fail_json('Unsupported action.', 400);
        }
    } catch (Throwable $e) {
        fail_json('Server exception: ' . $e->getMessage(), 500);
    }
}

function handle_enroll(array $request): void
{
    $containerId = require_string($request, 'container_id');
    $groupId = require_string($request, 'group_id');
    $shareId = require_share_id($request, 'share_id');
    $authVerifierHex = require_hex($request, 'auth_verifier_hex');
    $serverShareHex = require_hex($request, 'server_share_hex');

    $now = gmdate('c');

    $record = [
        'version' => 2,
        'container_id' => $containerId,
        'group_id' => $groupId,
        'share_id' => $shareId,
        'auth_verifier_hex' => strtolower($authVerifierHex),
        'server_share_hex' => strtolower($serverShareHex),
        'created_at' => $now,
        'updated_at' => $now,
        'release_count' => 0,
        'used_request_nonces' => [],
    ];

    with_record_lock($containerId, $groupId, $shareId, static function () use ($containerId, $groupId, $shareId, $record): void {
        save_record($containerId, $groupId, $shareId, $record);
    });

    respond_json([
        'ok' => true,
    ]);
}

function handle_release(array $request): void
{
    $containerId = require_string($request, 'container_id');
    $groupId = require_string($request, 'group_id');
    $shareId = require_share_id($request, 'share_id');
    $authTokenHex = require_hex($request, 'auth_token_hex');
    $requestNonceHex = require_hex($request, 'request_nonce_hex');

    $response = with_record_lock($containerId, $groupId, $shareId, static function () use ($containerId, $groupId, $shareId, $authTokenHex, $requestNonceHex): array {
        $record = load_record($containerId, $groupId, $shareId);
        if ($record === null) {
            fail_json('Remote share record not found.', 404);
        }

        $authTokenBin = hex2bin($authTokenHex);
        if ($authTokenBin === false) {
            fail_json('Invalid auth_token_hex.', 400);
        }

        $computedVerifier = hash('sha256', $authTokenBin);

        if (
            !isset($record['auth_verifier_hex']) ||
            !is_string($record['auth_verifier_hex']) ||
            !hash_equals(strtolower($record['auth_verifier_hex']), strtolower($computedVerifier))
        ) {
            fail_json('Remote authorization failed.', 403);
        }

        if (
            !isset($record['server_share_hex']) ||
            !is_string($record['server_share_hex']) ||
            !preg_match('/^[0-9a-fA-F]+$/', $record['server_share_hex'])
        ) {
            fail_json('Stored remote share is invalid.', 500);
        }

        $normalizedRequestNonce = strtolower($requestNonceHex);
        $usedRequestNonces = normalize_used_request_nonces($record['used_request_nonces'] ?? null);
        if (isset($usedRequestNonces[$normalizedRequestNonce])) {
            fail_json('Remote release nonce was already used.', 409);
        }

        $baseResponse = [
            'ok' => true,
            'container_id' => $containerId,
            'group_id' => $groupId,
            'share_id' => $shareId,
            'request_nonce_hex' => $normalizedRequestNonce,
            'server_share_hex' => strtolower($record['server_share_hex']),
        ];

        $signatureFields = sign_release_payload($baseResponse);

        $usedRequestNonces[$normalizedRequestNonce] = time();
        $record['used_request_nonces'] = limit_used_request_nonces($usedRequestNonces);
        $record['updated_at'] = gmdate('c');
        $record['release_count'] = (int)($record['release_count'] ?? 0) + 1;
        save_record($containerId, $groupId, $shareId, $record);

        return array_merge($baseResponse, $signatureFields);
    });

    respond_json($response);
}

function sign_release_payload(array $payload): array
{
    if (!extension_loaded('sodium')) {
        throw new RuntimeException('PHP sodium extension is not available.');
    }

    $cfg = load_signing_config();
    $seedHex = $cfg['seed_hex'];
    $keyId = $cfg['key_id'];

    $seed = sodium_hex2bin($seedHex);
    if ($seed === false || strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
        throw new RuntimeException('Signing seed must be 32 bytes / 64 hex characters.');
    }

    $keypair = sodium_crypto_sign_seed_keypair($seed);
    $secretKey = sodium_crypto_sign_secretkey($keypair);

    $message = build_release_signature_message($payload);
    $signature = sodium_crypto_sign_detached($message, $secretKey);

    return [
        'response_sig_key_id' => $keyId,
        'response_sig_hex' => sodium_bin2hex($signature),
    ];
}

function build_release_signature_message(array $payload): string
{
    $containerId = (string)$payload['container_id'];
    $groupId = (string)$payload['group_id'];
    $shareId = (int)$payload['share_id'];
    $requestNonceHex = strtolower((string)$payload['request_nonce_hex']);
    $serverShareHex = strtolower((string)$payload['server_share_hex']);

    return implode("\n", [
        'norikey-remote-release-v1',
        'container_id=' . $containerId,
        'group_id=' . $groupId,
        'share_id=' . $shareId,
        'request_nonce_hex=' . $requestNonceHex,
        'server_share_hex=' . $serverShareHex,
    ]);
}

function normalize_used_request_nonces($value): array
{
    if (!is_array($value)) {
        return [];
    }

    $now = time();
    $normalized = [];

    foreach ($value as $nonceHex => $timestamp) {
        if (!is_string($nonceHex) || !preg_match('/^[0-9a-fA-F]+$/', $nonceHex)) {
            continue;
        }

        $ts = null;
        if (is_int($timestamp)) {
            $ts = $timestamp;
        } elseif (is_string($timestamp) && ctype_digit($timestamp)) {
            $ts = (int)$timestamp;
        }

        if ($ts === null) {
            continue;
        }

        if ($ts < ($now - NORIKEY_NONCE_TTL_SECONDS)) {
            continue;
        }

        $normalized[strtolower($nonceHex)] = $ts;
    }

    return $normalized;
}

function limit_used_request_nonces(array $nonces): array
{
    arsort($nonces, SORT_NUMERIC);
    return array_slice($nonces, 0, NORIKEY_MAX_TRACKED_NONCES, true);
}


function with_record_lock(string $containerId, string $groupId, int $shareId, callable $callback)
{
    $lockPath = record_lock_path($containerId, $groupId, $shareId);
    $handle = fopen($lockPath, 'c+b');
    if ($handle === false) {
        throw new RuntimeException('Failed to open remote share lock file.');
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Failed to lock remote share record.');
        }

        return $callback();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function load_signing_config(): array
{
    if (!is_file(NORIKEY_SIGNING_INI) || !is_readable(NORIKEY_SIGNING_INI)) {
        throw new RuntimeException('Signing config file is missing or not readable.');
    }

    $ini = parse_ini_file(NORIKEY_SIGNING_INI, false, INI_SCANNER_TYPED);
    if ($ini === false) {
        throw new RuntimeException('Failed to parse signing config file.');
    }

    $seedHex = $ini['signing_seed_hex'] ?? null;
    $keyId = $ini['signing_key_id'] ?? 'default';

    if (!is_string($seedHex) || !preg_match('/^[0-9a-fA-F]{64}$/', $seedHex)) {
        throw new RuntimeException('Invalid signing_seed_hex in norikey_remote.ini.');
    }

    if (!is_string($keyId) || $keyId === '') {
        throw new RuntimeException('Invalid signing_key_id in norikey_remote.ini.');
    }

    return [
        'seed_hex' => strtolower($seedHex),
        'key_id' => $keyId,
    ];
}

function save_record(string $containerId, string $groupId, int $shareId, array $record): void
{
    $path = record_path($containerId, $groupId, $shareId);
    $json = json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

    if ($json === false) {
        throw new RuntimeException('Failed to encode remote share record.');
    }

    $tmpPath = $path . '.tmp.' . bin2hex(random_bytes(6));
    if (file_put_contents($tmpPath, $json . PHP_EOL) === false) {
        throw new RuntimeException('Failed to write temporary remote share record.');
    }

    if (!rename($tmpPath, $path)) {
        @unlink($tmpPath);
        throw new RuntimeException('Failed to replace remote share record atomically.');
    }
}

function load_record(string $containerId, string $groupId, int $shareId): ?array
{
    $path = record_path($containerId, $groupId, $shareId);

    if (!is_file($path) || !is_readable($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
        throw new RuntimeException('Remote share record is unreadable or empty.');
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Remote share record contains invalid JSON.');
    }

    return $decoded;
}

function record_path(string $containerId, string $groupId, int $shareId): string
{
    $key = record_key($containerId, $groupId, $shareId);
    return rtrim(NORIKEY_RECORD_DIR, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $key . '.json';
}

function record_lock_path(string $containerId, string $groupId, int $shareId): string
{
    $key = record_key($containerId, $groupId, $shareId);
    return rtrim(NORIKEY_RECORD_DIR, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $key . '.lock';
}

function record_key(string $containerId, string $groupId, int $shareId): string
{
    return hash('sha256', $containerId . '|' . $groupId . '|' . $shareId);
}

function ensure_record_dir_exists(): void
{
    if (is_dir(NORIKEY_RECORD_DIR)) {
        return;
    }

    if (!mkdir(NORIKEY_RECORD_DIR, 0700, true) && !is_dir(NORIKEY_RECORD_DIR)) {
        throw new RuntimeException('Failed to create remote record directory.');
    }
}

function require_string(array $request, string $key): string
{
    $value = $request[$key] ?? null;
    if (!is_string($value) || trim($value) === '') {
        fail_json("Missing or invalid field: {$key}.", 400);
    }

    return trim($value);
}

function require_share_id(array $request, string $key): int
{
    $value = $request[$key] ?? null;
    if (!is_int($value) && !is_string($value) && !is_float($value)) {
        fail_json("Missing or invalid field: {$key}.", 400);
    }

    $shareId = (int)$value;
    if ($shareId < 0 || $shareId > 255) {
        fail_json("Invalid share_id range for field: {$key}.", 400);
    }

    return $shareId;
}

function require_hex(array $request, string $key): string
{
    $value = $request[$key] ?? null;
    if (!is_string($value) || $value === '' || !preg_match('/^[0-9a-fA-F]+$/', $value)) {
        fail_json("Missing or invalid hex field: {$key}.", 400);
    }

    if ((strlen($value) % 2) !== 0) {
        fail_json("Hex field must contain an even number of characters: {$key}.", 400);
    }

    return strtolower($value);
}

function respond_json(array $payload, int $status = 200): void
{
    http_response_code($status);
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);

    if ($json === false) {
        http_response_code(500);
        echo '{"ok":false,"error":"Failed to encode JSON response."}';
        exit;
    }

    echo $json;
    exit;
}

function fail_json(string $message, int $status = 500): void
{
    respond_json([
        'ok' => false,
        'error' => $message,
    ], $status);
}