<?php
declare(strict_types=1);

/**
 * Chatwork Webhook receiver
 *
 * Required file in same directory:
 * - config.php (DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_CHARSET)
 * - optional WEBHOOK_TOKEN for signature validation
 */

require_once 'config.php';

$requestId = bin2hex(random_bytes(8));
logWebhook($requestId, 'Webhook request received.', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? null,
    'uri' => $_SERVER['REQUEST_URI'] ?? null,
    'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? null,
    'content_length' => $_SERVER['CONTENT_LENGTH'] ?? null,
]);

if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS') || !defined('DB_CHARSET')) {
    logWebhook($requestId, 'Database configuration constants are missing.');
    http_response_code(500);
    echo 'Database configuration constants are missing.';
    exit;
}

$rawBody = file_get_contents('php://input');
if ($rawBody === false || $rawBody === '') {
    logWebhook($requestId, 'Empty request body.');
    http_response_code(400);
    echo 'Empty request body.';
    exit;
}

$signatureHeader = $_SERVER['HTTP_X_CHATWORKWEBHOOKSIGNATURE'] ?? $_SERVER['X_CHATWORKWEBHOOKSIGNATURE'] ?? '';
$signatureQuery = $_GET['chatwork_webhook_signature'] ?? '';
$signature = $signatureHeader !== '' ? $signatureHeader : (is_string($signatureQuery) ? urldecode($signatureQuery) : '');
if (defined('WEBHOOK_TOKEN') && WEBHOOK_TOKEN !== '') {
    $expectedSignatures = buildExpectedSignatures($rawBody, WEBHOOK_TOKEN);
    $isValidSignature = false;
    foreach ($expectedSignatures as $expectedSignature) {
        if ($signature !== '' && hash_equals($expectedSignature, $signature)) {
            $isValidSignature = true;
            break;
        }
    }

    if (!$isValidSignature) {
        logWebhook($requestId, 'Invalid signature.', [
            'signature_header_present' => $signatureHeader !== '',
            'signature_query_present' => is_string($signatureQuery) && $signatureQuery !== '',
            'signature_used' => $signatureHeader !== '' ? 'header' : ((is_string($signatureQuery) && $signatureQuery !== '') ? 'query' : 'none'),
            'signature_header_preview' => previewSecret($signatureHeader),
            'signature_query_preview' => previewSecret(is_string($signatureQuery) ? urldecode($signatureQuery) : ''),
            'expected_signature_preview' => previewSecret($expectedSignatures[0] ?? ''),
            'expected_signature_count' => count($expectedSignatures),
        ]);
        http_response_code(403);
        echo 'Invalid signature.';
        exit;
    }
}

$payload = json_decode($rawBody, true);
if (!is_array($payload)) {
    logWebhook($requestId, 'Invalid JSON payload.', [
        'json_error' => json_last_error_msg(),
    ]);
    http_response_code(400);
    echo 'Invalid JSON payload.';
    exit;
}

$eventType = (string)($payload['webhook_event_type'] ?? '');
$event = $payload['webhook_event'] ?? [];
if (!is_array($event)) {
    logWebhook($requestId, 'Invalid webhook_event.');
    http_response_code(400);
    echo 'Invalid webhook_event.';
    exit;
}

$roomId = isset($event['room_id']) ? (int)$event['room_id'] : null;
$messageId = isset($event['message_id']) ? (string)$event['message_id'] : null;
$body = isset($event['body']) ? (string)$event['body'] : '';
$sentAt = isset($event['send_time']) ? (int)$event['send_time'] : null;

$senderMentionId = null;
$senderName = null;

if (isset($event['account']) && is_array($event['account'])) {
    $senderMentionId = firstNonEmptyString([
        $event['account']['account_id'] ?? null,
        $event['account']['id'] ?? null,
    ]);
    $senderName = firstNonEmptyString([
        $event['account']['name'] ?? null,
        $event['account']['account_name'] ?? null,
        $event['account']['display_name'] ?? null,
    ]);
} else {
    $senderMentionId = firstNonEmptyString([
        $event['account_id'] ?? null,
        $event['from_account_id'] ?? null,
        $event['sender_id'] ?? null,
    ]);
    $senderName = firstNonEmptyString([
        $event['name'] ?? null,
        $event['account_name'] ?? null,
        $event['from_account_name'] ?? null,
        $event['sender_name'] ?? null,
    ]);
}

$recipientTargets = extractRecipientTargets($body);
$recipientCsv = implode(',', $recipientTargets);

logWebhook($requestId, 'Webhook payload parsed.', [
    'event_type' => $eventType,
    'room_id' => $roomId,
    'message_id' => $messageId,
    'sender_mention_id' => $senderMentionId,
    'recipient_count' => count($recipientTargets),
    'sender_name' => $senderName,
    'sender_name_candidates' => [
        'name' => $event['name'] ?? null,
        'account_name' => $event['account_name'] ?? null,
        'from_account_name' => $event['from_account_name'] ?? null,
        'sender_name' => $event['sender_name'] ?? null,
        'account.name' => (is_array($event['account'] ?? null) ? ($event['account']['name'] ?? null) : null),
        'account.account_name' => (is_array($event['account'] ?? null) ? ($event['account']['account_name'] ?? null) : null),
    ],
]);
try {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', DB_HOST, DB_NAME, DB_CHARSET);
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    $pdo->beginTransaction();

    $senderUserId = null;
    if ($senderMentionId !== null && $senderMentionId !== '') {
        $senderUserId = upsertUser($pdo, $senderMentionId, $senderName);
    }

    foreach ($recipientTargets as $target) {
        if ($target === 'toall') {
            continue;
        }
        upsertUser($pdo, $target, null);
    }

    $insertSql = <<<SQL
INSERT INTO messages (
    room_id,
    message_id,
    sender_user_id,
    sender_mention_id,
    sender_name,
    webhook_event_type,
    message_body,
    recipient_targets,
    sent_at,
    raw_payload
) VALUES (
    :room_id,
    :message_id,
    :sender_user_id,
    :sender_mention_id,
    :sender_name,
    :webhook_event_type,
    :message_body,
    :recipient_targets,
    :sent_at,
    :raw_payload
)
ON DUPLICATE KEY UPDATE
    sender_user_id = VALUES(sender_user_id),
    sender_mention_id = VALUES(sender_mention_id),
    sender_name = VALUES(sender_name),
    webhook_event_type = VALUES(webhook_event_type),
    message_body = VALUES(message_body),
    recipient_targets = VALUES(recipient_targets),
    sent_at = VALUES(sent_at),
    raw_payload = VALUES(raw_payload),
    updated_at = CURRENT_TIMESTAMP
SQL;

    $stmt = $pdo->prepare($insertSql);
    $stmt->execute([
        ':room_id' => $roomId,
        ':message_id' => $messageId,
        ':sender_user_id' => $senderUserId,
        ':sender_mention_id' => $senderMentionId,
        ':sender_name' => $senderName,
        ':webhook_event_type' => $eventType,
        ':message_body' => $body,
        ':recipient_targets' => $recipientCsv,
        ':sent_at' => $sentAt !== null ? date('Y-m-d H:i:s', $sentAt) : null,
        ':raw_payload' => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    ]);

    $pdo->commit();
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    logWebhook($requestId, 'Failed to process webhook.', [
        'event_type' => $eventType,
        'room_id' => $roomId,
        'message_id' => $messageId,
        'error' => $e->getMessage(),
    ]);
    http_response_code(500);
    echo 'Failed to process webhook.';
    error_log('[chatwork-webhook] ' . $e->getMessage());
    exit;
}

http_response_code(200);
echo 'ok';

/**
 * Extract recipient mention IDs and toall marker from Chatwork message body.
 * Return unique values in first-seen order, e.g. ["123", "456", "toall"].
 */
function extractRecipientTargets(string $body): array
{
    $targets = [];

    if (preg_match_all('/\[To:(\d+)\]/u', $body, $matches)) {
        foreach ($matches[1] as $mentionId) {
            if (!in_array($mentionId, $targets, true)) {
                $targets[] = $mentionId;
            }
        }
    }

    if (preg_match('/\[toall\]/iu', $body)) {
        $targets[] = 'toall';
    }

    return $targets;
}

/**
 * Insert or update users table and return user ID.
 */
function upsertUser(PDO $pdo, string $mentionId, ?string $userName): int
{
    $sql = <<<SQL
INSERT INTO users (mention_id, user_name)
VALUES (:mention_id, :user_name)
ON DUPLICATE KEY UPDATE
    user_name = COALESCE(VALUES(user_name), user_name),
    updated_at = CURRENT_TIMESTAMP
SQL;

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':mention_id' => $mentionId,
        ':user_name' => $userName,
    ]);

    $idSql = 'SELECT id FROM users WHERE mention_id = :mention_id LIMIT 1';
    $idStmt = $pdo->prepare($idSql);
    $idStmt->execute([':mention_id' => $mentionId]);
    $row = $idStmt->fetch();

    if (!$row || !isset($row['id'])) {
        throw new RuntimeException('Failed to resolve user ID for mention_id=' . $mentionId);
    }

    return (int)$row['id'];
}

/**
 * Return first non-empty scalar value as string; otherwise null.
 */
function firstNonEmptyString(array $candidates): ?string
{
    foreach ($candidates as $candidate) {
        if ($candidate === null) {
            continue;
        }
        if (is_scalar($candidate)) {
            $value = trim((string)$candidate);
            if ($value !== '') {
                return $value;
            }
        }
    }

    return null;
}
/**
 * Write webhook execution log either to configured file (WEBHOOK_LOG_FILE) or PHP error log.
 */
function logWebhook(string $requestId, string $message, array $context = []): void
{
    $payload = [
        'timestamp' => gmdate('c'),
        'request_id' => $requestId,
        'message' => $message,
    ];

    if ($context !== []) {
        $payload['context'] = $context;
    }

    $line = '[chatwork-webhook] ' . json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($line === false) {
        $line = '[chatwork-webhook] {"timestamp":"' . gmdate('c') . '","request_id":"' . $requestId . '","message":"Failed to encode log payload."}';
    }

    if (defined('WEBHOOK_LOG_FILE') && WEBHOOK_LOG_FILE !== '') {
        error_log($line . PHP_EOL, 3, WEBHOOK_LOG_FILE);
        return;
    }

    error_log($line);
}

/**
 * Return non-sensitive preview of a secret value for debugging.
 */
function previewSecret(string $value): string
{
    if ($value === '') {
        return '';
    }

    $length = strlen($value);
    if ($length <= 8) {
        return str_repeat('*', $length);
    }

    return substr($value, 0, 4) . '...' . substr($value, -4);
}
/**
 * Build accepted signature list from webhook token.
 *
 * Supports both plain text tokens and base64-encoded tokens. Some providers expose
 * the token as base64 text even though signature computation requires the raw bytes.
 */
function buildExpectedSignatures(string $rawBody, string $token): array
{
    $keys = [$token];
    $decodedToken = base64_decode($token, true);
    if ($decodedToken !== false && base64_encode($decodedToken) === $token) {
        $keys[] = $decodedToken;
    }

    $signatures = [];
    foreach ($keys as $key) {
        $signature = base64_encode(hash_hmac('sha256', $rawBody, $key, true));
        if (!in_array($signature, $signatures, true)) {
            $signatures[] = $signature;
        }
    }

    return $signatures;
}
