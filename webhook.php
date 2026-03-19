<?php
declare(strict_types=1);

/**
 * Chatwork Webhook receiver
 *
 * Required file in same directory:
 * - config.php (DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_CHARSET)
 * - optional WEBHOOK_TOKEN for signature validation
 */

require_once __DIR__ . '/config.php';

if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS') || !defined('DB_CHARSET')) {
    http_response_code(500);
    echo 'Database configuration constants are missing.';
    exit;
}

$rawBody = file_get_contents('php://input');
if ($rawBody === false || $rawBody === '') {
    http_response_code(400);
    echo 'Empty request body.';
    exit;
}

$signature = $_SERVER['HTTP_X_CHATWORKWEBHOOKSIGNATURE'] ?? $_SERVER['X_CHATWORKWEBHOOKSIGNATURE'] ?? '';
if (defined('WEBHOOK_TOKEN') && WEBHOOK_TOKEN !== '') {
    $expected = base64_encode(hash_hmac('sha256', $rawBody, WEBHOOK_TOKEN, true));
    if ($signature === '' || !hash_equals($expected, $signature)) {
        http_response_code(403);
        echo 'Invalid signature.';
        exit;
    }
}

$payload = json_decode($rawBody, true);
if (!is_array($payload)) {
    http_response_code(400);
    echo 'Invalid JSON payload.';
    exit;
}

$eventType = (string)($payload['webhook_event_type'] ?? '');
$event = $payload['webhook_event'] ?? [];
if (!is_array($event)) {
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
    $senderMentionId = isset($event['account']['account_id']) ? (string)$event['account']['account_id'] : null;
    $senderName = isset($event['account']['name']) ? (string)$event['account']['name'] : null;
} else {
    $senderMentionId = isset($event['account_id']) ? (string)$event['account_id'] : null;
    $senderName = isset($event['name']) ? (string)$event['name'] : null;
}

$recipientTargets = extractRecipientTargets($body);
$recipientCsv = implode(',', $recipientTargets);

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
