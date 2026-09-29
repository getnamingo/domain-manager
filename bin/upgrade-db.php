<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$driver = strtolower((string)($_ENV['DB_DRIVER'] ?? 'mysql'));
if ($driver !== 'mysql') {
    fwrite(STDOUT, "No Domain Manager schema migration is required for DB_DRIVER={$driver}.\n");
    exit(0);
}

$host = $_ENV['DB_HOST'] ?? '127.0.0.1';
$port = $_ENV['DB_PORT'] ?? '3306';
$name = $_ENV['DB_DATABASE'] ?? '';
$user = $_ENV['DB_USERNAME'] ?? '';
$pass = $_ENV['DB_PASSWORD'] ?? '';

if ($name === '') {
    throw new RuntimeException('DB_DATABASE is not configured.');
}

$pdo = new PDO(
    "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
    $user,
    $pass,
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$pdo->exec('ALTER TABLE zones MODIFY domain_name VARCHAR(253)');
$pdo->exec('ALTER TABLE users_webauthn MODIFY credential_id VARBINARY(1024) NOT NULL');

$duplicate = $pdo->query(
    "SELECT domain_name
     FROM zones
     WHERE domain_name IS NOT NULL
     GROUP BY domain_name
     HAVING COUNT(*) > 1
     LIMIT 1"
)->fetchColumn();

if ($duplicate !== false) {
    throw new RuntimeException(
        "Cannot add unique zone-name protection because duplicate zone '{$duplicate}' exists."
    );
}

$index = $pdo->prepare(
    "SELECT COUNT(*)
     FROM information_schema.statistics
     WHERE table_schema = ?
       AND table_name = 'zones'
       AND index_name = 'uniq_zone_domain_name'"
);
$index->execute([$name]);

if ((int)$index->fetchColumn() === 0) {
    $pdo->exec('ALTER TABLE zones ADD UNIQUE KEY uniq_zone_domain_name (domain_name)');
}

fwrite(STDOUT, "Domain Manager database migration completed.\n");
