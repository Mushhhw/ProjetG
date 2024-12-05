<?php
$host = 'db';
$dbname = 'projet';
$username = 'projet';
$password = 'Gb67SNBn??NyAsmt';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    echo "Connexion réussie à la base de données.";
} catch (PDOException $e) {
    echo "Erreur de connexion à la base de données : " . $e->getMessage();
}
?>
