<?php
$host = 'db';
$dsn = 'mysql:host=db;dbname=projet;port=3306;charset=utf8mb4';
$username = 'projet';
$password = 'Gb67SNBn??NyAsmt';
$dbpass = 'Gb67SNBn??NyAsmt';
$dbname = 'projet'; // Ajoutez cette ligne si elle n'existe pas


try {
    $pdo = new PDO($dsn, $username, $password);
    // Autres configurations...
} catch (PDOException $e) {
    echo 'Erreur de connexion à la base de données : ' . $e->getMessage();
}
?>
