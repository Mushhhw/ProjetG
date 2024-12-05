<?php
require '/var/www/html/vendor/autoload.php';
use phpseclib3\Net\SFTP;

session_start();

// Activer l'affichage des erreurs PHP
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Vérifiez si la session utilisateur est définie
if (!isset($_SESSION['user_logged_in']) || $_SESSION['user_logged_in'] !== true) {
    die("Erreur : Accès non autorisé. Veuillez vous connecter.");
}

// Informations de connexion à la base de données MySQL
$host = 'localhost';
$dbname = 'projet';
$dbuser = 'projet';
$dbpass = 'Gb67SNBn??NyAsmt';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}

// Récupération de l'utilisateur connecté
$username = $_SESSION['username'];

// Récupération des informations utilisateur
$stmt = $pdo->prepare("SELECT docker_id FROM users WHERE username = :username");
$stmt->execute([':username' => $username]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    die("Erreur : Utilisateur non trouvé dans la base de données.");
}

// Calcul du port SSH basé sur docker_id
$docker_id = $user['docker_id'];
$ssh_port = 32768 + $docker_id;

// Connexion au serveur SFTP
$sftp = new SFTP('localhost', $ssh_port);
if (!$sftp->login($username, 'test')) { // Remplacez 'test' par le mot de passe de l'utilisateur
    die("Erreur : Connexion SFTP échouée sur le port {$ssh_port}.");
}

// Récupérer le chemin demandé
if (!isset($_GET['path'])) {
    die("Erreur : Chemin non spécifié.");
}

$path = $_GET['path'];

// Vérifiez que le chemin est valide
if (!$sftp->file_exists($path)) {
    die("Erreur : Le fichier spécifié n'existe pas.");
}

// Vérifiez que ce n'est pas un dossier
if ($sftp->is_dir($path)) {
    die("Erreur : Impossible d'afficher un dossier.");
}

// Téléchargez le contenu du fichier
$content = $sftp->get($path);

if ($content === false) {
    die("Erreur : Impossible de lire le fichier.");
}

// Détecter le type MIME basé sur l'extension
$extension = pathinfo($path, PATHINFO_EXTENSION);
$mime_types = [
    'txt' => 'text/plain',
    'html' => 'text/html',
    'css' => 'text/css',
    'js' => 'application/javascript',
    'json' => 'application/json',
    'xml' => 'application/xml',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    'pdf' => 'application/pdf',
    'zip' => 'application/zip',
    'rar' => 'application/x-rar-compressed',
];

$mime_type = $mime_types[$extension] ?? 'application/octet-stream';

// Envoyez les en-têtes et le contenu du fichier
header('Content-Type: ' . $mime_type);
echo $content;
?>
