<?php
session_start();

// Vérifiez si la session utilisateur est définie
if (!isset($_SESSION['user_logged_in']) || $_SESSION['user_logged_in'] !== true) {
    // Rediriger vers la page de connexion si l'utilisateur n'est pas authentifié
    header('Location: /index.php');
    exit;
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

// Récupération de la clé privée
$private_key_path = "/var/ssh/private_keys/{$docker_id}_id_rsa";
if (!file_exists($private_key_path)) {
    die("Erreur : La clé privée associée est introuvable.");
}

// Chargement de la clé privée
require '/var/www/html/vendor/autoload.php';
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SFTP;

$private_key = PublicKeyLoader::load(file_get_contents($private_key_path));

// Connexion au serveur SFTP
$sftp = new SFTP('localhost', $ssh_port);
if (!$sftp->login($username, $private_key)) { // Utilise la clé privée pour l'authentification
    die("Erreur : Connexion SFTP échouée avec les clés RSA sur le port {$ssh_port}.");
}

// Détermine le répertoire actuel (navigation)
$base_dir = "/home/$username/files";
$current_dir = isset($_GET['path']) ? $_GET['path'] : $base_dir;

// Vérification pour empêcher de sortir du répertoire de base
if (strpos(realpath($current_dir), realpath($base_dir)) !== 0) {
    $current_dir = $base_dir;
}

// Gestion des actions utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Supprimer un fichier ou dossier
    if (isset($_POST['delete'])) {
        $target = $current_dir . '/' . $_POST['delete'];
        if ($sftp->delete($target, true)) { // true pour supprimer récursivement
            echo "Fichier/Dossier supprimé avec succès : " . htmlspecialchars($_POST['delete']);
        } else {
            echo "Erreur : Impossible de supprimer " . htmlspecialchars($_POST['delete']);
        }
    }

    // Créer un dossier
    if (isset($_POST['new_folder'])) {
        $folder_name = $_POST['new_folder'];
        $new_dir = $current_dir . '/' . $folder_name;
        if ($sftp->mkdir($new_dir)) {
            echo "Dossier créé avec succès : " . htmlspecialchars($folder_name);
        } else {
            echo "Erreur : Impossible de créer le dossier " . htmlspecialchars($folder_name);
        }
    }

    // Téléverser un fichier
    if (isset($_FILES['upload_file'])) {
        $file_name = $_FILES['upload_file']['name'];
        $local_path = $_FILES['upload_file']['tmp_name'];
        $remote_path = $current_dir . '/' . $file_name;
        if ($sftp->put($remote_path, $local_path, SFTP::SOURCE_LOCAL_FILE)) {
            echo "Fichier téléversé avec succès : " . htmlspecialchars($file_name);
        } else {
            echo "Erreur : Impossible de téléverser le fichier.";
        }
    }

    // Déconnexion
    if (isset($_POST['logout']) && $_POST['logout'] === 'true') {
        session_destroy();
        header('Location: /index.php'); // Redirection vers la page de connexion
        exit;
    }
}

// Liste des fichiers/dossiers
$files = $sftp->nlist($current_dir);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion des fichiers</title>
</head>
<body>
    <h1>Bienvenue, <?php echo htmlspecialchars($username); ?></h1>
    <h2>Répertoire actuel : <?php echo htmlspecialchars($current_dir); ?></h2>

    <h3>Créer un dossier</h3>
    <form method="POST">
        <input type="text" name="new_folder" placeholder="Nom du dossier" required>
        <button type="submit">Créer</button>
    </form>

    <h3>Téléverser un fichier</h3>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="upload_file" required>
        <button type="submit">Téléverser</button>
    </form>

    <h3>Contenu du répertoire</h3>
    <ul>
        <?php if ($current_dir !== $base_dir): ?>
            <li><a href="?path=<?php echo urlencode(dirname($current_dir)); ?>">[Retour au dossier parent]</a></li>
        <?php endif; ?>
        <?php foreach ($files as $file): ?>
            <?php if ($file !== '.' && $file !== '..'): ?>
                <li>
                    <?php
                    $full_path = $current_dir . '/' . $file;
                    if ($sftp->is_dir($full_path)): ?>
                        <a href="?path=<?php echo urlencode($full_path); ?>">[Dossier] <?php echo htmlspecialchars($file); ?></a>
                    <?php else: ?>
                        <?php if (pathinfo($file, PATHINFO_EXTENSION) === 'txt'): ?>
                            <a href="download.php?path=<?php echo urlencode($full_path); ?>" target="_blank">[Fichier] <?php echo htmlspecialchars($file); ?></a>
                        <?php else: ?>
                            [Fichier] <?php echo htmlspecialchars($file); ?>
                        <?php endif; ?>
                    <?php endif; ?>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="delete" value="<?php echo htmlspecialchars($file); ?>">
                        <button type="submit">Supprimer</button>
                    </form>
                </li>
            <?php endif; ?>
        <?php endforeach; ?>
    </ul>

    <!-- Formulaire de déconnexion -->
    <form method="POST" style="display: inline;">
        <input type="hidden" name="logout" value="true">
        <button type="submit">Se déconnecter</button>
    </form>
</body>
</html>
