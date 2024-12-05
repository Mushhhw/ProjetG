<?php
include 'config.php';


// Démarrage de la session
session_start();

// Informations de connexion à la base de données MySQL


// Connexion à la base de données
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}


// Gestion des erreurs
$error_message = '';

// Fonction pour vérifier le mot de passe avec Blowfish + SALT
function verify_password($password, $hashed_password) {
    $salt = "Martine1337*";

    // Générer le même sel utilisé pour le hachage
    $blowfish_salt = '$2y$10$' . str_pad(substr(base64_encode($salt), 0, 22), 22, '.');

    // Vérifier le mot de passe
    return crypt($password, $blowfish_salt) === $hashed_password;
}

// Déconnexion si demandé
if (isset($_GET['logout']) && $_GET['logout'] === 'true') {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Traitement du formulaire de connexion
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (!empty($username) && !empty($password)) {
        try {
            // Récupérer les informations de l'utilisateur depuis la base de données
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
            $stmt->execute([':username' => $username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Vérifier le mot de passe avec Blowfish + SALT
                if (verify_password($password, $user['password'])) {
                    // Définir les sessions en fonction du rôle
                    if ($user['role_user'] == 1) {
                        $_SESSION['admin_logged_in'] = true;
                        $_SESSION['username'] = $user['username'];
                        header('Location: admin/index.php');
                        exit;
                    } else {
                        $_SESSION['user_logged_in'] = true;
                        $_SESSION['username'] = $user['username'];
                        header('Location: user/index.php');
                        exit;
                    }
                } else {
                    $error_message = "Identifiants incorrects. Veuillez réessayer.";
                }
            } else {
                $error_message = "Utilisateur non trouvé.";
            }
        } catch (PDOException $e) {
            $error_message = "Erreur lors de la connexion : " . $e->getMessage();
        }
    } else {
        $error_message = "Veuillez remplir tous les champs.";
    }
}


?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion</title>
</head>
<body>
    <h1>Connexion</h1>
    <?php if (!empty($error_message)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error_message); ?></p>
    <?php endif; ?>
    <form method="POST">
        <label for="username">Nom d'utilisateur :</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Mot de passe :</label>
        <input type="password" id="password" name="password" required>
        <br>
        <button type="submit">Se connecter</button>
    </form>
</body>
</html>
