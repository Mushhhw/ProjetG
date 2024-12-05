<?php


ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


// Démarrage de la session
session_start();

// Vérification si l'utilisateur est un administrateur authentifié
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    session_destroy();
    header('Location: /index.php?error=unauthorized_admin');
    exit;
}

// Informations de connexion à la base de données
$host = 'localhost';
$dbname = 'projet';
$dbuser = 'projet';
$dbpass = 'Gb67SNBn??NyAsmt';

// Connexion à la base de données
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion à la base de données : " . $e->getMessage());
}

// Gestion des utilisateurs
$message = '';
$cli_output = '';

// Fonction pour générer un mot de passe haché avec Blowfish et SALT
function hash_password($password) {
    $salt = "Martine1337*";
    $blowfish_salt = '$2y$10$' . str_pad(substr(base64_encode($salt), 0, 22), 22, '.');
    return crypt($password, $blowfish_salt);
}

// Fonction pour calculer le port SSH personnalisé
function calculate_ssh_port($docker_id) {
    return 32768 + $docker_id; // Exemple : ID Docker 1 => Port 32769
}

// Fonction pour générer une paire de clés SSH avec ssh-keygen
function generate_ssh_keys_openSSH($docker_id) {
    $private_key_path = "/var/ssh/private_keys/{$docker_id}_id_rsa";
    $public_key_path = "/var/ssh/private_keys/{$docker_id}_id_rsa.pub";

    // Utilisation de ssh-keygen pour générer une paire de clés RSA
    $generate_command = "ssh-keygen -t rsa -b 2048 -f $private_key_path -N ''";  // -N '' pour ne pas définir de passphrase
    shell_exec($generate_command);

    // Lire la clé publique générée
    $public_key = file_get_contents($public_key_path);

    // Restreindre les permissions sur la clé privée
    chmod($private_key_path, 0600);

    // Retourner la clé publique pour l'ajouter à authorized_keys
    return $public_key;
}

// Fonction pour créer un docker container
function create_docker_container($username, $docker_id, $password) {
    global $cli_output;

    // Récupérer la clé publique depuis la base de données
    $stmt = $pdo->prepare("SELECT ssh_public_key FROM users WHERE docker_id = :docker_id");
    $stmt->execute([':docker_id' => $docker_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !isset($user['ssh_public_key'])) {
        $cli_output .= "Erreur : Clé publique non trouvée dans la base de données pour l'utilisateur.";
        return;
    }

    $ssh_public_key = $user['ssh_public_key'];
    
    // Calculer le port SSH personnalisé pour l'utilisateur
    $ssh_port = calculate_ssh_port($docker_id);

    // Charger le Dockerfile à partir du fichier Dockerfile (pas Dockerfile_template)
    $dockerfile_template = file_get_contents("/var/www/html/dockerfiles/Dockerfile");

    if (!$dockerfile_template) {
        $cli_output .= "Erreur : Le fichier Dockerfile n'a pas pu être trouvé.";
        return;
    }

    // Créer le Dockerfile avec les données spécifiques
    $dockerfile_content = str_replace(
        ['{{USERNAME}}', '{{PASSWORD}}', '{{AUTHORIZED_KEYS}}'],
        [$username, $password, $ssh_public_key],
        $dockerfile_template
    );

    // Sauvegarder le Dockerfile spécifique à cet utilisateur
    $dockerfile_path = "/var/www/html/dockerfiles/Dockerfile_$docker_id";
    file_put_contents($dockerfile_path, $dockerfile_content);

    // Construire l'image Docker avec la clé publique comme argument
    $cli_output .= shell_exec("docker build --build-arg SSH_PUBLIC_KEY=\"$ssh_public_key\" -t user_$docker_id -f $dockerfile_path . 2>&1");

    if (strpos($cli_output, 'Successfully built') === false) {
        $cli_output .= "Erreur : La construction de l'image Docker a échoué.";
        return;
    }

    // Démarrer le conteneur
    $cli_output .= shell_exec("docker run -d --name user_$docker_id -p $ssh_port:22 user_$docker_id 2>&1");
}

// Fonction pour supprimer un conteneur Docker
function delete_docker_container($docker_id) {
    global $cli_output;

    // Supprimer le conteneur Docker s'il existe
    $cli_output .= shell_exec("docker rm -f user_$docker_id 2>&1");

    // Supprimer l'image Docker associée
    $cli_output .= shell_exec("docker rmi user_$docker_id 2>&1");

    // Supprimer les fichiers Dockerfile associés
    $dockerfile_path = "/var/www/html/dockerfiles/Dockerfile_$docker_id";
    if (file_exists($dockerfile_path)) {
        if (unlink($dockerfile_path)) {
            $cli_output .= "Dockerfile associé au Docker ID {$docker_id} supprimé avec succès.\n";
        } else {
            $cli_output .= "Erreur : Impossible de supprimer le Dockerfile associé au Docker ID {$docker_id}.\n";
        }
    }

    // Supprimer les fichiers de clés SSH associés
    $private_key_path = "/var/ssh/private_keys/{$docker_id}_id_rsa";
    $public_key_path = "/var/ssh/private_keys/{$docker_id}_id_rsa.pub";

    if (file_exists($private_key_path)) {
        if (unlink($private_key_path)) {
            $cli_output .= "Clé privée associée au Docker ID {$docker_id} supprimée avec succès.\n";
        } else {
            $cli_output .= "Erreur : Impossible de supprimer la clé privée associée au Docker ID {$docker_id}.\n";
        }
    } else {
        $cli_output .= "Clé privée non trouvée pour le Docker ID {$docker_id}.\n";
    }

    if (file_exists($public_key_path)) {
        if (unlink($public_key_path)) {
            $cli_output .= "Clé publique associée au Docker ID {$docker_id} supprimée avec succès.\n";
        } else {
            $cli_output .= "Erreur : Impossible de supprimer la clé publique associée au Docker ID {$docker_id}.\n";
        }
    } else {
        $cli_output .= "Clé publique non trouvée pour le Docker ID {$docker_id}.\n";
    }
}

// Fonction pour créer un Dockerfile spécifique à un utilisateur
function create_dockerfile_for_user($username, $password, $ssh_public_key, $docker_id) {
    // Lire le modèle Dockerfile
    $dockerfile_template = file_get_contents("/var/www/html/dockerfiles/Dockerfile");

    if (!$dockerfile_template) {
        global $cli_output;
        $cli_output .= "Erreur : Le fichier Dockerfile n'a pas pu être trouvé.";
        return;
    }

    // Remplacer les espaces réservés par les informations spécifiques de l'utilisateur
    $dockerfile_content = str_replace(
        ['{{USERNAME}}', '{{PASSWORD}}'],
        [$username, $password],
        $dockerfile_template
    );

    // Ajouter la clé publique à authorized_keys
    $dockerfile_content = str_replace(
        '{{SSH_PUBLIC_KEY}}',
        addslashes($ssh_public_key),
        $dockerfile_content
    );

    // Sauvegarder le Dockerfile spécifique à l'utilisateur
    $dockerfile_path = "/var/www/html/dockerfiles/Dockerfile_$docker_id";
    file_put_contents($dockerfile_path, $dockerfile_content);

    return $dockerfile_path;
}

// Fonction pour ajouter un utilisateur dans la base de données
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_user'])) {
    $new_username = $_POST['username'] ?? '';
    $new_password = $_POST['password'] ?? '';
    $role_user = $_POST['role_user'] ?? '0';
    $docker_id = $_POST['docker_id'] ?? null;

    if (!empty($new_username) && !empty($new_password) && !empty($docker_id)) {
        try {
            // Hachage du mot de passe pour la base de données
            $hashed_password = hash_password($new_password);

            // Vérifier si l'utilisateur existe déjà
            $stmt_check = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
            $stmt_check->execute([':username' => $new_username]);
            $user_exists = $stmt_check->fetchColumn();

            if ($user_exists) {
                $message = "Erreur : L'utilisateur existe déjà.";
            } else {
                // Générer une paire de clés SSH au format OpenSSH
                $ssh_public_key = generate_ssh_keys_openSSH($docker_id);

                // Créer le Dockerfile spécifique à l'utilisateur
                $dockerfile_path = create_dockerfile_for_user($new_username, $new_password, $ssh_public_key, $docker_id);

                // Insertion dans la table users
                $stmt_insert = $pdo->prepare("
                    INSERT INTO users (username, password, role_user, docker_id, ssh_public_key)
                    VALUES (:username, :password, :role_user, :docker_id, :ssh_public_key)
                ");
                $stmt_insert->execute([
                    ':username' => $new_username,
                    ':password' => $hashed_password,
                    ':role_user' => $role_user,
                    ':docker_id' => $docker_id,
                    ':ssh_public_key' => $ssh_public_key, // Stockage de la clé publique
                ]);

                // Construire l'image Docker pour l'utilisateur
                $cli_output .= shell_exec("docker build --build-arg SSH_PUBLIC_KEY=\"$ssh_public_key\" -t user_$docker_id -f $dockerfile_path . 2>&1");

                // Vérifier si la construction a réussi avant de lancer le conteneur
                if (strpos($cli_output, 'Successfully built') === false) {
                    $message = "Erreur : La construction de l'image Docker a échoué.";
                } else {
                    // Démarrer le conteneur Docker
                    $ssh_port = calculate_ssh_port($docker_id);
                    $cli_output .= shell_exec("docker run -d --name user_$docker_id -p $ssh_port:22 user_$docker_id 2>&1");

                    $message = "Utilisateur $new_username créé avec succès avec le port SSH : " . $ssh_port;
                }
            }
        } catch (PDOException $e) {
            $message = "Erreur lors de la création de l'utilisateur : " . $e->getMessage();
        } catch (Exception $e) {
            $message = "Erreur lors de la génération des clés SSH : " . $e->getMessage();
        }
    } else {
        $message = "Erreur : Les champs utilisateur, mot de passe et Docker ID sont obligatoires.";
    }
}

// Supprimer un utilisateur et son conteneur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_user'])) {
    $user_id = $_POST['user_id'] ?? null;

    if (!empty($user_id)) {
        try {
            // Récupérer les informations de l'utilisateur
            $stmt_check = $pdo->prepare("SELECT docker_id FROM users WHERE id = :id");
            $stmt_check->execute([':id' => $user_id]);
            $user = $stmt_check->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $docker_id = $user['docker_id'];

                // Supprimer le conteneur Docker et les fichiers associés
                delete_docker_container($docker_id);

                // Supprimer l'utilisateur de la base de données
                $stmt_delete = $pdo->prepare("DELETE FROM users WHERE id = :id");
                $stmt_delete->execute([':id' => $user_id]);

                $message = "Utilisateur et conteneur Docker supprimés avec succès.";
            } else {
                $message = "Erreur : Utilisateur non trouvé.";
            }
        } catch (PDOException $e) {
            $message = "Erreur lors de la suppression de l'utilisateur : " . $e->getMessage();
        }
    } else {
        $message = "Erreur : L'ID de l'utilisateur est manquant.";
    }
}

// Modifier le mot de passe d’un utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    $user_id = $_POST['user_id'] ?? null;
    $new_password = $_POST['new_password'] ?? '';

    if (!empty($user_id) && !empty($new_password)) {
        try {
            // Hachage du nouveau mot de passe
            $hashed_password = hash_password($new_password);

            // Mise à jour du mot de passe
            $stmt_update = $pdo->prepare("UPDATE users SET password = :password WHERE id = :id");
            $stmt_update->execute([
                ':password' => $hashed_password,
                ':id' => $user_id
            ]);

            $message = "Mot de passe modifié avec succès.";
        } catch (PDOException $e) {
            $message = "Erreur lors de la modification du mot de passe : " . $e->getMessage();
        }
    } else {
        $message = "Erreur : Les champs sont obligatoires.";
    }
}

// Récupération des utilisateurs existants
try {
    $stmt = $pdo->query("SELECT * FROM users");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Erreur lors de la récupération des données : " . $e->getMessage());
}

// Déconnexion de l'utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']) && $_POST['logout'] === 'true') {
    session_destroy();
    header('Location: /index.php');
    exit;
}

// Récupération du nom de l'administrateur connecté
$admin_username = $_SESSION['username'];
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Admin</title>
</head>
<body>
    <header>
        <h1>Bienvenue, <?php echo htmlspecialchars($admin_username); ?> (Admin)</h1>
        <p>Utilisez les options ci-dessous pour gérer les utilisateurs et les conteneurs Docker.</p>
    </header>

    <main>
        <h2>Liste des utilisateurs</h2>
        <?php if (!empty($message)): ?>
            <p style="color: green;"><?php echo htmlspecialchars($message); ?></p>
        <?php endif; ?>
        <?php if (!empty($cli_output)): ?>
            <pre><?php echo htmlspecialchars($cli_output); ?></pre>
        <?php endif; ?>
        <table border="1">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nom d'utilisateur</th>
                    <th>Mot de passe (hashé)</th>
                    <th>Rôle</th>
                    <th>Docker ID</th>
                    <th>Clé SSH publique</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($user['id']); ?></td>
                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                        <td><?php echo htmlspecialchars($user['password']); ?></td>
                        <td><?php echo $user['role_user'] == 1 ? 'Admin' : 'Utilisateur'; ?></td>
                        <td><?php echo htmlspecialchars($user['docker_id'] ?? 'Non défini'); ?></td>
                        <td>
                            <?php if (!empty($user['ssh_public_key'])): ?>
                                <textarea readonly style="width: 100%; height: 80px;">
                                    <?php echo htmlspecialchars($user['ssh_public_key']); ?>
                                </textarea>
                            <?php else: ?>
                                Non défini
                            <?php endif; ?>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <button type="submit" name="delete_user" onclick="return confirm('Voulez-vous vraiment supprimer cet utilisateur ?');" <?php echo $user['role_user'] == 1 ? 'disabled' : ''; ?>>
                                    Supprimer
                                </button>
                            </form>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <input type="password" name="new_password" placeholder="Nouveau mot de passe" required>
                                <button type="submit" name="change_password">Modifier le mot de passe</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <h2>Créer un nouvel utilisateur</h2>
        <form method="POST">
            <label for="username">Nom d'utilisateur :</label>
            <input type="text" id="username" name="username" required>
            <br>
            <label for="password">Mot de passe :</label>
            <input type="password" id="password" name="password" required>
            <br>
            <label for="role_user">Rôle :</label>
            <select id="role_user" name="role_user">
                <option value="0">Utilisateur</option>
                <option value="1">Admin</option>
            </select>
            <br>
            <label for="docker_id">Docker ID :</label>
            <input type="number" id="docker_id" name="docker_id" required>
            <br>
            <button type="submit" name="create_user">Créer l'utilisateur</button>
        </form>
    </main>

    <footer>
        <form method="POST" style="text-align: left;">
            <input type="hidden" name="logout" value="true">
            <button type="submit">Déconnexion</button>
        </form>
        <p>&copy; 2024 - Votre entreprise</p>
    </footer>
</body>
</html>
