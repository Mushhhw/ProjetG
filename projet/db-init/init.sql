CREATE DATABASE IF NOT EXISTS projet;
USE projet;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role_user INT NOT NULL,
    docker_id INT NULL,
    ssh_public_key TEXT NULL
);

INSERT INTO users (username, password, role_user)
VALUES ('admin', '$2y$10$...', 1);
