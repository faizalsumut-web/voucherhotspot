CREATE TABLE vouchers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(50) NOT NULL UNIQUE,
    status ENUM('available', 'sold') NOT NULL DEFAULT 'available',
    price DECIMAL(10, 2) NOT NULL,
    agent_id INT,
    sold_at TIMESTAMP NULL,
    FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE SET NULL
);