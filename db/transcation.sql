CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voucher_id INT,
    agent_id INT,
    amount DECIMAL(10, 2) NOT NULL,
    type ENUM('sale', 'topup') NOT NULL,
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (voucher_id) REFERENCES vouchers(id),
    FOREIGN KEY (agent_id) REFERENCES users(id)
);