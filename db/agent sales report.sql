 CREATE TABLE agent_sales_reports (
     id INT AUTO_INCREMENT PRIMARY KEY,
     agent_id INT NOT NULL,
     report_type ENUM('weekly', 'monthly') NOT NULL,
        total_revenue DECIMAL(10, 2) NOT NULL,
     report_date DATE NOT NULL,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE CASCADE
 );