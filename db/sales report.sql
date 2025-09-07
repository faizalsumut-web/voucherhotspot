CREATE TABLE sales_reports (
     id INT AUTO_INCREMENT PRIMARY KEY,
    report_type ENUM('weekly', 'monthly') NOT NULL,
    total_revenue DECIMAL(10, 2) NOT NULL,
     report_date DATE NOT NULL,
   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);