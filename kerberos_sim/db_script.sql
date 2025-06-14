DROP DATABASE kerberos_db;

-- Tạo database
CREATE DATABASE kerberos_db;
USE kerberos_db;

-- Bảng users: Lưu thông tin người dùng
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Mật khẩu hash (SHA-256)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng services: Danh sách dịch vụ trong hệ thống
CREATE TABLE services (
    id INT PRIMARY KEY AUTO_INCREMENT,
    service_name VARCHAR(255) UNIQUE NOT NULL,
    service_key VARCHAR(255) NOT NULL, -- Khóa bí mật của dịch vụ
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng service_tickets: Lưu thông tin Service Ticket (ST)
CREATE TABLE service_tickets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    service_name VARCHAR(255) NOT NULL, -- Dịch vụ mà ST cấp quyền truy cập
    ticket_data TEXT NOT NULL, 
    session_key VARCHAR(255) NOT NULL, -- Session key của phiên làm việc
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Thời điểm cấp
    expires_at TIMESTAMP NOT NULL, -- Thời điểm hết hạn
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (service_name) REFERENCES services(service_name) ON DELETE CASCADE
);

-- Bảng logs: Lưu lịch sử truy cập dịch vụ
CREATE TABLE logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    service_name VARCHAR(255) NOT NULL, -- Dịch vụ mà user đã truy cập
    access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Thời gian truy cập
    status VARCHAR(50) NOT NULL, -- Trạng thái truy cập (Thành công/Thất bại)
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (service_name) REFERENCES services(service_name) ON DELETE CASCADE
);
