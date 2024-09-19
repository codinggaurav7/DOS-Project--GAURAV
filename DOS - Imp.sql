CREATE DATABASE Attack_Detection;
CREATE DATABASE Network_Traffic;
CREATE DATABASE System_Resources;
CREATE DATABASE Incident_Response;
CREATE DATABASE Security_Information;
-- TABLE-1
USE Attack_Detection;
CREATE TABLE attacks (id INT PRIMARY KEY,attack_type INT,attack_date DATETIME,source_ip VARCHAR(50));
CREATE TABLE attack_types (id INT PRIMARY KEY,type_name VARCHAR(100),description VARCHAR(255));
CREATE TABLE sources (id INT PRIMARY KEY,source_ip VARCHAR(50),source_country VARCHAR(50));
CREATE TABLE detection_rules (id INT PRIMARY KEY,rule_name VARCHAR(100),rule_description VARCHAR(255));
CREATE TABLE alerts (id INT PRIMARY KEY,attack_id INT,alert_date DATETIME,alert_level VARCHAR(50));
-- TABLE-2
USE Network_Traffic;
CREATE TABLE traffic (id INT PRIMARY KEY,timestamp DATETIME,source_ip VARCHAR(50),destination_ip VARCHAR(50),protocol VARCHAR(50));
CREATE TABLE protocols (id INT PRIMARY KEY,protocol_name VARCHAR(50),protocol_description VARCHAR(255));
CREATE TABLE ip_addresses (id INT PRIMARY KEY,ip_address VARCHAR(50),ip_type VARCHAR(50));
CREATE TABLE network_devices (id INT PRIMARY KEY,device_name VARCHAR(100),device_type VARCHAR(100));
CREATE TABLE traffic_stats (id INT PRIMARY KEY,timestamp DATETIME,traffic_volume INT);
-- TABLE-3
USE System_Resources;
CREATE TABLE resource_usage (id INT PRIMARY KEY,timestamp DATETIME,cpu_usage DECIMAL(5, 2),memory_usage DECIMAL(5, 2),disk_usage DECIMAL(5, 2));
CREATE TABLE resources (id INT PRIMARY KEY,resource_name VARCHAR(100),resource_description VARCHAR(255));
CREATE TABLE system_stats (id INT PRIMARY KEY,timestamp DATETIME,system_load DECIMAL(5, 2),system_uptime DECIMAL(10, 2));
CREATE TABLE process_list (id INT PRIMARY KEY,process_name VARCHAR(100),process_pid INT,process_cpu_usage DECIMAL(5, 2));
CREATE TABLE user_sessions (id INT PRIMARY KEY,user_id VARCHAR(100),session_start DATETIME,session_end DATETIME);
-- TABLE-4
USE Incident_Response;
CREATE TABLE incidents (id INT PRIMARY KEY,incident_date DATETIME,incident_type VARCHAR(100),incident_description VARCHAR(255));
CREATE TABLE incident_types (id INT PRIMARY KEY,type_name VARCHAR(100),type_description VARCHAR(255));
CREATE TABLE response_plans (id INT PRIMARY KEY,plan_name VARCHAR(100),plan_description VARCHAR(255));
CREATE TABLE response_teams (id INT PRIMARY KEY,team_name VARCHAR(100),team_lead VARCHAR(100));
CREATE TABLE incident_reports (id INT PRIMARY KEY,incident_id INT,report_date DATETIME,report_description VARCHAR(255));
-- TABLE-5
USE Security_Information;
CREATE TABLE vulnerabilities (id INT PRIMARY KEY,vuln_name VARCHAR(100),vuln_description VARCHAR(255),vuln_severity VARCHAR(50));
CREATE TABLE patches (id INT PRIMARY KEY,patch_name VARCHAR(100),patch_description VARCHAR(255),patch_release_date DATE);
CREATE TABLE security_advisories (id INT PRIMARY KEY,advisory_name VARCHAR(100),advisory_description VARCHAR(255));
CREATE TABLE threat_intelligence (id INT PRIMARY KEY,threat_name VARCHAR(100),threat_description VARCHAR(255),threat_level VARCHAR(50));
CREATE TABLE security_incidents (id INT PRIMARY KEY,incident_id INT,security_incident_date DATETIME);

-- INSERT DATA IN T-1
USE Attack_Detection;
INSERT INTO attacks (id, attack_type, attack_date, source_ip)
VALUES
(1, 1, '2022-01-01 12:00:00', '192.168.1.100'),
(2, 2, '2022-01-02 13:00:00', '192.168.1.101'),
(3, 3, '2022-01-03 14:00:00', '192.168.1.102'),
(4, 1, '2022-01-04 15:00:00', '192.168.1.103'),
(5, 2, '2022-01-05 16:00:00', '192.168.1.104');

INSERT INTO attack_types (id, type_name, description) VALUES
(1, 'DDoS', 'Distributed Denial of Service'),
(2, 'SQL Injection', 'Structured Query Language Injection'),
(3, 'Cross-Site Scripting', 'XSS'),
(4, 'Brute Force', 'Password Guessing'),
(5, 'Phishing', 'Social Engineering');

INSERT INTO sources (id, source_ip, source_country) VALUES
(1, '192.168.1.100', 'USA'),
(2, '192.168.1.101', 'China'),
(3, '192.168.1.102', 'Russia'),
(4, '192.168.1.103', 'India'),
(5, '192.168.1.104', 'Brazil');

INSERT INTO detection_rules (id, rule_name, rule_description) VALUES
(1, 'Rule 1', 'Detect DDoS attacks'),
(2, 'Rule 2', 'Detect SQL Injection'),
(3, 'Rule 3', 'Detect XSS'),
(4, 'Rule 4', 'Detect Brute Force'),
(5, 'Rule 5', 'Detect Phishing');

INSERT INTO alerts (id, attack_id, alert_date, alert_level) VALUES
(1, 1, '2022-01-01 12:00:00', 'High'),
(2, 2, '2022-01-02 13:00:00', 'Medium'),
(3, 3, '2022-01-03 14:00:00', 'Low'),
(4, 4, '2022-01-04 15:00:00', 'High'),
(5, 5, '2022-01-05 16:00:00', 'Medium');

-- SELECT * FROM attacks;
-- SELECT * FROM alerts WHERE alert_level = 'High';

-- INSERT DATA IN T-2
USE Network_Traffic;
INSERT INTO traffic (id, timestamp, source_ip, destination_ip, protocol)
VALUES
(1, '2022-01-01 12:00:00', '192.168.1.100', '192.168.1.1', 'TCP'),
(2, '2022-01-02 13:00:00', '192.168.1.101', '192.168.1.2', 'UDP'),
(3, '2022-01-03 14:00:00', '192.168.1.102', '192.168.1.3', 'HTTP'),
(4, '2022-01-04 15:00:00', '192.168.1.103', '192.168.1.4', 'FTP'),
(5, '2022-01-05 16:00:00', '192.168.1.104', '192.168.1.5', 'SSH');

INSERT INTO protocols (id, protocol_name, protocol_description) VALUES
(1, 'TCP', 'Transmission Control Protocol'),
(2, 'UDP', 'User Datagram Protocol'),
(3, 'HTTP', 'Hypertext Transfer Protocol'),
(4, 'FTP', 'File Transfer Protocol'),
(5, 'SSH', 'Secure Shell');

INSERT INTO ip_addresses (id, ip_address, ip_type) VALUES
(1, '192.168.1.100', 'Public'),
(2, '192.168.1.101', 'Private'),
(3, '192.168.1.102', 'Public'),
(4, '192.168.1.103', 'Private'),
(5, '192.168.1.104', 'Public');

INSERT INTO network_devices (id, device_name, device_type) VALUES
(1, 'Router', 'Cisco'),
(2, 'Switch', 'HP'),
(3, 'Firewall', 'Juniper'),
(4, 'Server', 'Dell'),
(5, 'Client', 'Laptop');

INSERT INTO traffic_stats (id, timestamp, traffic_volume) VALUES
(1, '2022-01-01 12:00:00', 1000),
(2, '2022-01-02 13:00:00', 2000),
(3, '2022-01-03 14:00:00', 1500),
(4, '2022-01-04 15:00:00', 1800),
(5, '2022-01-05 16:00:00', 2100);

-- SELECT * FROM traffic;
-- SELECT * FROM traffic_stats WHERE traffic_volume > 1500;

-- INSERT DATA IN T-3
USE System_Resources;
INSERT INTO resource_usage (id, timestamp, cpu_usage, memory_usage, disk_usage) VALUES
(1, '2022-01-01 12:00:00', 25.50, 45.30, 75.20),
(2, '2022-01-02 13:00:00', 30.10, 50.20, 80.10),
(3, '2022-01-03 14:00:00', 40.50, 60.50, 85.50),
(4, '2022-01-04 15:00:00', 35.00, 55.00, 90.00),
(5, '2022-01-05 16:00:00', 50.70, 65.80, 95.90);

INSERT INTO resources (id, resource_name, resource_description) VALUES
(1, 'CPU', 'Central Processing Unit'),
(2, 'Memory', 'RAM Memory'),
(3, 'Disk', 'Hard Disk Storage'),
(4, 'Network', 'Network Adapter'),
(5, 'GPU', 'Graphics Processing Unit');

INSERT INTO system_stats (id, timestamp, system_load, system_uptime) VALUES
(1, '2022-01-01 12:00:00', 1.50, 240.50),
(2, '2022-01-02 13:00:00', 2.10, 300.75),
(3, '2022-01-03 14:00:00', 2.75, 360.25),
(4, '2022-01-04 15:00:00', 3.00, 420.10),
(5, '2022-01-05 16:00:00', 3.50, 480.90);

INSERT INTO process_list (id, process_name, process_pid, process_cpu_usage) VALUES
(1, 'nginx', 101, 10.50),
(2, 'mysqld', 102, 15.20),
(3, 'httpd', 103, 12.30),
(4, 'python', 104, 18.70),
(5, 'java', 105, 20.00);

INSERT INTO user_sessions (id, user_id, session_start, session_end) VALUES
(1, 'user_1', '2022-01-01 12:00:00', '2022-01-01 13:00:00'),
(2, 'user_2', '2022-01-02 13:00:00', '2022-01-02 14:00:00'),
(3, 'user_3', '2022-01-03 14:00:00', '2022-01-03 15:00:00'),
(4, 'user_4', '2022-01-04 15:00:00', '2022-01-04 16:00:00'),
(5, 'user_5', '2022-01-05 16:00:00', '2022-01-05 17:00:00');

-- SELECT * FROM resource_usage;
-- SELECT * FROM system_stats WHERE system_load > 2.00;

-- INSERT DATA IN T-4
USE Incident_Response;
INSERT INTO incidents (id, incident_date, incident_type, incident_description) VALUES
(1, '2022-01-01 14:00:00', 'DDoS Attack', 'Distributed Denial of Service attack detected'),
(2, '2022-01-02 15:00:00', 'SQL Injection', 'SQL Injection attempt on database'),
(3, '2022-01-03 16:00:00', 'XSS', 'Cross-site scripting vulnerability exploited'),
(4, '2022-01-04 17:00:00', 'Brute Force Attack', 'Brute force attack on login system'),
(5, '2022-01-05 18:00:00', 'Phishing', 'Phishing attempt via email detected');

INSERT INTO incident_types (id, type_name, type_description) VALUES
(1, 'DDoS', 'Distributed Denial of Service attack'),
(2, 'SQL Injection', 'SQL Injection attack on databases'),
(3, 'XSS', 'Cross-site scripting attack'),
(4, 'Brute Force', 'Password guessing attack'),
(5, 'Phishing', 'Social engineering attack to obtain sensitive information');

INSERT INTO response_plans (id, plan_name, plan_description) VALUES
(1, 'DDoS Mitigation Plan', 'Steps to mitigate DDoS attacks including rate-limiting and filtering'),
(2, 'SQL Injection Response', 'Plan to address and block SQL injection attacks'),
(3, 'XSS Defense', 'Plan to sanitize input and prevent XSS attacks'),
(4, 'Brute Force Protection', 'Procedure for locking accounts and monitoring login attempts'),
(5, 'Phishing Awareness', 'Guidelines for identifying phishing attempts and securing email communication');

INSERT INTO response_teams (id, team_name, team_lead) VALUES
(1, 'Incident Response Team A', 'John Doe'),
(2, 'Security Operations Team', 'Jane Smith'),
(3, 'Network Security Team', 'Alice Johnson'),
(4, 'Database Security Team', 'Bob Lee'),
(5, 'Email Security Team', 'Chris Brown');

INSERT INTO incident_reports (id, incident_id, report_date, report_description) VALUES
(1, 1, '2022-01-01 16:00:00', 'Report on DDoS attack and mitigation efforts'),
(2, 2, '2022-01-02 17:00:00', 'Report on SQL Injection and database patching'),
(3, 3, '2022-01-03 18:00:00', 'Report on XSS vulnerability and code fix'),
(4, 4, '2022-01-04 19:00:00', 'Report on brute force attack and password policy update'),
(5, 5, '2022-01-05 20:00:00', 'Report on phishing attempt and user awareness training');
-- SELECT * FROM incidents;
-- SELECT * FROM response_plans WHERE plan_name = 'DDoS Mitigation Plan';

-- ADD DATA TO T-5
USE Security_Information;
 INSERT INTO vulnerabilities (id, vuln_name, vuln_description, vuln_severity) VALUES
(1, 'CVE-2021-12345', 'Buffer Overflow Vulnerability in X Software', 'High'),
(2, 'CVE-2022-67890', 'SQL Injection Vulnerability in Y Web Application', 'Critical'),
(3, 'CVE-2023-11111', 'Cross-Site Scripting (XSS) in Z Service', 'Medium'),
(4, 'CVE-2023-22222', 'Privilege Escalation in Linux Kernel', 'High'),
(5, 'CVE-2024-33333', 'Remote Code Execution in Web Server', 'Critical');

INSERT INTO patches (id, patch_name, patch_description, patch_release_date) VALUES
(1, 'Patch 1.1', 'Fixes buffer overflow vulnerability in X software', '2022-02-01'),
(2, 'Patch 2.3', 'Addresses SQL injection in Y web application', '2022-03-10'),
(3, 'Patch 3.5', 'Resolves XSS vulnerability in Z service', '2023-05-15'),
(4, 'Patch 4.2', 'Fixes privilege escalation in Linux kernel', '2023-06-20'),
(5, 'Patch 5.0', 'Prevents remote code execution in web server', '2024-01-10');

INSERT INTO security_advisories (id, advisory_name, advisory_description) VALUES
(1, 'Advisory 001', 'Guidance on mitigating buffer overflow vulnerabilities'),
(2, 'Advisory 002', 'Alert on widespread SQL injection attacks in Y web application'),
(3, 'Advisory 003', 'Best practices for mitigating XSS vulnerabilities'),
(4, 'Advisory 004', 'Linux privilege escalation patch guidance'),
(5, 'Advisory 005', 'Remote code execution prevention techniques in web servers');

INSERT INTO threat_intelligence (id, threat_name, threat_description, threat_level) VALUES
(1, 'APT-34', 'Advanced Persistent Threat group targeting government sectors', 'High'),
(2, 'DarkHydrus', 'Phishing campaigns targeting Middle Eastern organizations', 'Critical'),
(3, 'Emotet', 'Malware used to deliver ransomware through phishing emails', 'Critical'),
(4, 'TrickBot', 'Banking malware aimed at stealing financial credentials', 'High'),
(5, 'Mirai Botnet', 'DDoS attacks using infected IoT devices', 'Medium');

INSERT INTO security_incidents (id, incident_id, security_incident_date) VALUES
(1, 1, '2022-01-15 10:30:00'),
(2, 2, '2022-02-20 11:00:00'),
(3, 3, '2023-03-25 14:45:00'),
(4, 4, '2023-06-30 16:00:00'),
(5, 5, '2024-01-05 18:30:00');
-- SELECT * FROM vulnerabilities;
-- SELECT * FROM threat_intelligence WHERE threat_level = 'Critical';

-- QUERIES FOR ATTACK TABLE
SELECT * FROM attacks;
SELECT * FROM attacks WHERE attack_type = 1;
SELECT * FROM attacks WHERE attack_date BETWEEN '2022-01-01' AND '2022-01-31';  
SELECT * FROM attacks WHERE source_ip = '192.168.1.100'; 

-- QUERIES FOR ATTACK TYPES TABLE
SELECT * FROM attack_types;  
SELECT * FROM attack_types WHERE type_name = 'DDoS'; 
SELECT * FROM attack_types WHERE description LIKE '%flooding%';  

-- QUERIES FOR SOURCE TABLE
SELECT * FROM sources;  
SELECT * FROM sources WHERE source_ip = '192.168.1.100'; 
SELECT * FROM sources WHERE source_country = 'USA'; 

-- QUERIES FOR DETECTION RULES TABLE
SELECT * FROM detection_rules; 
SELECT * FROM detection_rules WHERE rule_name = 'Rule 1'; 
SELECT * FROM detection_rules WHERE rule_description LIKE '%DDoS%'; 

-- QUERIES FOR ALERTS TABLE
SELECT * FROM alerts;  
SELECT * FROM alerts WHERE alert_level = 'High';  
SELECT * FROM alerts WHERE alert_date BETWEEN '2022-01-01' AND '2022-01-31'; 










