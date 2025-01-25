## FUTURE_CS_01

### HELLO 😁
### Here is the walkthrough documentation of how I completed Task 1 of the Cyber Security Internship at Future Interns :-

### I have made use of my <a href="https://github.com/ABRM2002/BASIC-HOME-LAB/tree/main">**HOME LAB**</a> for completing this task which includes my Windows and Kali Linux as 2 of my virtual machines and I start off by Installing the tool OWASP ZAP on my Kali machine via Official Website : <a href="https://www.zaproxy.org/download"> OWASP ZAP </a>
---
 
# Task 1 : **Perform a Vulnerability Assessment of a Sample Web Application**
![image](https://github.com/user-attachments/assets/eb70a5d2-204d-416e-8c90-1bb03ff6c9f1)

---

## A. Tool Used : **OWASP ZAP** :- 
### **ZAP also called Zed Attack Proxy is an open-source web application security testing tool that offers a range of features, including vulnerability scanning, proxying, and fuzzing.**

### Target Sample Web Application : **OWASP JUICE SHOP**

### **OWASP JUICE SHOP** : **It is a Modern web application deliberately designed to be insecure for learning purposes and is easier to set up**

![Screenshot 2025-01-23 223037](https://github.com/user-attachments/assets/94bf2b23-4b61-4891-b8eb-cc70113ae892)


---

### Steps:-

### Step 1: Install OWASP Juice Shop Using Docker :-

### If Docker is installed on your Kali Linux, you can set up OWASP Juice Shop with a single command. Here’s how:

### 1. Install Docker : Open your terminal and run the following commands:-

- sudo apt update

- sudo apt install docker.io

- sudo systemctl start docker

- sudo systemctl enable docker

---

### 2. Pull and Run OWASP Juice Shop: Run the following command to download and start OWASP Juice Shop via Docker:-

- sudo docker pull bkimminich/juice-shop - This command downloads the official OWASP Juice Shop image from Docker Hub.

- sudo docker run -d -p 3000:3000 bkimminich/juice-shop - After pulling the image, starts the Juice Shop container.

### Explanation of Each Part:

**sudo:**
- This runs the command with superuser (root) privileges, which is often needed to run Docker commands if your user is not part of the docker group.
If your user already has Docker permissions, you can omit this part.

**docker run:**
- This is the command to start a new Docker container based on an image. It tells Docker to create and run a container from a specified image.

**-d:**
- This flag stands for "detached mode". It runs the container in the background, so your terminal is free for other tasks. Without this flag, the container would run in the foreground, and you'd need to open a new terminal for other commands.

**-p 3000 : 3000:**
- This flag is used to map ports between your host machine and the container.

**3000:3000 means:**
- The first 3000 is the port on your host machine (your local computer).
The second 3000 is the port inside the Docker container where the Juice Shop web application is running.

- This maps the container’s port 3000 to your machine’s port 3000, allowing you to access the Juice Shop web app in your browser by visiting http://localhost:3000.

**bkimminich/juice-shop:**
- This is the Docker image name. bkimminich/juice-shop refers to the official Docker image for OWASP Juice Shop, which is maintained by Björn Kimminich (the creator of Juice Shop).
If this image isn’t already downloaded to your machine, Docker will pull it from Docker Hub (an online repository of Docker images) before running the container.

![Screenshot 2025-01-24 142310](https://github.com/user-attachments/assets/063056e3-900b-4d36-b4d0-0cb6b5ac8a88)


---

## 3. Access Juice Shop: Once the container is running, you can access the Juice Shop web application by navigating to:-

- Search this url on the browser : http://localhost:3000

---

## Step 2: Perform a vulnerability assessment on the OWASP Juice Shop :-

- Set the Target URL (OWASP Juice Shop):-
Enter the target URL:

In OWASP ZAP, you’ll see a browser-like interface at the top after selecting Automated Scan.


![Screenshot 2025-01-24 142445](https://github.com/user-attachments/assets/bf0dfa84-866a-4d17-82f4-af09e2b71156)


- Enter the target URL of Juice Shop (running on Docker): http://localhost:3000

- Then click on attack it will start the 2 types of scans

- Spider Scan:

This will crawl the Juice Shop application to identify all reachable pages.

- Active Scan:

This scan will actively test for vulnerabilities like SQL Injection, XSS, and more.
Review the Results:

![Screenshot 2025-01-24 142840](https://github.com/user-attachments/assets/1e185a85-e4f0-4148-af4e-fb593e5051ca)


- Once the scan completes, go to the Alerts tab.

- ZAP will list vulnerabilities along with their severity (e.g., Low, Medium, High).

- Document these vulnerabilities for your report.

![Screenshot 2025-01-24 143147](https://github.com/user-attachments/assets/6e5dcdd5-33de-4959-a274-86563e075586)


---

## Key Findings:

- Number of Medium-Risk Vulnerabilities: 3
- Number of Low-Risk Vulnerabilities: 2
- Number of Informational Vulnerabilities: 2

## **Vulnerability Assessment Report** :-

[Vulnerability Assessment Report Task 1 - OWASP ZAP.pdf](https://github.com/user-attachments/files/18533382/Vulnerability.Assessment.Report.Task.1.-.OWASP.ZAP.pdf)

---

## B. Tool Used : **Nmap** :-






## Summary of Nmap Commands for Juice Shop on Port 3000 :-

- Basic Nmap scan on port 3000:

Command: nmap -p 3000 localhost
Purpose: Scans port 3000 to check if it's open.
Expected Outcome: Port 3000 should show as open if OWASP Juice Shop is running.

---

- Service version detection on port 3000:

Command: nmap -sV -p 3000 localhost
Purpose: Tries to detect the version of the service running on port 3000.
Expected Outcome: If Juice Shop is running, the service version detection may not yield detailed results due to custom configurations (e.g., Node.js). Sometimes the service might be identified as HTTP or web server, but exact details may be missed.

---

- Operating system detection (optional) on port 3000:

Command: nmap -O -p 3000 localhost
Purpose: Attempts to detect the operating system running on the machine hosting the service.
Expected Outcome: If the machine is a local VM or container, Nmap might not always identify the OS precisely, especially if it's a specialized system like Kali Linux or a Docker container.

---

- Vulnerability scan on port 3000:

Command: nmap --script vuln -p 3000 localhost
Purpose: Runs a general vulnerability scan to find common security flaws.
Expected Outcome: If the OWASP Juice Shop is running, vulnerabilities may not be identified unless they're specifically known or targeted by one of the vuln scripts. Juice Shop itself is intentionally insecure, so many vulnerabilities will require targeted scanning beyond basic Nmap scripts.

---

- Web vulnerability scanning on port 3000:

Command: nmap --script http-sql-injection,http-enum,http-vuln-cve2017-5638 -p 3000 localhost
Purpose: Uses specific Nmap scripts to check for common web vulnerabilities like SQL injection or known CVE vulnerabilities.
Expected Outcome: Juice Shop is designed with multiple vulnerabilities for educational purposes, but not all scanners might detect them unless they focus on specific issues (e.g., authentication bypass, XXS, etc.).

---

- HTTP service enumeration on port 3000:

Command: nmap --script http-enum -p 3000 localhost
Purpose: Enumerates HTTP-related services (directories, common issues).
Expected Outcome: Nmap will try to identify any public directories or misconfigurations. However, Juice Shop might not trigger any obvious findings unless there are misconfigurations or exposed admin panels.

