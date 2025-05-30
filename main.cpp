#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFiClient.h>

// Constants
const char* AP_SSID = "IoT_Portal";
const char* AP_PASSWORD = "password123";  // Consider a stronger password in production
const int DNS_PORT = 53;
const int WEB_PORT = 80;
const int MAX_LOGIN_ATTEMPTS = 3;
const unsigned long RATE_LIMIT_PERIOD = 60000; // 1 minute in milliseconds
const char* BACKEND_URL = "http://10.2.0.196:5000";  // Use your PC's local IP for backend
const char* WIFI_SSID = "Aiden Galaxy A70";  // Replace with your WiFi SSID
const char* WIFI_PASSWORD = "09090909";  // Replace with your WiFi Password


// Global variables
DNSServer dnsServer;
WebServer webServer(WEB_PORT);
IPAddress apIP(192, 168, 4, 1);
String csrfToken = ""; // Simple CSRF token
unsigned long lastLoginAttempt = 0;
int loginAttempts = 0;
String clientIP = "";

// Add these global variables at the top with other globals
bool isBackendConnected = false;
unsigned long lastBackendCheck = 0;
const unsigned long BACKEND_CHECK_INTERVAL = 5000; // 5 seconds

// HTML Templates
const char* loginPageHTML = R"(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Portal - Login</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
    .container { max-width: 400px; margin: 40px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h2 { color: #333; text-align: center; }
    input[type=text], input[type=password] { width: 100%; padding: 12px 10px; margin: 8px 0; display: inline-block; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background-color: #45a049; }
    .register-link { text-align: center; margin-top: 15px; }
    .error { color: red; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Login</h2>
    <div id="error-message" class="error"></div>
    <form id="login-form" action="/login" method="POST">
      <input type="hidden" name="csrf_token" value="%CSRF_TOKEN%">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Login</button>
    </form>
    <div class="register-link">
      Don't have an account? <a href="/register">Register</a>
    </div>
  </div>
  <script>
    document.getElementById('login-form').addEventListener('submit', function(e) {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      fetch('/login', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&csrf_token=${csrfToken}`
      })
      .then(response => response.json())
      .then(data => {
        console.log('Login response:', data);  // Debug line
        if (data.success) {
          localStorage.setItem('jwt', data.token);
          window.location.href = '/welcome';
        } else {
          document.getElementById('error-message').textContent = data.message || 'Login failed';
        }
      })
      .catch(error => {
        console.error('Login error:', error);  // Debug line
        document.getElementById('error-message').textContent = 'Connection error. Please try again.';
      });
    });
  </script>
</body>
</html>)";

const char* registerPageHTML = R"(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Portal - Register</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
    .container { max-width: 400px; margin: 40px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h2 { color: #333; text-align: center; }
    input[type=text], input[type=password] { width: 100%; padding: 12px 10px; margin: 8px 0; display: inline-block; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background-color: #45a049; }
    .login-link { text-align: center; margin-top: 15px; }
    .error { color: red; text-align: center; }
    .password-requirements { font-size: 12px; color: #666; margin-top: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Register</h2>
    <div id="error-message" class="error"></div>
    <form id="register-form" action="/register" method="POST">
      <input type="hidden" name="csrf_token" value="%CSRF_TOKEN%">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <div class="password-requirements">Password must be at least 8 characters and include uppercase, lowercase, number, and special character.</div>
      <label for="confirm-password">Confirm Password:</label>
      <input type="password" id="confirm-password" name="confirm-password" required>
      <button type="submit">Register</button>
    </form>
    <div class="login-link">
      Already have an account? <a href="/login">Login</a>
    </div>
  </div>
  <script>
    document.getElementById('register-form').addEventListener('submit', function(e) {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
      const csrfToken = document.querySelector('input[name="csrf_token"]').value;
      
      // Password validation
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(password)) {
        document.getElementById('error-message').textContent = 'Password does not meet requirements';
        return;
      }
      
      if (password !== confirmPassword) {
        document.getElementById('error-message').textContent = 'Passwords do not match';
        return;
      }
      
      fetch('/register', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&csrf_token=${csrfToken}`
      })
      .then(response => response.json())
      .then(data => {
        console.log('Registration response:', data);  // Debug line
        if (data.success) {
          alert('Registration successful! Please login.');
          window.location.href = '/login';
        } else {
          document.getElementById('error-message').textContent = data.message || 'Registration failed';
        }
      })
      .catch(error => {
        console.error('Registration error:', error);  // Debug line
        document.getElementById('error-message').textContent = 'Connection error. Please try again.';
      });
    });
  </script>
</body>
</html>
)";

const char* adminPageHTML = R"(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Portal - Admin</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
    .container { max-width: 800px; margin: 40px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h2 { color: #333; text-align: center; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .back-btn { background-color: #607d8b; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .action-btn { margin-right: 5px; padding: 5px 10px; border: none; border-radius: 3px; cursor: pointer; }
    .edit-btn { background-color: #2196F3; color: white; }
    .delete-btn { background-color: #f44336; color: white; }
    .add-btn { background-color: #4CAF50; color: white; padding: 10px; margin-bottom: 20px; border: none; border-radius: 4px; cursor: pointer; }
    .modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }
    .modal-content { background-color: white; margin: 15% auto; padding: 20px; border-radius: 5px; width: 70%; }
    .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
    .close:hover { color: black; }
    .form-group { margin-bottom: 15px; }
    .form-group label { display: block; margin-bottom: 5px; }
    .form-group input, .form-group textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
    .form-submit { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2>Admin Management</h2>
      <button id="back-btn" class="back-btn">Back to Dashboard</button>
    </div>
    
    <button id="add-admin-btn" class="add-btn">Add New Administrator</button>
    
    <table id="admins-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Email</th>
          <th>Phone</th>
          <th>Access Level</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="admins-body">
        <tr><td colspan="6">Loading administrators...</td></tr>
      </tbody>
    </table>
  </div>
  
  <!-- Add/Edit Admin Modal -->
  <div id="admin-modal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h3 id="modal-title">Add Administrator</h3>
      <form id="admin-form">
        <input type="hidden" id="admin-id">
        <div class="form-group">
          <label for="admin-name">Name:</label>
          <input type="text" id="admin-name" required>
        </div>
        <div class="form-group">
          <label for="admin-email">Email:</label>
          <input type="email" id="admin-email" required>
        </div>
        <div class="form-group">
          <label for="admin-phone">Phone:</label>
          <input type="tel" id="admin-phone">
        </div>
        <div class="form-group">
          <label for="admin-access">Access Level:</label>
          <select id="admin-access" required>
            <option value="regular">Regular</option>
            <option value="super">Super Admin</option>
          </select>
        </div>
        <button type="submit" class="form-submit">Save Administrator</button>
      </form>
    </div>
  </div>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const token = localStorage.getItem('jwt');
      if (!token) {
        window.location.href = '/login';
        return;
      }
      
      // Parse JWT to check role
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload.role !== 'admin') {
        alert('Access denied. Admin rights required.');
        window.location.href = '/dashboard';
        return;
      }
      
      // Load administrators
      loadAdmins();
      
      // Event listeners
      document.getElementById('back-btn').addEventListener('click', function() {
        window.location.href = '/dashboard';
      });
      
      document.getElementById('add-admin-btn').addEventListener('click', function() {
        openModal();
      });
      
      document.querySelector('.close').addEventListener('click', function() {
        closeModal();
      });
      
      document.getElementById('admin-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveAdmin();
      });
    });
    
    function loadAdmins() {
      const token = localStorage.getItem('jwt');
      
      fetch('/api/admins', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      .then(response => response.json())
      .then(data => {
        const tableBody = document.getElementById('admins-body');
        tableBody.innerHTML = '';
        
        if (data.admins && data.admins.length > 0) {
          data.admins.forEach(admin => {
            const row = document.createElement('tr');
            row.innerHTML = `
              <td>${admin.id}</td>
              <td>${admin.name}</td>
              <td>${admin.email}</td>
              <td>${admin.phone || '-'}</td>
              <td>${admin.access_level}</td>
              <td>
                <button class="action-btn edit-btn" data-id="${admin.id}">Edit</button>
                <button class="action-btn delete-btn" data-id="${admin.id}">Delete</button>
              </td>
            `;
            tableBody.appendChild(row);
          });
          
          // Add event listeners for edit and delete buttons
          document.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', function() {
              const adminId = this.getAttribute('data-id');
              editAdmin(adminId, data.admins);
            });
          });
          
          document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', function() {
              const adminId = this.getAttribute('data-id');
              deleteAdmin(adminId);
            });
          });
        } else {
          tableBody.innerHTML = '<tr><td colspan="6">No administrators available.</td></tr>';
        }
      })
      .catch(error => {
        document.getElementById('admins-body').innerHTML = '<tr><td colspan="6">Error loading administrators.</td></tr>';
        console.error('Error:', error);
      });
    }
    
    function openModal(admin = null) {
      const modal = document.getElementById('admin-modal');
      const modalTitle = document.getElementById('modal-title');
      const adminIdInput = document.getElementById('admin-id');
      const adminNameInput = document.getElementById('admin-name');
      const adminEmailInput = document.getElementById('admin-email');
      const adminPhoneInput = document.getElementById('admin-phone');
      const adminAccessInput = document.getElementById('admin-access');
      
      if (admin) {
        modalTitle.textContent = 'Edit Administrator';
        adminIdInput.value = admin.id;
        adminNameInput.value = admin.name;
        adminEmailInput.value = admin.email;
        adminPhoneInput.value = admin.phone || '';
        adminAccessInput.value = admin.access_level;
      } else {
        modalTitle.textContent = 'Add Administrator';
        adminIdInput.value = '';
        adminNameInput.value = '';
        adminEmailInput.value = '';
        adminPhoneInput.value = '';
        adminAccessInput.value = 'regular';
      }
      
      modal.style.display = 'block';
    }
    
    function closeModal() {
      const modal = document.getElementById('admin-modal');
      modal.style.display = 'none';
    }
    
    function editAdmin(adminId, admins) {
      const admin = admins.find(a => a.id == adminId);
      if (admin) {
        openModal(admin);
      }
    }
    
    function saveAdmin() {
      const token = localStorage.getItem('jwt');
      const adminId = document.getElementById('admin-id').value;
      const adminName = document.getElementById('admin-name').value;
      const adminEmail = document.getElementById('admin-email').value;
      const adminPhone = document.getElementById('admin-phone').value;
      const adminAccess = document.getElementById('admin-access').value;
      
      const adminData = {
        name: adminName,
        email: adminEmail,
        phone: adminPhone,
        access_level: adminAccess
      };
      
      const method = adminId ? 'PUT' : 'POST';
      const url = adminId ? `/api/admins/${adminId}` : '/api/admins';
      
      fetch(url, {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(adminData)
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          closeModal();
          loadAdmins();
        } else {
          alert(data.message || 'Error saving administrator');
        }
      })
      .catch(error => {
        alert('An error occurred. Please try again.');
        console.error('Error:', error);
      });
    }
    
    function deleteAdmin(adminId) {
      if (!confirm('Are you sure you want to delete this administrator?')) {
        return;
      }
      
      const token = localStorage.getItem('jwt');
      
      fetch(`/api/admins/${adminId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          loadAdmins();
        } else {
          alert(data.message || 'Error deleting administrator');
        }
      })
      .catch(error => {
        alert('An error occurred. Please try again.');
        console.error('Error:', error);
      });
    }
  </script>
</body>
</html>
)";

const char* welcomePageHTML = R"(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Portal - Welcome</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
    .container { max-width: 600px; margin: 40px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h2 { color: #333; text-align: center; }
    .welcome-message { text-align: center; margin: 20px 0; }
    .logout-btn { width: 100%; background-color: #f44336; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Welcome to IoT Portal</h2>
    <div class="welcome-message">
      <p>You are successfully logged in!</p>
      <p>Username: <span id="username"></span></p>
    </div>
    <button class="logout-btn" id="logoutBtn">Logout</button>
  </div>
  <script>
    // Get username from JWT token
    const token = localStorage.getItem('jwt');

    // Add event listener for logout button
    document.getElementById('logoutBtn').addEventListener('click', function() {
      localStorage.removeItem('jwt');
      window.location.href = '/login';
    });
    if (!token) {
      window.location.href = '/login';
    } else {
      const payload = JSON.parse(atob(token.split('.')[1]));
      document.getElementById('username').textContent = payload.username;
    }

    function logout() {
      localStorage.removeItem('jwt');
      window.location.href = '/login';
    }
  </script>
</body>
</html>
)";

// Function to generate a simple CSRF token (in production, use a more secure method)
String generateCSRFToken() {
  const int tokenLength = 16;
  String token = "";
  for (int i = 0; i < tokenLength; i++) {
    token += char('a' + random(0, 26));
  }
  return token;
}

// Function to replace tokens in HTML templates
String processHTML(const String& html, const String& csrfToken) {
  String processedHTML = html;
  processedHTML.replace("%CSRF_TOKEN%", csrfToken);
  return processedHTML;
}

// Captive portal detection - redirect any DNS request to our IP
class CaptiveRequestHandler : public RequestHandler {
public:
  CaptiveRequestHandler() {}
  bool canHandle(HTTPMethod method, String uri) { return true; }
  
  bool handle(WebServer& server, HTTPMethod requestMethod, String requestUri) {
    // Redirect to login page
    server.sendHeader("Location", String("/login"), true);
    server.send(302, "text/plain", "");
    return true;
  }
};

// Add this function before setup()
bool checkBackendConnection() {
    Serial.println("\n--- Checking Backend Connection ---");
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi not connected, reconnecting...");
        Serial.printf("Attempting to connect to: %s\n", WIFI_SSID);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
        int attempts = 0;
        while (WiFi.status() != WL_CONNECTED && attempts < 20) {
            delay(500);
            Serial.print(".");
            attempts++;
        }
        Serial.println();
        if (WiFi.status() != WL_CONNECTED) {
            return false;
        }
    }

    WiFiClient client;
    HTTPClient http;
    
    String url = String(BACKEND_URL) + "/api/health";
    Serial.print("Checking backend connection: ");
    Serial.println(url);
    
    http.begin(client, url);
    http.setTimeout(5000); // 5 second timeout
    
    int httpCode = http.GET();
    
    if (httpCode > 0) {
        String payload = http.getString();
        Serial.printf("HTTP Response code: %d\n", httpCode);
        Serial.printf("Response: %s\n", payload.c_str());
        http.end();
        return (httpCode == 200);
    } else {
        Serial.printf("Connection failed, error: %s\n", http.errorToString(httpCode).c_str());
        http.end();
        return false;
    }
}

void setup() {
  Serial.begin(115200);
  Serial.println("\n=== ESP32 IoT Portal Starting ===");
  Serial.println("Initializing...");
  
  // Set WiFi to station mode and disconnect from an AP if it was previously connected
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  delay(100);
  
  // Connect to WiFi
  Serial.printf("Connecting to WiFi: %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  Serial.println();
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("Connected to WiFi, IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("Failed to connect to WiFi");
  }
  
  // Set up WiFi in AP+STA mode
  WiFi.mode(WIFI_AP_STA);
  
  // Connect to WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected to WiFi, IP: ");
  Serial.println(WiFi.localIP());
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  
  Serial.print("AP IP address: ");
  Serial.println(apIP);
  
  // Start DNS server for captive portal
  dnsServer.start(DNS_PORT, "*", apIP);
  
  // Generate initial CSRF token
  csrfToken = generateCSRFToken();
  
  // Route definitions
  webServer.on("/", HTTP_GET, []() {
    // Redirect to login page
    webServer.sendHeader("Location", String("/login"), true);
    webServer.send(302, "text/plain", "");
  });
  
  webServer.on("/login", HTTP_GET, []() {
    webServer.send(200, "text/html", processHTML(loginPageHTML, csrfToken));
  });
  
  webServer.on("/login", HTTP_POST, []() {
    Serial.println("Login request received");  // Debug line
    Serial.println("Args: " + String(webServer.args()));  // Debug line
    
    // Check if rate limited
    if (loginAttempts >= MAX_LOGIN_ATTEMPTS && 
        (millis() - lastLoginAttempt) < RATE_LIMIT_PERIOD) {
      // Send rate limit error response
      StaticJsonDocument<200> jsonResponse;
      jsonResponse["success"] = false;
      jsonResponse["message"] = "Too many login attempts. Please try again later.";
      
      String response;
      serializeJson(jsonResponse, response);
      webServer.send(429, "application/json", response);
      return;
    }
    
    // Reset rate limit if period has passed
    if ((millis() - lastLoginAttempt) >= RATE_LIMIT_PERIOD) {
      loginAttempts = 0;
    }
    
    // Update login attempt tracking
    lastLoginAttempt = millis();
    loginAttempts++;
    
    // Check CSRF token
    if (webServer.hasArg("csrf_token") && webServer.arg("csrf_token") != csrfToken) {
      StaticJsonDocument<200> jsonResponse;
      jsonResponse["success"] = false;
      jsonResponse["message"] = "Invalid security token";
      
      String response;
      serializeJson(jsonResponse, response);
      webServer.send(403, "application/json", response);
      return;
    }
    
    // Get login credentials from POST data
    String username = webServer.arg("username");
    String password = webServer.arg("password");
    
    Serial.println("Login attempt:");
    Serial.println("Username: " + username);
    Serial.println("Password: " + password);
    
    StaticJsonDocument<200> jsonResponse;
    
    if (username.length() > 0 && password.length() > 0) {
      String mockJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.";
      mockJWT += "eyJ1c2VybmFtZSI6IiIgKyB1c2VybmFtZSArICIiLCJyb2xlIjoidXNlciJ9.";
      mockJWT += "SIGNATURE";
      
      jsonResponse["success"] = true;
      jsonResponse["message"] = "Login successful";
      jsonResponse["token"] = mockJWT;
      
      loginAttempts = 0;
      Serial.println("Login successful");  // Add this debug line
    } else {
      jsonResponse["success"] = false;
      jsonResponse["message"] = "Invalid username or password";
      Serial.println("Login failed");  // Add this debug line
    }
    
    String response;
    serializeJson(jsonResponse, response);
    Serial.println("Sending response: " + response);  // Add this debug line
    webServer.send(200, "application/json", response);
  });
  
  webServer.on("/register", HTTP_GET, []() {
    webServer.send(200, "text/html", processHTML(registerPageHTML, csrfToken));
  });
    webServer.on("/register", HTTP_POST, []() {
    Serial.println("\n--- Registration Request ---");
    Serial.println("Registration request received");
    Serial.printf("Client IP: %s\n", webServer.client().remoteIP().toString().c_str());
    
    String username = webServer.arg("username");
    String password = webServer.arg("password");
    
    StaticJsonDocument<200> requestBody;
    requestBody["username"] = username;
    requestBody["password"] = password;
    
    String jsonString;
    serializeJson(requestBody, jsonString);

    WiFiClient client;
    HTTPClient http;
    
    String url = String(BACKEND_URL) + "/api/register";
    Serial.println("Attempting to connect to: " + url);
    
    bool connected = http.begin(client, url);
    if (!connected) {
        Serial.println("Failed to connect to server");
        StaticJsonDocument<200> response;
        response["success"] = false;
        response["message"] = "Server connection failed";
        String responseStr;
        serializeJson(response, responseStr);
        webServer.send(503, "application/json", responseStr);
        return;
    }

    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);  // Increase timeout to 10 seconds
    
    int httpCode = http.POST(jsonString);
    String payload = http.getString();
    Serial.printf("HTTP Response code: %d\n", httpCode);
    Serial.printf("Response payload: %s\n", payload.c_str());
    
    http.end();
    
    StaticJsonDocument<200> responseDoc;
    if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_CREATED) {
        deserializeJson(responseDoc, payload);
        responseDoc["success"] = true;
    } else {
        responseDoc["success"] = false;
        responseDoc["message"] = "Registration failed: " + String(http.errorToString(httpCode));
    }
    
    String finalResponse;
    serializeJson(responseDoc, finalResponse);
    webServer.send(200, "application/json", finalResponse);
  });
  
  // Admin page route
  webServer.on("/admin", HTTP_GET, []() {
    webServer.send(200, "text/html", adminPageHTML);
  });
  
  // Add welcome page route
  webServer.on("/welcome", HTTP_GET, []() {
    webServer.send(200, "text/html", welcomePageHTML);
  });
  
  // API routes (mock implementations)
  webServer.on("/api/products", HTTP_GET, []() {
    // This would normally validate the JWT, but for the demo we'll accept any request
    StaticJsonDocument<512> jsonResponse;
    JsonArray products = jsonResponse.createNestedArray("products");
    
    // Mock product data
    JsonObject product1 = products.createNestedObject();
    product1["id"] = 1;
    product1["name"] = "Smart LED Bulb";
    product1["description"] = "WiFi-controlled multi-color LED bulb";
    product1["is_active"] = true;
    
    JsonObject product2 = products.createNestedObject();
    product2["id"] = 2;
    product2["name"] = "Temperature Sensor";
    product2["description"] = "Wireless temperature and humidity sensor";
    product2["is_active"] = true;
    
    String response;
    serializeJson(jsonResponse, response);
    webServer.send(200, "application/json", response);
  });
  
  webServer.on("/api/products", HTTP_POST, []() {
    // This would normally validate the JWT and admin role
    StaticJsonDocument<200> jsonResponse;
    jsonResponse["success"] = true;
    jsonResponse["message"] = "Product created successfully";
    jsonResponse["product_id"] = 3; // Mock ID for new product
    
    String response;
    serializeJson(jsonResponse, response);
    webServer.send(200, "application/json", response);
  });
  
  webServer.on("/api/admins", HTTP_GET, []() {
    StaticJsonDocument<1024> jsonResponse;
    JsonArray admins = jsonResponse.createNestedArray("admins");
    
    // Mock admin data
    JsonObject admin1 = admins.createNestedObject();
    admin1["id"] = 1;
    admin1["name"] = "John Doe";
    admin1["email"] = "john@example.com";
    admin1["phone"] = "1234567890";
    admin1["access_level"] = "super";
    admin1["is_active"] = true;
    
    JsonObject admin2 = admins.createNestedObject();
    admin2["id"] = 2;
    admin2["name"] = "Jane Smith";
    admin2["email"] = "jane@example.com";
    admin2["phone"] = "0987654321";
    admin2["access_level"] = "regular";
    admin2["is_active"] = true;
    
    String response;
    serializeJson(jsonResponse, response);
    webServer.send(200, "application/json", response);
  });
  
  // Add a default handler for all other routes
  webServer.addHandler(new CaptiveRequestHandler());
  
  // Start the web server
  webServer.begin();
  
  Serial.println("HTTP server started");
}

void loop() {
  static unsigned long lastWifiCheck = 0;
  unsigned long currentMillis = millis();
  
  if (WiFi.status() != WL_CONNECTED && (currentMillis - lastWifiCheck >= 5000)) {
    lastWifiCheck = currentMillis;
    Serial.println("\n--- WiFi Status Check ---");
    Serial.println("WiFi connection lost. Reconnecting...");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }
  
  dnsServer.processNextRequest();
  webServer.handleClient();
  
  // Check backend connection periodically
  if (millis() - lastBackendCheck > BACKEND_CHECK_INTERVAL) {
    checkBackendConnection();
    lastBackendCheck = millis();
  }
  
  // Add a small delay to prevent watchdog timer issues
  delay(1);
}