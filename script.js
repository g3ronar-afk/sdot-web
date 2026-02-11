// Global Variables
let currentUser = null;
let currentRole = null;
let authToken = null;
let performanceChart = null;
let conversionChart = null;

// API Base URL
const API_BASE = '/.netlify/functions/api';

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    const savedUser = localStorage.getItem('sdot_user');
    const savedRole = localStorage.getItem('sdot_role');
    const savedToken = localStorage.getItem('sdot_token');
    
    if (savedUser && savedRole && savedToken) {
        currentUser = savedUser;
        currentRole = savedRole;
        authToken = savedToken;
        showDashboard();
    }
    
    // Setup event listeners
    setupEventListeners();
});

// Setup all event listeners
function setupEventListeners() {
    // Login
    document.getElementById('login-btn').addEventListener('click', login);
    document.getElementById('login-password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', logout);
    
    // Tab Navigation
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
    
    // Modal close buttons
    document.querySelector('.modal-close').addEventListener('click', hideModal);
    document.querySelector('.modal-cancel').addEventListener('click', hideModal);
    document.querySelector('.modal-overlay').addEventListener('click', function(e) {
        if (e.target === this) hideModal();
    });
    
    // Add buttons
    document.getElementById('add-script-btn').addEventListener('click', () => showAddForm('script'));
    document.getElementById('add-objection-btn').addEventListener('click', () => showAddForm('objection'));
    document.getElementById('add-performance-btn').addEventListener('click', () => showAddForm('performance'));
    document.getElementById('add-user-btn').addEventListener('click', () => showAddForm('user'));
    
    // Export button
    document.getElementById('export-performance-btn').addEventListener('click', exportPerformanceData);
}

// Login Function
async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    
    if (!username || !password) {
        showAlert('Please enter both username and password', 'error');
        return;
    }
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user.username;
            currentRole = data.user.role;
            authToken = data.token;
            
            // Save to localStorage
            localStorage.setItem('sdot_user', currentUser);
            localStorage.setItem('sdot_role', currentRole);
            localStorage.setItem('sdot_token', authToken);
            
            showDashboard();
            showAlert('Login successful!', 'success');
        } else {
            showAlert(data.message || 'Invalid credentials', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showAlert('Login failed. Please try again.', 'error');
    } finally {
        hideLoading();
    }
}

// Show Dashboard
function showDashboard() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('main-dashboard').style.display = 'block';
    
    // Update user info
    document.getElementById('current-user').textContent = currentUser;
    document.getElementById('current-role').textContent = currentRole.charAt(0).toUpperCase() + currentRole.slice(1);
    
    // Show/hide admin tabs
    const adminTab = document.querySelector('[data-tab="users"]');
    if (adminTab) {
        adminTab.style.display = currentRole === 'admin' ? 'flex' : 'none';
    }
    
    // Load dashboard data
    loadDashboardData();
    loadScripts();
    loadObjections();
    loadPerformanceData();
    if (currentRole === 'admin') {
        loadUsers();
    }
}

// Logout Function
function logout() {
    currentUser = null;
    currentRole = null;
    authToken = null;
    
    // Clear localStorage
    localStorage.removeItem('sdot_user');
    localStorage.removeItem('sdot_role');
    localStorage.removeItem('sdot_token');
    
    // Reset forms
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('remember-me').checked = false;
    
    // Show login screen
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('main-dashboard').style.display = 'none';
    
    showAlert('Logged out successfully', 'success');
}

// Switch between tabs
function switchTab(tabName) {
    // Update active tab
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update active content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`tab-${tabName}`).classList.add('active');
    
    // Refresh tab data if needed
    if (tabName === 'dashboard') {
        loadDashboardData();
    }
}

// Load Dashboard Data
async function loadDashboardData() {
    try {
        const response = await fetch(`${API_BASE}/dashboard`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Update stats
            document.getElementById('total-dials').textContent = data.summary.total_dials || 0;
            document.getElementById('total-connects').textContent = data.summary.total_connects || 0;
            document.getElementById('total-appointments').textContent = data.summary.total_appointments || 0;
            document.getElementById('total-conversions').textContent = data.summary.total_conversions || 0;
            
            // Update charts
            updateCharts(data.performance);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Update Charts
function updateCharts(performanceData) {
    const ctx1 = document.getElementById('performance-chart').getContext('2d');
    const ctx2 = document.getElementById('conversion-chart').getContext('2d');
    
    // Destroy existing charts
    if (performanceChart) performanceChart.destroy();
    if (conversionChart) conversionChart.destroy();
    
    // Prepare data
    const dates = performanceData.map(p => p.date).slice(-10); // Last 10 dates
    const dials = performanceData.map(p => p.dials).slice(-10);
    const connects = performanceData.map(p => p.connects).slice(-10);
    const appointments = performanceData.map(p => p.appointments).slice(-10);
    const conversions = performanceData.map(p => p.conversions).slice(-10);
    
    // Performance Chart
    performanceChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Dials',
                    data: dials,
                    borderColor: '#3B82F6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Connects',
                    data: connects,
                    borderColor: '#8B5CF6',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Appointments',
                    data: appointments,
                    borderColor: '#10B981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Daily Performance Trends'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Conversion Chart
    const connectRates = performanceData.map(p => p.dials > 0 ? (p.connects / p.dials * 100).toFixed(1) : 0).slice(-10);
    const appointmentRates = performanceData.map(p => p.connects > 0 ? (p.appointments / p.connects * 100).toFixed(1) : 0).slice(-10);
    const conversionRates = performanceData.map(p => p.appointments > 0 ? (p.conversions / p.appointments * 100).toFixed(1) : 0).slice(-10);
    
    conversionChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Connect Rate %',
                    data: connectRates,
                    backgroundColor: 'rgba(59, 130, 246, 0.7)'
                },
                {
                    label: 'Appointment Rate %',
                    data: appointmentRates,
                    backgroundColor: 'rgba(16, 185, 129, 0.7)'
                },
                {
                    label: 'Conversion Rate %',
                    data: conversionRates,
                    backgroundColor: 'rgba(139, 92, 246, 0.7)'
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Conversion Rates (%)'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Percentage'
                    }
                }
            }
        }
    });
}

// Load Scripts
async function loadScripts() {
    try {
        const response = await fetch(`${API_BASE}/scripts`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        const tbody = document.getElementById('scripts-table-body');
        
        if (data.success && data.scripts) {
            tbody.innerHTML = data.scripts.map(script => `
                <tr>
                    <td>${script.title}</td>
                    <td>${script.persona || 'N/A'}</td>
                    <td>${script.created_by || currentUser}</td>
                    <td>${new Date(script.created_at).toLocaleDateString()}</td>
                    <td class="action-buttons">
                        <button class="action-btn view" onclick="viewScript(${script.id})">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${currentRole === 'admin' || script.created_by === currentUser ? `
                        <button class="action-btn edit" onclick="editScript(${script.id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete" onclick="deleteScript(${script.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No scripts found</td></tr>';
        }
    } catch (error) {
        console.error('Error loading scripts:', error);
    }
}

// Show Add/Edit Form
function showAddForm(type, id = null) {
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.querySelector('.modal-body');
    const modalSave = document.querySelector('.modal-save');
    
    if (type === 'script') {
        modalTitle.textContent = id ? 'Edit Script' : 'Add New Script';
        
        modalBody.innerHTML = `
            <div class="form-group">
                <label for="script-title">Title</label>
                <input type="text" id="script-title" class="form-control" placeholder="Enter script title">
            </div>
            <div class="form-group">
                <label for="script-content">Content</label>
                <textarea id="script-content" class="form-control" rows="6" placeholder="Enter script content"></textarea>
            </div>
            <div class="form-group">
                <label for="script-persona">Persona</label>
                <input type="text" id="script-persona" class="form-control" placeholder="Enter target persona">
            </div>
        `;
        
        if (id) {
            // Load existing data for editing
            fetchScriptData(id);
        }
        
        modalSave.onclick = () => saveScript(id);
        
    } else if (type === 'performance') {
        modalTitle.textContent = id ? 'Edit Performance' : 'Add Performance';
        
        modalBody.innerHTML = `
            <div class="form-row">
                <div class="form-group">
                    <label for="perf-date">Date</label>
                    <input type="date" id="perf-date" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="perf-dials">Dials</label>
                    <input type="number" id="perf-dials" class="form-control" min="0" required>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="perf-connects">Connects</label>
                    <input type="number" id="perf-connects" class="form-control" min="0" required>
                </div>
                <div class="form-group">
                    <label for="perf-appointments">Appointments</label>
                    <input type="number" id="perf-appointments" class="form-control" min="0" required>
                </div>
            </div>
            <div class="form-group">
                <label for="perf-conversions">Conversions</label>
                <input type="number" id="perf-conversions" class="form-control" min="0" required>
            </div>
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                Note: Connects cannot exceed Dials, Appointments cannot exceed Connects, Conversions cannot exceed Appointments
            </div>
        `;
        
        if (id) {
            // Load existing data for editing
            fetchPerformanceData(id);
        }
        
        modalSave.onclick = () => savePerformance(id);
        
    } else if (type === 'user' && currentRole === 'admin') {
        modalTitle.textContent = id ? 'Edit User' : 'Add New User';
        
        modalBody.innerHTML = `
            <div class="form-group">
                <label for="user-username">Username</label>
                <input type="text" id="user-username" class="form-control" placeholder="Enter username" ${id ? 'readonly' : ''}>
            </div>
            ${!id ? `
            <div class="form-group">
                <label for="user-password">Password</label>
                <input type="password" id="user-password" class="form-control" placeholder="Enter password">
            </div>
            <div class="form-group">
                <label for="user-confirm-password">Confirm Password</label>
                <input type="password" id="user-confirm-password" class="form-control" placeholder="Confirm password">
            </div>
            ` : ''}
            <div class="form-group">
                <label for="user-role">Role</label>
                <select id="user-role" class="form-control">
                    <option value="admin">Admin</option>
                    <option value="client">Client</option>
                    <option value="va">Virtual Assistant</option>
                </select>
            </div>
            ${id ? `
            <div class="form-group">
                <label>Reset Password</label>
                <input type="password" id="user-new-password" class="form-control" placeholder="Leave blank to keep current password">
            </div>
            ` : ''}
        `;
        
        if (id) {
            // Load existing data for editing
            fetchUserData(id);
        }
        
        modalSave.onclick = () => saveUser(id);
    }
    
    showModal();
}

// Show Modal
function showModal() {
    document.getElementById('modal-overlay').style.display = 'flex';
}

// Hide Modal
function hideModal() {
    document.getElementById('modal-overlay').style.display = 'none';
}

// Save Script
async function saveScript(id = null) {
    const title = document.getElementById('script-title').value.trim();
    const content = document.getElementById('script-content').value.trim();
    const persona = document.getElementById('script-persona').value.trim();
    
    if (!title || !content) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/scripts${id ? `/${id}` : ''}`, {
            method: id ? 'PUT' : 'POST',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title, content, persona })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`Script ${id ? 'updated' : 'added'} successfully!`, 'success');
            hideModal();
            loadScripts();
        } else {
            showAlert(data.message || 'Error saving script', 'error');
        }
    } catch (error) {
        console.error('Error saving script:', error);
        showAlert('Failed to save script', 'error');
    }
}

// Save Performance
async function savePerformance(id = null) {
    const date = document.getElementById('perf-date').value;
    const dials = parseInt(document.getElementById('perf-dials').value);
    const connects = parseInt(document.getElementById('perf-connects').value);
    const appointments = parseInt(document.getElementById('perf-appointments').value);
    const conversions = parseInt(document.getElementById('perf-conversions').value);
    
    // Validation
    if (!date || isNaN(dials) || isNaN(connects) || isNaN(appointments) || isNaN(conversions)) {
        showAlert('Please fill in all fields with valid numbers', 'error');
        return;
    }
    
    if (connects > dials) {
        showAlert('Connects cannot exceed Dials', 'error');
        return;
    }
    
    if (appointments > connects) {
        showAlert('Appointments cannot exceed Connects', 'error');
        return;
    }
    
    if (conversions > appointments) {
        showAlert('Conversions cannot exceed Appointments', 'error');
        return;
    }
    
    try {
        // Check for duplicate date for the same user
        if (!id) {
            const checkResponse = await fetch(`${API_BASE}/performance/check-date?date=${date}`, {
                headers: { 
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            const checkData = await checkResponse.json();
            
            if (checkData.exists) {
                showAlert('Performance data already exists for this date. Please edit the existing entry instead.', 'error');
                return;
            }
        }
        
        const response = await fetch(`${API_BASE}/performance${id ? `/${id}` : ''}`, {
            method: id ? 'PUT' : 'POST',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ date, dials, connects, appointments, conversions })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`Performance data ${id ? 'updated' : 'added'} successfully!`, 'success');
            hideModal();
            loadPerformanceData();
            loadDashboardData();
        } else {
            showAlert(data.message || 'Error saving performance data', 'error');
        }
    } catch (error) {
        console.error('Error saving performance:', error);
        showAlert('Failed to save performance data', 'error');
    }
}

// Load Performance Data
async function loadPerformanceData() {
    try {
        const response = await fetch(`${API_BASE}/performance`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        const tbody = document.getElementById('performance-table-body');
        
        if (data.success && data.performance) {
            tbody.innerHTML = data.performance.map(perf => `
                <tr>
                    <td>${new Date(perf.date).toLocaleDateString()}</td>
                    <td>${perf.dials}</td>
                    <td>${perf.connects}</td>
                    <td>${perf.appointments}</td>
                    <td>${perf.conversions}</td>
                    <td>${perf.created_by || currentUser}</td>
                    <td class="action-buttons">
                        <button class="action-btn view" onclick="viewPerformance(${perf.id})">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${currentRole === 'admin' || perf.created_by === currentUser ? `
                        <button class="action-btn edit" onclick="editPerformance(${perf.id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete" onclick="deletePerformance(${perf.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No performance data found</td></tr>';
        }
    } catch (error) {
        console.error('Error loading performance data:', error);
    }
}

// Load Users (Admin only)
async function loadUsers() {
    if (currentRole !== 'admin') return;
    
    try {
        const response = await fetch(`${API_BASE}/users`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        const tbody = document.getElementById('users-table-body');
        
        if (data.success && data.users) {
            tbody.innerHTML = data.users.map(user => `
                <tr>
                    <td>${user.username}</td>
                    <td><span class="status-badge ${user.role === 'active' ? 'status-active' : 'status-inactive'}">${user.role.toUpperCase()}</span></td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td class="action-buttons">
                        <button class="action-btn edit" onclick="editUser(${user.id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        ${user.username !== currentUser ? `
                        <button class="action-btn delete" onclick="deleteUser(${user.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No users found</td></tr>';
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

// Save User
async function saveUser(id = null) {
    const username = document.getElementById('user-username').value.trim();
    const role = document.getElementById('user-role').value;
    
    if (!username || !role) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    
    if (!id) {
        // New user
        const password = document.getElementById('user-password').value;
        const confirmPassword = document.getElementById('user-confirm-password').value;
        
        if (!password) {
            showAlert('Password is required for new users', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showAlert('Passwords do not match', 'error');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/users`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, role })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert('User created successfully!', 'success');
                hideModal();
                loadUsers();
            } else {
                showAlert(data.message || 'Error creating user', 'error');
            }
        } catch (error) {
            console.error('Error creating user:', error);
            showAlert('Failed to create user', 'error');
        }
    } else {
        // Edit user
        const newPassword = document.getElementById('user-new-password')?.value;
        const updateData = { role };
        if (newPassword) {
            updateData.password = newPassword;
        }
        
        try {
            const response = await fetch(`${API_BASE}/users/${id}`, {
                method: 'PUT',
                headers: { 
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updateData)
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert('User updated successfully!', 'success');
                hideModal();
                loadUsers();
            } else {
                showAlert(data.message || 'Error updating user', 'error');
            }
        } catch (error) {
            console.error('Error updating user:', error);
            showAlert('Failed to update user', 'error');
        }
    }
}

// Export Performance Data
async function exportPerformanceData() {
    try {
        const response = await fetch(`${API_BASE}/performance/export`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.url) {
            // Create download link
            const link = document.createElement('a');
            link.href = data.url;
            link.download = `sdot-performance-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            showAlert('Performance data exported successfully!', 'success');
        } else {
            showAlert(data.message || 'Error exporting data', 'error');
        }
    } catch (error) {
        console.error('Error exporting performance data:', error);
        showAlert('Failed to export data', 'error');
    }
}

// Helper Functions
function showAlert(message, type = 'info') {
    // Create alert element
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        ${message}
    `;
    
    // Add to top of dashboard
    const dashboard = document.querySelector('.dashboard-content');
    dashboard.insertBefore(alert, dashboard.firstChild);
    
    // Remove after 5 seconds
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

function showLoading() {
    // You can add a loading spinner here
    document.getElementById('login-btn').innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
    document.getElementById('login-btn').disabled = true;
}

function hideLoading() {
    document.getElementById('login-btn').innerHTML = 'Sign In';
    document.getElementById('login-btn').disabled = false;
}

// CRUD Operations for other modules (similar structure)
async function deleteScript(id) {
    if (!confirm('Are you sure you want to delete this script?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/scripts/${id}`, {
            method: 'DELETE',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Script deleted successfully!', 'success');
            loadScripts();
        } else {
            showAlert(data.message || 'Error deleting script', 'error');
        }
    } catch (error) {
        console.error('Error deleting script:', error);
        showAlert('Failed to delete script', 'error');
    }
}

async function deletePerformance(id) {
    if (!confirm('Are you sure you want to delete this performance record?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/performance/${id}`, {
            method: 'DELETE',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Performance record deleted successfully!', 'success');
            loadPerformanceData();
            loadDashboardData();
        } else {
            showAlert(data.message || 'Error deleting performance record', 'error');
        }
    } catch (error) {
        console.error('Error deleting performance:', error);
        showAlert('Failed to delete performance record', 'error');
    }
}

async function deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    
    try {
        const response = await fetch(`${API_BASE}/users/${id}`, {
            method: 'DELETE',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('User deleted successfully!', 'success');
            loadUsers();
        } else {
            showAlert(data.message || 'Error deleting user', 'error');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showAlert('Failed to delete user', 'error');
    }
}

// Load data for editing
async function fetchScriptData(id) {
    try {
        const response = await fetch(`${API_BASE}/scripts/${id}`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.script) {
            document.getElementById('script-title').value = data.script.title;
            document.getElementById('script-content').value = data.script.content;
            document.getElementById('script-persona').value = data.script.persona || '';
        }
    } catch (error) {
        console.error('Error fetching script data:', error);
    }
}

async function fetchPerformanceData(id) {
    try {
        const response = await fetch(`${API_BASE}/performance/${id}`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.performance) {
            document.getElementById('perf-date').value = data.performance.date.split('T')[0];
            document.getElementById('perf-dials').value = data.performance.dials;
            document.getElementById('perf-connects').value = data.performance.connects;
            document.getElementById('perf-appointments').value = data.performance.appointments;
            document.getElementById('perf-conversions').value = data.performance.conversions;
        }
    } catch (error) {
        console.error('Error fetching performance data:', error);
    }
}

async function fetchUserData(id) {
    try {
        const response = await fetch(`${API_BASE}/users/${id}`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.user) {
            document.getElementById('user-username').value = data.user.username;
            document.getElementById('user-role').value = data.user.role;
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
    }
}

// Edit functions
function editScript(id) {
    showAddForm('script', id);
}

function editPerformance(id) {
    showAddForm('performance', id);
}

function editUser(id) {
    showAddForm('user', id);
}

// View functions
async function viewScript(id) {
    try {
        const response = await fetch(`${API_BASE}/scripts/${id}`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.script) {
            const modalTitle = document.getElementById('modal-title');
            const modalBody = document.querySelector('.modal-body');
            const modalSave = document.querySelector('.modal-save');
            
            modalTitle.textContent = 'Script Details';
            modalBody.innerHTML = `
                <div class="form-group">
                    <label>Title</label>
                    <div class="view-field">${data.script.title}</div>
                </div>
                <div class="form-group">
                    <label>Persona</label>
                    <div class="view-field">${data.script.persona || 'N/A'}</div>
                </div>
                <div class="form-group">
                    <label>Content</label>
                    <div class="view-field" style="white-space: pre-wrap; background: #f8fafc; padding: 15px; border-radius: 8px;">${data.script.content}</div>
                </div>
                <div class="form-group">
                    <label>Created By</label>
                    <div class="view-field">${data.script.created_by || 'N/A'}</div>
                </div>
                <div class="form-group">
                    <label>Date Created</label>
                    <div class="view-field">${new Date(data.script.created_at).toLocaleString()}</div>
                </div>
            `;
            
            modalSave.style.display = 'none';
            showModal();
        }
    } catch (error) {
        console.error('Error viewing script:', error);
        showAlert('Failed to load script details', 'error');
    }
}

async function viewPerformance(id) {
    try {
        const response = await fetch(`${API_BASE}/performance/${id}`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.performance) {
            const modalTitle = document.getElementById('modal-title');
            const modalBody = document.querySelector('.modal-body');
            const modalSave = document.querySelector('.modal-save');
            
            modalTitle.textContent = 'Performance Details';
            
            // Calculate rates
            const perf = data.performance;
            const connectRate = perf.dials > 0 ? ((perf.connects / perf.dials) * 100).toFixed(1) : 0;
            const appointmentRate = perf.connects > 0 ? ((perf.appointments / perf.connects) * 100).toFixed(1) : 0;
            const conversionRate = perf.appointments > 0 ? ((perf.conversions / perf.appointments) * 100).toFixed(1) : 0;
            
            modalBody.innerHTML = `
                <div class="form-row">
                    <div class="form-group">
                        <label>Date</label>
                        <div class="view-field">${new Date(perf.date).toLocaleDateString()}</div>
                    </div>
                    <div class="form-group">
                        <label>Created By</label>
                        <div class="view-field">${perf.created_by || 'N/A'}</div>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Dials</label>
                        <div class="view-field">${perf.dials}</div>
                    </div>
                    <div class="form-group">
                        <label>Connects</label>
                        <div class="view-field">${perf.connects}</div>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Appointments</label>
                        <div class="view-field">${perf.appointments}</div>
                    </div>
                    <div class="form-group">
                        <label>Conversions</label>
                        <div class="view-field">${perf.conversions}</div>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Connect Rate</label>
                        <div class="view-field">${connectRate}%</div>
                    </div>
                    <div class="form-group">
                        <label>Appointment Rate</label>
                        <div class="view-field">${appointmentRate}%</div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Conversion Rate</label>
                    <div class="view-field">${conversionRate}%</div>
                </div>
            `;
            
            modalSave.style.display = 'none';
            showModal();
        }
    } catch (error) {
        console.error('Error viewing performance:', error);
        showAlert('Failed to load performance details', 'error');
    }
}

// Add view field style
const style = document.createElement('style');
style.textContent = `
    .view-field {
        padding: 10px 15px;
        background: #f8fafc;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        margin-top: 5px;
    }
`;
document.head.appendChild(style);

// Load Objections
async function loadObjections() {
    try {
        const response = await fetch(`${API_BASE}/objections`, {
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        const tbody = document.getElementById('objections-table-body');
        
        if (data.success && data.objections) {
            tbody.innerHTML = data.objections.map(obj => `
                <tr>
                    <td>${obj.objection}</td>
                    <td>${obj.response.substring(0, 100)}${obj.response.length > 100 ? '...' : ''}</td>
                    <td>${obj.created_by || currentUser}</td>
                    <td>${new Date(obj.created_at).toLocaleDateString()}</td>
                    <td class="action-buttons">
                        <button class="action-btn view" onclick="viewObjection(${obj.id})">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${currentRole === 'admin' || obj.created_by === currentUser ? `
                        <button class="action-btn edit" onclick="editObjection(${obj.id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete" onclick="deleteObjection(${obj.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No objections found</td></tr>';
        }
    } catch (error) {
        console.error('Error loading objections:', error);
    }
}