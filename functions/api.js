const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Database setup
let db;

async function initDB() {
    db = await open({
        filename: './data/sdot.db',
        driver: sqlite3.Database
    });

    // Create tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin','client','va')) NOT NULL DEFAULT 'va',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            persona TEXT,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS objections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            objection TEXT NOT NULL,
            response TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE NOT NULL,
            dials INTEGER NOT NULL DEFAULT 0,
            connects INTEGER NOT NULL DEFAULT 0,
            appointments INTEGER NOT NULL DEFAULT 0,
            conversions INTEGER NOT NULL DEFAULT 0,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(date, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS cadence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            due_date DATE NOT NULL,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS compliance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            notes TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `);

    // Create default admin if not exists
    const adminExists = await db.get("SELECT id FROM users WHERE username = 'admin'");
    if (!adminExists) {
        const passwordHash = await bcrypt.hash('admin123', 10);
        await db.run(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ['admin', passwordHash, 'admin']
        );
    }

    return db;
}

// Initialize database
initDB();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'sdot-secret-key-change-in-production';

// Helper functions
function authenticateToken(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;
    
    const token = authHeader.split(' ')[1];
    if (!token) return null;
    
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Main handler
exports.handler = async function(event, context) {
    const path = event.path.replace('/.netlify/functions/api', '');
    const method = event.httpMethod;
    
    try {
        // Routes
        if (path === '/login' && method === 'POST') {
            return await handleLogin(event);
        }
        
        if (path === '/dashboard' && method === 'GET') {
            return await handleDashboard(event);
        }
        
        if (path === '/scripts') {
            if (method === 'GET') return await getScripts(event);
            if (method === 'POST') return await createScript(event);
        }
        
        if (path.startsWith('/scripts/')) {
            const id = path.split('/')[1];
            if (method === 'GET') return await getScript(id, event);
            if (method === 'PUT') return await updateScript(id, event);
            if (method === 'DELETE') return await deleteScript(id, event);
        }
        
        if (path === '/performance') {
            if (method === 'GET') return await getPerformance(event);
            if (method === 'POST') return await createPerformance(event);
        }
        
        if (path === '/performance/check-date' && method === 'GET') {
            return await checkPerformanceDate(event);
        }
        
        if (path === '/performance/export' && method === 'GET') {
            return await exportPerformance(event);
        }
        
        if (path.startsWith('/performance/')) {
            const id = path.split('/')[1];
            if (method === 'GET') return await getPerformanceById(id, event);
            if (method === 'PUT') return await updatePerformance(id, event);
            if (method === 'DELETE') return await deletePerformance(id, event);
        }
        
        if (path === '/users' && method === 'GET') {
            return await getUsers(event);
        }
        
        if (path === '/users' && method === 'POST') {
            return await createUser(event);
        }
        
        if (path.startsWith('/users/')) {
            const id = path.split('/')[1];
            if (method === 'GET') return await getUser(id, event);
            if (method === 'PUT') return await updateUser(id, event);
            if (method === 'DELETE') return await deleteUser(id, event);
        }
        
        if (path === '/objections' && method === 'GET') {
            return await getObjections(event);
        }
        
        return {
            statusCode: 404,
            body: JSON.stringify({ success: false, message: 'Not found' })
        };
        
    } catch (error) {
        console.error('API Error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ success: false, message: 'Internal server error' })
        };
    }
};

// Login Handler
async function handleLogin(event) {
    const { username, password } = JSON.parse(event.body);
    
    if (!username || !password) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Username and password required' })
        };
    }
    
    const user = await db.get("SELECT * FROM users WHERE username = ? AND is_active = 1", username);
    
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Invalid credentials' })
        };
    }
    
    const validPassword = await verifyPassword(password, user.password_hash);
    
    if (!validPassword) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Invalid credentials' })
        };
    }
    
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
    
    return {
        statusCode: 200,
        body: JSON.stringify({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        })
    };
}

// Dashboard Handler
async function handleDashboard(event) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    // Get performance summary
    let summaryQuery;
    let summaryParams;
    
    if (user.role === 'admin') {
        summaryQuery = `
            SELECT 
                SUM(dials) as total_dials,
                SUM(connects) as total_connects,
                SUM(appointments) as total_appointments,
                SUM(conversions) as total_conversions,
                COUNT(*) as total_entries
            FROM performance
        `;
        summaryParams = [];
    } else if (user.role === 'client') {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        summaryQuery = `
            SELECT 
                SUM(dials) as total_dials,
                SUM(connects) as total_connects,
                SUM(appointments) as total_appointments,
                SUM(conversions) as total_conversions,
                COUNT(*) as total_entries
            FROM performance 
            WHERE user_id IN (${placeholders})
        `;
        summaryParams = allIds;
    } else {
        summaryQuery = `
            SELECT 
                SUM(dials) as total_dials,
                SUM(connects) as total_connects,
                SUM(appointments) as total_appointments,
                SUM(conversions) as total_conversions,
                COUNT(*) as total_entries
            FROM performance 
            WHERE user_id = ?
        `;
        summaryParams = [user.id];
    }
    
    const summary = await db.get(summaryQuery, summaryParams);
    
    // Get performance data for charts
    let perfQuery;
    let perfParams;
    
    if (user.role === 'admin') {
        perfQuery = "SELECT * FROM performance ORDER BY date DESC LIMIT 30";
        perfParams = [];
    } else if (user.role === 'client') {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        perfQuery = `SELECT * FROM performance WHERE user_id IN (${placeholders}) ORDER BY date DESC LIMIT 30`;
        perfParams = allIds;
    } else {
        perfQuery = "SELECT * FROM performance WHERE user_id = ? ORDER BY date DESC LIMIT 30";
        perfParams = [user.id];
    }
    
    const performance = await db.all(perfQuery, perfParams);
    
    return {
        statusCode: 200,
        body: JSON.stringify({
            success: true,
            summary: summary || { total_dials: 0, total_connects: 0, total_appointments: 0, total_conversions: 0 },
            performance: performance || []
        })
    };
}

// Scripts Handlers
async function getScripts(event) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    let query;
    let params;
    
    if (user.role === 'admin') {
        query = `
            SELECT s.*, u.username as created_by 
            FROM scripts s
            LEFT JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        `;
        params = [];
    } else if (user.role === 'client') {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        query = `
            SELECT s.*, u.username as created_by 
            FROM scripts s
            LEFT JOIN users u ON s.user_id = u.id
            WHERE s.user_id IN (${placeholders})
            ORDER BY s.created_at DESC
        `;
        params = allIds;
    } else {
        query = `
            SELECT s.*, u.username as created_by 
            FROM scripts s
            LEFT JOIN users u ON s.user_id = u.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
        `;
        params = [user.id];
    }
    
    const scripts = await db.all(query, params);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true, scripts })
    };
}

async function createScript(event) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    const { title, content, persona } = JSON.parse(event.body);
    
    if (!title || !content) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Title and content are required' })
        };
    }
    
    const result = await db.run(
        "INSERT INTO scripts (title, content, persona, user_id, created_by) VALUES (?, ?, ?, ?, ?)",
        [title, content, persona || null, user.id, user.username]
    );
    
    return {
        statusCode: 201,
        body: JSON.stringify({ success: true, id: result.lastID })
    };
}

// Performance Handlers
async function getPerformance(event) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    let query;
    let params;
    
    if (user.role === 'admin') {
        query = `
            SELECT p.*, u.username as created_by 
            FROM performance p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.date DESC
        `;
        params = [];
    } else if (user.role === 'client') {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        query = `
            SELECT p.*, u.username as created_by 
            FROM performance p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.user_id IN (${placeholders})
            ORDER BY p.date DESC
        `;
        params = allIds;
    } else {
        query = `
            SELECT p.*, u.username as created_by 
            FROM performance p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.user_id = ?
            ORDER BY p.date DESC
        `;
        params = [user.id];
    }
    
    const performance = await db.all(query, params);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true, performance })
    };
}

async function createPerformance(event) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    const { date, dials, connects, appointments, conversions } = JSON.parse(event.body);
    
    if (!date || dials === undefined || connects === undefined || appointments === undefined || conversions === undefined) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'All fields are required' })
        };
    }
    
    // Validate business rules
    if (parseInt(connects) > parseInt(dials)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Connects cannot exceed Dials' })
        };
    }
    
    if (parseInt(appointments) > parseInt(connects)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Appointments cannot exceed Connects' })
        };
    }
    
    if (parseInt(conversions) > parseInt(appointments)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Conversions cannot exceed Appointments' })
        };
    }
    
    try {
        const result = await db.run(
            "INSERT INTO performance (date, dials, connects, appointments, conversions, user_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [date, dials, connects, appointments, conversions, user.id, user.username]
        );
        
        return {
            statusCode: 201,
            body: JSON.stringify({ success: true, id: result.lastID })
        };
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return {
                statusCode: 400,
                body: JSON.stringify({ success: false, message: 'Performance data already exists for this date' })
            };
        }
        throw error;
    }
}

async function checkPerformanceDate(event) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    const { date } = event.queryStringParameters || {};
    
    if (!date) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Date is required' })
        };
    }
    
    const existing = await db.get(
        "SELECT id FROM performance WHERE date = ? AND user_id = ?",
        [date, user.id]
    );
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true, exists: !!existing })
    };
}

async function exportPerformance(event) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'client'].includes(user.role)) {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    let query;
    let params;
    
    if (user.role === 'admin') {
        query = `
            SELECT p.*, u.username 
            FROM performance p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.date DESC
        `;
        params = [];
    } else {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        query = `
            SELECT p.*, u.username 
            FROM performance p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.user_id IN (${placeholders})
            ORDER BY p.date DESC
        `;
        params = allIds;
    }
    
    const performance = await db.all(query, params);
    
    // In a real implementation, you'd generate a CSV file and upload to cloud storage
    // For now, we'll return a mock URL
    return {
        statusCode: 200,
        body: JSON.stringify({
            success: true,
            url: '/exports/performance.csv',
            data: performance
        })
    };
}

// Users Handlers (Admin only)
async function getUsers(event) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    const users = await db.all(`
        SELECT id, username, role, created_at, is_active 
        FROM users 
        ORDER BY created_at DESC
    `);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true, users })
    };
}

async function createUser(event) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    const { username, password, role } = JSON.parse(event.body);
    
    if (!username || !password || !role) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Username, password and role are required' })
        };
    }
    
    if (!['admin', 'client', 'va'].includes(role)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Invalid role' })
        };
    }
    
    try {
        const passwordHash = await hashPassword(password);
        const result = await db.run(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            [username, passwordHash, role]
        );
        
        return {
            statusCode: 201,
            body: JSON.stringify({ success: true, id: result.lastID })
        };
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return {
                statusCode: 400,
                body: JSON.stringify({ success: false, message: 'Username already exists' })
            };
        }
        throw error;
    }
}

async function updateUser(id, event) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    const { role, password } = JSON.parse(event.body);
    
    if (role && !['admin', 'client', 'va'].includes(role)) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Invalid role' })
        };
    }
    
    let query = "UPDATE users SET ";
    const updates = [];
    const params = [];
    
    if (role) {
        updates.push("role = ?");
        params.push(role);
    }
    
    if (password) {
        const passwordHash = await hashPassword(password);
        updates.push("password_hash = ?");
        params.push(passwordHash);
    }
    
    if (updates.length === 0) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'No fields to update' })
        };
    }
    
    query += updates.join(', ') + " WHERE id = ?";
    params.push(id);
    
    await db.run(query, params);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true })
    };
}

async function deleteUser(id, event) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    // Don't allow deleting yourself
    if (parseInt(id) === user.id) {
        return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: 'Cannot delete your own account' })
        };
    }
    
    await db.run("DELETE FROM users WHERE id = ?", id);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true })
    };
}

// Objections Handlers
async function getObjections(event) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    let query;
    let params;
    
    if (user.role === 'admin') {
        query = `
            SELECT o.*, u.username as created_by 
            FROM objections o
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
        `;
        params = [];
    } else if (user.role === 'client') {
        const vaUsers = await db.all("SELECT id FROM users WHERE role = 'va'");
        const vaIds = vaUsers.map(u => u.id);
        const allIds = [user.id, ...vaIds];
        
        const placeholders = allIds.map(() => '?').join(',');
        query = `
            SELECT o.*, u.username as created_by 
            FROM objections o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE o.user_id IN (${placeholders})
            ORDER BY o.created_at DESC
        `;
        params = allIds;
    } else {
        query = `
            SELECT o.*, u.username as created_by 
            FROM objections o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC
        `;
        params = [user.id];
    }
    
    const objections = await db.all(query, params);
    
    return {
        statusCode: 200,
        body: JSON.stringify({ success: true, objections })
    };
}