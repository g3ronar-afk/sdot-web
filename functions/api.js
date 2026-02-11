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
        console.log('Default admin created: admin / admin123');
    }

    return db;
}

// Initialize database
initDB().catch(console.error);

// JWT Secret - FALLBACK FOR NON-SECRET ENV VAR
const JWT_SECRET = process.env.JWT_SECRET || 'sdot-production-secret-key-2024-change-this-in-production';

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
    // Add CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight OPTIONS request
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    const path = event.path.replace('/.netlify/functions/api', '');
    const method = event.httpMethod;
    
    try {
        // Ensure DB is initialized
        if (!db) {
            db = await initDB();
        }

        // Routes
        if (path === '/login' && method === 'POST') {
            return await handleLogin(event, headers);
        }
        
        if (path === '/dashboard' && method === 'GET') {
            return await handleDashboard(event, headers);
        }
        
        if (path === '/scripts') {
            if (method === 'GET') return await getScripts(event, headers);
            if (method === 'POST') return await createScript(event, headers);
        }
        
        if (path.startsWith('/scripts/')) {
            const id = path.split('/')[2];
            if (method === 'GET') return await getScript(id, event, headers);
            if (method === 'PUT') return await updateScript(id, event, headers);
            if (method === 'DELETE') return await deleteScript(id, event, headers);
        }
        
        if (path === '/performance') {
            if (method === 'GET') return await getPerformance(event, headers);
            if (method === 'POST') return await createPerformance(event, headers);
        }
        
        if (path === '/performance/check-date' && method === 'GET') {
            return await checkPerformanceDate(event, headers);
        }
        
        if (path === '/performance/export' && method === 'GET') {
            return await exportPerformance(event, headers);
        }
        
        if (path.startsWith('/performance/')) {
            const id = path.split('/')[2];
            if (method === 'GET') return await getPerformanceById(id, event, headers);
            if (method === 'PUT') return await updatePerformance(id, event, headers);
            if (method === 'DELETE') return await deletePerformance(id, event, headers);
        }
        
        if (path === '/users' && method === 'GET') {
            return await getUsers(event, headers);
        }
        
        if (path === '/users' && method === 'POST') {
            return await createUser(event, headers);
        }
        
        if (path.startsWith('/users/')) {
            const id = path.split('/')[2];
            if (method === 'GET') return await getUser(id, event, headers);
            if (method === 'PUT') return await updateUser(id, event, headers);
            if (method === 'DELETE') return await deleteUser(id, event, headers);
        }
        
        if (path === '/objections' && method === 'GET') {
            return await getObjections(event, headers);
        }
        
        return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ success: false, message: 'Endpoint not found' })
        };
        
    } catch (error) {
        console.error('API Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                success: false, 
                message: 'Internal server error',
                error: error.message 
            })
        };
    }
};

// Login Handler
async function handleLogin(event, headers) {
    try {
        const { username, password } = JSON.parse(event.body);
        
        if (!username || !password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Username and password required' })
            };
        }
        
        const user = await db.get("SELECT * FROM users WHERE username = ? AND is_active = 1", username);
        
        if (!user) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'Invalid credentials' })
            };
        }
        
        const validPassword = await verifyPassword(password, user.password_hash);
        
        if (!validPassword) {
            return {
                statusCode: 401,
                headers,
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
            headers,
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
    } catch (error) {
        console.error('Login error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Login failed' })
        };
    }
}

// Dashboard Handler
async function handleDashboard(event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
        // Get performance summary
        let summaryQuery;
        let summaryParams;
        
        if (user.role === 'admin') {
            summaryQuery = `
                SELECT 
                    COALESCE(SUM(dials), 0) as total_dials,
                    COALESCE(SUM(connects), 0) as total_connects,
                    COALESCE(SUM(appointments), 0) as total_appointments,
                    COALESCE(SUM(conversions), 0) as total_conversions,
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
                    COALESCE(SUM(dials), 0) as total_dials,
                    COALESCE(SUM(connects), 0) as total_connects,
                    COALESCE(SUM(appointments), 0) as total_appointments,
                    COALESCE(SUM(conversions), 0) as total_conversions,
                    COUNT(*) as total_entries
                FROM performance 
                WHERE user_id IN (${placeholders})
            `;
            summaryParams = allIds;
        } else {
            summaryQuery = `
                SELECT 
                    COALESCE(SUM(dials), 0) as total_dials,
                    COALESCE(SUM(connects), 0) as total_connects,
                    COALESCE(SUM(appointments), 0) as total_appointments,
                    COALESCE(SUM(conversions), 0) as total_conversions,
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
            headers,
            body: JSON.stringify({
                success: true,
                summary: summary || { 
                    total_dials: 0, 
                    total_connects: 0, 
                    total_appointments: 0, 
                    total_conversions: 0,
                    total_entries: 0
                },
                performance: performance || []
            })
        };
    } catch (error) {
        console.error('Dashboard error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load dashboard' })
        };
    }
}

// Scripts Handlers
async function getScripts(event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
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
            headers,
            body: JSON.stringify({ success: true, scripts })
        };
    } catch (error) {
        console.error('Get scripts error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load scripts' })
        };
    }
}

async function createScript(event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { title, content, persona } = JSON.parse(event.body);
        
        if (!title || !content) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Title and content are required' })
            };
        }
        
        const result = await db.run(
            "INSERT INTO scripts (title, content, persona, user_id, created_by) VALUES (?, ?, ?, ?, ?)",
            [title, content, persona || null, user.id, user.username]
        );
        
        return {
            statusCode: 201,
            headers,
            body: JSON.stringify({ success: true, id: result.lastID })
        };
    } catch (error) {
        console.error('Create script error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to create script' })
        };
    }
}

async function getScript(id, event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
        const script = await db.get(
            `SELECT s.*, u.username as created_by 
             FROM scripts s
             LEFT JOIN users u ON s.user_id = u.id
             WHERE s.id = ?`,
            id
        );
        
        if (!script) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Script not found' })
            };
        }
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, script })
        };
    } catch (error) {
        console.error('Get script error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load script' })
        };
    }
}

async function updateScript(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { title, content, persona } = JSON.parse(event.body);
        
        const script = await db.get("SELECT * FROM scripts WHERE id = ?", id);
        if (!script) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Script not found' })
            };
        }
        
        if (user.role !== 'admin' && script.user_id !== user.id) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ success: false, message: 'Cannot edit others scripts' })
            };
        }
        
        await db.run(
            "UPDATE scripts SET title = ?, content = ?, persona = ? WHERE id = ?",
            [title, content, persona || null, id]
        );
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Update script error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to update script' })
        };
    }
}

async function deleteScript(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const script = await db.get("SELECT * FROM scripts WHERE id = ?", id);
        if (!script) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Script not found' })
            };
        }
        
        if (user.role !== 'admin' && script.user_id !== user.id) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ success: false, message: 'Cannot delete others scripts' })
            };
        }
        
        await db.run("DELETE FROM scripts WHERE id = ?", id);
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Delete script error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to delete script' })
        };
    }
}

// Performance Handlers
async function getPerformance(event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
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
            headers,
            body: JSON.stringify({ success: true, performance })
        };
    } catch (error) {
        console.error('Get performance error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load performance data' })
        };
    }
}

async function createPerformance(event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { date, dials, connects, appointments, conversions } = JSON.parse(event.body);
        
        if (!date || dials === undefined || connects === undefined || appointments === undefined || conversions === undefined) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'All fields are required' })
            };
        }
        
        // Validate business rules
        if (parseInt(connects) > parseInt(dials)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Connects cannot exceed Dials' })
            };
        }
        
        if (parseInt(appointments) > parseInt(connects)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Appointments cannot exceed Connects' })
            };
        }
        
        if (parseInt(conversions) > parseInt(appointments)) {
            return {
                statusCode: 400,
                headers,
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
                headers,
                body: JSON.stringify({ success: true, id: result.lastID })
            };
        } catch (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ success: false, message: 'Performance data already exists for this date' })
                };
            }
            throw error;
        }
    } catch (error) {
        console.error('Create performance error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to create performance record' })
        };
    }
}

async function checkPerformanceDate(event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
        const { date } = event.queryStringParameters || {};
        
        if (!date) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Date is required' })
            };
        }
        
        const existing = await db.get(
            "SELECT id FROM performance WHERE date = ? AND user_id = ?",
            [date, user.id]
        );
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, exists: !!existing })
        };
    } catch (error) {
        console.error('Check date error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to check date' })
        };
    }
}

async function exportPerformance(event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'client'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
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
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                data: performance
            })
        };
    } catch (error) {
        console.error('Export error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to export data' })
        };
    }
}

async function getPerformanceById(id, event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
        const performance = await db.get(
            `SELECT p.*, u.username as created_by 
             FROM performance p
             LEFT JOIN users u ON p.user_id = u.id
             WHERE p.id = ?`,
            id
        );
        
        if (!performance) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Performance record not found' })
            };
        }
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, performance })
        };
    } catch (error) {
        console.error('Get performance by id error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load performance record' })
        };
    }
}

async function updatePerformance(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { date, dials, connects, appointments, conversions } = JSON.parse(event.body);
        
        const perf = await db.get("SELECT * FROM performance WHERE id = ?", id);
        if (!perf) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Performance record not found' })
            };
        }
        
        if (user.role !== 'admin' && perf.user_id !== user.id) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ success: false, message: 'Cannot edit others records' })
            };
        }
        
        await db.run(
            "UPDATE performance SET date = ?, dials = ?, connects = ?, appointments = ?, conversions = ? WHERE id = ?",
            [date, dials, connects, appointments, conversions, id]
        );
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Update performance error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to update performance record' })
        };
    }
}

async function deletePerformance(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || !['admin', 'va'].includes(user.role)) {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const perf = await db.get("SELECT * FROM performance WHERE id = ?", id);
        if (!perf) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'Performance record not found' })
            };
        }
        
        if (user.role !== 'admin' && perf.user_id !== user.id) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ success: false, message: 'Cannot delete others records' })
            };
        }
        
        await db.run("DELETE FROM performance WHERE id = ?", id);
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Delete performance error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to delete performance record' })
        };
    }
}

// Users Handlers (Admin only)
async function getUsers(event, headers) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const users = await db.all(`
            SELECT id, username, role, created_at, is_active 
            FROM users 
            ORDER BY created_at DESC
        `);
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, users })
        };
    } catch (error) {
        console.error('Get users error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load users' })
        };
    }
}

async function createUser(event, headers) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { username, password, role } = JSON.parse(event.body);
        
        if (!username || !password || !role) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Username, password and role are required' })
            };
        }
        
        if (!['admin', 'client', 'va'].includes(role)) {
            return {
                statusCode: 400,
                headers,
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
                headers,
                body: JSON.stringify({ success: true, id: result.lastID })
            };
        } catch (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ success: false, message: 'Username already exists' })
                };
            }
            throw error;
        }
    } catch (error) {
        console.error('Create user error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to create user' })
        };
    }
}

async function getUser(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const userData = await db.get(
            "SELECT id, username, role, created_at, is_active FROM users WHERE id = ?",
            id
        );
        
        if (!userData) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'User not found' })
            };
        }
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, user: userData })
        };
    } catch (error) {
        console.error('Get user error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load user' })
        };
    }
}

async function updateUser(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        const { role, password } = JSON.parse(event.body);
        
        if (role && !['admin', 'client', 'va'].includes(role)) {
            return {
                statusCode: 400,
                headers,
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
                headers,
                body: JSON.stringify({ success: false, message: 'No fields to update' })
            };
        }
        
        query += updates.join(', ') + " WHERE id = ?";
        params.push(id);
        
        await db.run(query, params);
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Update user error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to update user' })
        };
    }
}

async function deleteUser(id, event, headers) {
    const user = authenticateToken(event);
    if (!user || user.role !== 'admin') {
        return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ success: false, message: 'Forbidden' })
        };
    }
    
    try {
        // Don't allow deleting yourself
        if (parseInt(id) === user.id) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Cannot delete your own account' })
            };
        }
        
        await db.run("DELETE FROM users WHERE id = ?", id);
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
        };
    } catch (error) {
        console.error('Delete user error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to delete user' })
        };
    }
}

// Objections Handlers
async function getObjections(event, headers) {
    const user = authenticateToken(event);
    if (!user) {
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ success: false, message: 'Unauthorized' })
        };
    }
    
    try {
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
            headers,
            body: JSON.stringify({ success: true, objections })
        };
    } catch (error) {
        console.error('Get objections error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to load objections' })
        };
    }
}