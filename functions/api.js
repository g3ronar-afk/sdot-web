const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

// ===========================================
// DATABASE PATH CONFIGURATION - CRITICAL FOR NETLIFY
// ===========================================
// On Netlify: Use /tmp/sdot.db (writable temporary storage)
// On Local: Use ./data/sdot.db (local development)
const DB_PATH = process.env.NETLIFY 
    ? '/tmp/sdot.db' 
    : path.join(__dirname, '..', 'data', 'sdot.db');

// JWT Secret - Fallback for development
const JWT_SECRET = process.env.JWT_SECRET || 'sdot-production-secret-key-2024-change-this-in-production';

// ===========================================
// DATABASE SEEDING - CREATES DEFAULT ADMIN
// ===========================================
async function seedDatabase(db) {
    try {
        // Check if any user exists
        const userCount = await db.get("SELECT COUNT(*) as count FROM users");
        if (userCount.count === 0) {
            console.log("🌱 Seeding database: No users found. Creating default admin...");
            const passwordHash = await bcrypt.hash('admin123', 10);
            await db.run(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ['admin', passwordHash, 'admin']
            );
            console.log("✅ Default admin created: admin / admin123");
        } else {
            console.log("✅ Users exist, skipping seed.");
        }
    } catch (error) {
        console.error("❌ Seeding error:", error);
    }
}

// ===========================================
// DATABASE INITIALIZATION - WITH DB_PATH
// ===========================================
let db;

async function initDB() {
    try {
        // Ensure the directory exists for local development
        if (!process.env.NETLIFY) {
            const dir = path.join(__dirname, '..', 'data');
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
                console.log(`📁 Created database directory: ${dir}`);
            }
        }

        // Open database connection using DB_PATH
        db = await open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        console.log(`💾 Connected to database at: ${DB_PATH}`);

        // ===========================================
        // CREATE ALL TABLES
        // ===========================================
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

        console.log('✅ Database tables created/verified');

        // Seed the database with default admin user
        await seedDatabase(db);

        return db;
    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
}

// Initialize database immediately
initDB().catch(console.error);

// ===========================================
// HELPER FUNCTIONS
// ===========================================
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

// ===========================================
// MAIN HANDLER
// ===========================================
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

        // ===========================================
        // ROUTES
        // ===========================================
        
        // AUTH
        if (path === '/login' && method === 'POST') {
            return await handleLogin(event, headers);
        }
        
        // DASHBOARD
        if (path === '/dashboard' && method === 'GET') {
            return await handleDashboard(event, headers);
        }
        
        // SCRIPTS
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
        
        // PERFORMANCE
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
        
        // USERS (Admin only)
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
        
        // OBJECTIONS
        if (path === '/objections' && method === 'GET') {
            return await getObjections(event, headers);
        }
        
        // 404
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

// ===========================================
// HANDLER FUNCTIONS
// ===========================================

// LOGIN HANDLER
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

// DASHBOARD HANDLER
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

// ===========================================
// ADD THE REST OF YOUR HANDLER FUNCTIONS HERE
// (getScripts, createScript, getPerformance, etc.)
// ===========================================
// Keep all your existing handler functions below this line
// getScripts, createScript, getScript, updateScript, deleteScript,
// getPerformance, createPerformance, checkPerformanceDate, exportPerformance,
// getPerformanceById, updatePerformance, deletePerformance,
// getUsers, createUser, getUser, updateUser, deleteUser,
// getObjections, etc.