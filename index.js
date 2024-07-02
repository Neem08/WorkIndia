const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ status: "No token provided", status_code: 403 });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ status: "Unauthorized", status_code: 401 });
        req.userId = decoded.user_id;
        next();
    });
};

const verifyAdminApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== ADMIN_API_KEY) {
        return res.status(403).json({ status: "Invalid API key", status_code: 403 });
    }
    next();
};

// 1. Register a User
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ 
            status: "Missing required fields", 
            status_code: 400 
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        await connection.end();

        res.status(200).json({
            status: "Account successfully created",
            status_code: 200,
            user_id: result.insertId
        });
    } catch (error) {
        console.error('Error in signup:', error);
        res.status(500).json({ status: "Error creating account", status_code: 500, error: error.message });
    }
});

// 2. Login User
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        await connection.end();

        if (rows.length === 0) {
            return res.status(401).json({ status: "Incorrect username/password provided. Please retry", status_code: 401 });
        }

        const user = rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (isPasswordValid) {
            const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({
                status: "Login successful",
                status_code: 200,
                user_id: user.user_id,
                access_token: token
            });
        } else {
            res.status(401).json({ status: "Incorrect username/password provided. Please retry", status_code: 401 });
        }
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).json({ status: "Error logging in", status_code: 500, error: error.message });
    }
});

// 3. Add a new news/article/post (Admin only)
app.post('/api/shorts/create', verifyAdminApiKey, async (req, res) => {
    const { category, title, author, publish_date, content, actual_content_link, image } = req.body;

    try {
        const connection = await mysql.createConnection(dbConfig);
        const [result] = await connection.execute(
            'INSERT INTO shorts (category, title, author, publish_date, content, actual_content_link, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [category, title, author, publish_date, content, actual_content_link, image]
        );
        await connection.end();

        res.status(200).json({
            message: "Short added successfully",
            short_id: result.insertId,
            status_code: 200
        });
    } catch (error) {
        console.error('Error creating short:', error);
        res.status(500).json({ status: "Error creating short", status_code: 500, error: error.message });
    }
});

// 4. Get shorts-feed for any user
app.get('/api/shorts/feed', async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(
            'SELECT * FROM shorts ORDER BY publish_date DESC, upvote DESC'
        );
        await connection.end();

        res.status(200).json(rows);
    } catch (error) {
        console.error('Error fetching feed:', error);
        res.status(500).json({ status: "Error fetching feed", status_code: 500, error: error.message });
    }
});

// 5. Get user feed based on filters and random text searches
app.get('/api/shorts/filter', verifyToken, async (req, res) => {
    const { category, publish_date, upvote, title, keyword, author } = req.query;

    let query = 'SELECT * FROM shorts WHERE 1=1';
    const params = [];

    if (category) {
        query += ' AND category = ?';
        params.push(category);
    }
    if (publish_date) {
        query += ' AND publish_date >= ?';
        params.push(publish_date);
    }
    if (upvote) {
        query += ' AND upvote > ?';
        params.push(parseInt(upvote));
    }
    if (title) {
        query += ' AND title LIKE ?';
        params.push(`%${title}%`);
    }
    if (keyword) {
        query += ' AND (title LIKE ? OR content LIKE ?)';
        params.push(`%${keyword}%`, `%${keyword}%`);
    }
    if (author) {
        query += ' AND author LIKE ?';
        params.push(`%${author}%`);
    }

    query += ' ORDER BY publish_date DESC, upvote DESC';

    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(query, params);
        await connection.end();

        res.status(200).json(rows);
    } catch (error) {
        console.error('Error filtering shorts:', error);
        res.status(500).json({ status: "Error filtering shorts", status_code: 500, error: error.message });
    }
});

app.get('/', (req, res) => {
    res.send('Hello');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
