const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key', // Replace with your actual secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// SQLite Database
const db = new sqlite3.Database('./medical_login.db', (err) => {
    if (err) {
        console.error('Could not connect to the database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// Route for root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html')); // Serve the login page
});

// Create a login route
app.post('/login', async (req, res) => {
    const { user_id, user_pass, fingerprint } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [user_id], async (err, row) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error.' });
        }
        if (!row) {
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

        // Check password
        const match = await bcrypt.compare(user_pass, row.password);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

        // Check fingerprint
        const fingerprintMatch = await bcrypt.compare(fingerprint, row.fingerprint_hex);
        if (!fingerprintMatch) {
            return res.status(401).json({ success: false, message: 'Invalid fingerprint.' });
        }

        // If all checks pass
        req.session.user = row; // Store user session
        res.json({ success: true, message: 'Login successful!' });
    });
});

// Serve dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/'); // Redirect to login if not authenticated
    }
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Insert user function (for adding new users with hashed passwords and fingerprints)
async function insertUser(username, password, fingerprintHex) {
    const saltRounds = 10; // Adjust the cost factor as necessary
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const hashedFingerprint = await bcrypt.hash(fingerprintHex, saltRounds); // Hashing the fingerprint

    db.run(`INSERT INTO users (username, password, fingerprint_hex) VALUES (?, ?, ?)`,
        [username, hashedPassword, hashedFingerprint], 
        function(err) {
            if (err) {
                return console.error(err.message);
            }
            console.log(`A row has been inserted with rowid ${this.lastID}`);
        });
}

// Example of inserting users (uncomment to add users if not already in the database)
// (async () => {
//     await insertUser('Kousi1', 'Medlogin1', 'a1b2c3d4e5f67890');
//     await insertUser('Kousi2', 'Medlogin2', 'f1e2d3c4b5a67890');
//     await insertUser('Kousi3', 'Medlogin3', 'c3d4e5f6a1b27890');
//     await insertUser('Kousi4', 'Medlogin4', 'b5a6c3d4f1e27890');
//     await insertUser('Kousi5', 'Medlogin5', 'd4e5f6a1c3b27890');
// })();

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
