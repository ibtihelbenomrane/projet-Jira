const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Configuration de la base de données
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'notification_app', // Assurez-vous que la base de données s'appelle "notification_app"
});

// Connexion à la base de données
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL Database:', err);
        return;
    }
    console.log('Connected to MySQL Database.');
});

// Route d'enregistrement
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    console.log('Received registration data:', req.body); // Afficher les données reçues

    // Vérification si l'utilisateur existe déjà
    db.query('SELECT * FROM register WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);  // Log si erreur de requête
            return res.status(500).json({ error: 'Database query error' });
        }
        if (results.length > 0) {
            console.log('User already exists');
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hachage du mot de passe
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Hashing error:', err);
                return res.status(500).json({ error: 'Error hashing password' });
            }

            // Insertion de l'utilisateur dans la base de données
            db.query('INSERT INTO register (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err) => {
                if (err) {
                    console.error('Database insertion error:', err);
                    return res.status(500).json({ error: 'Database insertion error' });
                }
                console.log('User registered successfully');
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    });
});


// Route de connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM register WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database query error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ error: 'Error comparing passwords' });
            }

            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Ajoutez éventuellement un token JWT ici si nécessaire
            res.json({ message: 'Login successful' });
        });
    });
});




app.get('/notifications/:studentId', (req, res) => {
    const { studentId } = req.params;
    db.query(
        'SELECT * FROM notifications WHERE student_id = ?',
        [studentId],
        (err, results) => {
            if (err) return res.status(500).json({ error: 'Database query error' });
            res.json(results);
        }
    );
});


app.post('/notifications', (req, res) => {
    const { title, message, student_id } = req.body;
    db.query(
        'INSERT INTO notifications (title, message, student_id) VALUES (?, ?, ?)',
        [title, message, student_id],
        (err) => {
            if (err) return res.status(500).json({ error: 'Database insertion error' });
            res.status(201).json({ message: 'Notification created' });
        }
    );
});




// Démarrage du serveur
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

