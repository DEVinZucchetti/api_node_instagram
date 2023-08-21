

const fs = require('fs');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = 'suaChaveSecreta'; // Troque para uma chave mais segura em um ambiente de produção
const dbFile = 'db.sqlite';



// Verifica se o arquivo do banco de dados existe, caso contrário, cria-o
if (!fs.existsSync(dbFile)) {
    const db = new sqlite3.Database(dbFile);

    // Cria a tabela de usuários
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            contact TEXT NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            sponsor TEXT,
            confirm_terms BOOL,
            plan_type TEXT
        )`);

        // Cria a tabela de posts
        db.run(`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            url TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);
    });

    db.close((err) => {
        if (err) {
            return console.error('Error closing the database:', err.message);
        }
        console.log('Database created successfully.');
    });
}

// Conexão com o banco de dados
const db = new sqlite3.Database(dbFile)
    ;
app.post('/api/register', async (req, res) => {
    const { name, email, contact, password, bio, sponsor, confirmTerms, planType } = req.body;

    // Verifica se o e-mail já está em uso
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
        if (err) {
            console.log(err)
            return res.status(500).json({ message: 'Error registering user.' });
        }

        if (row) {
            return res.status(409).json({ message: 'E-mail already in use.' });
        }

        try {
            // Criptografa a senha antes de armazenar no banco de dados
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const confirm_terms = confirmTerms
            const plan_type = planType

            // Insere o novo usuário no banco de dados
            db.run('INSERT INTO users (name, email, password, contact, sponsor, confirm_terms, plan_type, bio  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [name, email, hashedPassword, contact, sponsor, confirm_terms, plan_type, bio], function (err) {
                if (err) {
                    console.log(err)
                    return res.status(500).json({ message: 'Error registering user.' });
                }

                // Obtém o ID do usuário recém-criado
                const userId = this.lastID;

                // Retorna o usuário criado com o ID
                const newUser = { id: userId, name, email };
                return res.status(201).json({ user: newUser });
            });
        } catch (error) {
            console.log(error)
            return res.status(500).json({ message: 'Error registering user.' });
        }
    });
});

app.post('/api/posts', async (req, res) => {
    const { title, description, url } = req.body;

    // Obtém o token de autorização do cabeçalho da requisição
    const token = req.headers.authorization.split(' ')[1];
    console.log(req.headers.authorization)
    if (!token) {
        return res.status(401).json({ message: 'Authorization token not found.' });
    }

    try {
        // Verifica o token e obtém as informações do usuário
        const decodedToken = jwt.verify(token, SECRET_KEY, { ignoreExpiration: true });

        const userId = decodedToken.id;

        // Insere o novo post no banco de dados com o userId obtido do token
        db.run('INSERT INTO posts (title, description, url, user_id) VALUES (?, ?, ?, ?)', [title, description, url, userId], function (err) {
            if (err) {
                return res.status(500).json({ message: 'Error creating post.' });
            }

            // Obtém o ID do post recém-criado
            const postId = this.lastID;

            // Retorna o post criado com o ID
            const newPost = { id: postId, title, description, url, user_id: userId };
            return res.status(201).json({ post: newPost });
        });
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: 'Error creating post.' });
    }
});


// Rota de login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Busca o usuário no banco de dados pelo e-mail
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Error logging in.' });
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Verifica a senha
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Gera um token JWT fake (somente para fins de demonstração)
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY);

        return res.status(200).json({ token, name: user.name, id: user.id });
    });
});

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});