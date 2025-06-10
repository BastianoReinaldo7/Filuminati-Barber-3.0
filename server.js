require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise'); // Usamos la versión promise-based
const bodyParser = require('body-parser');
const session = require('express-session');
const bcryptjs = require('bcryptjs'); // ✅ Corregido (antes era 'bcrypts')
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3005;

// Configuración de middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configuración de sesión mejorada
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'secretofiluminati_backup',
        resave: false,
        saveUninitialized: false,
        cookie: { 
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 1 día
        }
    })
);

// Configuración de conexión a la base de datos con pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3305,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Verificar conexión a la base de datos al iniciar
pool.getConnection()
    .then(connection => {
        console.log('Conectado a la base de datos MySQL');
        connection.release();
    })
    .catch(err => {
        console.error('Error al conectar a MySQL:', err);
        process.exit(1);
    });

// Middleware para verificar autenticación
const requireLogin = (req, res, next) => {
    if (!req.session.loggedin) {
        return res.status(401).json({ error: 'Debes iniciar sesión para acceder a este recurso' });
    }
    next();
};

// Ruta para registrar un nuevo usuario
app.post('/registrar', async (req, res) => {
    const { nombre, apellido, correo, comuna, contrasena } = req.body;

    if (!nombre || !apellido || !correo || !comuna || !contrasena) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    try {
        const hashedPassword = await bcryptjs.hash(contrasena, 10); // ✅ Corregido (antes era 'bcrypt')
        const query = `INSERT INTO usuarios (nombre, apellido, correo, comuna, contrasena) VALUES (?, ?, ?, ?, ?)`;
        
        const [results] = await pool.execute(query, [nombre, apellido, correo, comuna, hashedPassword]);
        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    } catch (error) {
        console.error('Error al registrar el usuario:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'El correo electrónico ya está registrado' });
        }
        
        res.status(500).json({ error: 'Error al registrar el usuario' });
    }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    try {
        const query = `SELECT * FROM usuarios WHERE correo = ?`;
        const [results] = await pool.execute(query, [correo]);

        if (results.length > 0) {
            const user = results[0];
            const isMatch = await bcryptjs.compare(contrasena, user.contrasena); // ✅ Corregido (antes era 'bcrypt')

            if (isMatch) {
                req.session.loggedin = true;
                req.session.userId = user.id;
                req.session.nombre = user.nombre;
                return res.status(200).json({ 
                    message: 'Inicio de sesión exitoso',
                    nombre: user.nombre 
                });
            }
        }
        
        res.status(401).json({ error: 'Credenciales incorrectas' });
    } catch (error) {
        console.error('Error en el inicio de sesión:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Ruta para agregar un nuevo corte
app.post('/agregar-corte', requireLogin, async (req, res) => {
    const { fecha, tipo_servicio, descripcion } = req.body;
    const user_id = req.session.userId;

    if (!fecha || !tipo_servicio || !descripcion) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    try {
        const query = `INSERT INTO cortes (user_id, fecha, tipo_servicio, descripcion) VALUES (?, ?, ?, ?)`;
        await pool.execute(query, [user_id, fecha, tipo_servicio, descripcion]);
        res.status(200).json({ success: true });
    } catch (error) {
        console.error('Error al agregar el corte:', error);
        res.status(500).json({ error: 'Error al agregar el corte' });
    }
});

// Ruta para obtener los cortes del usuario
app.get('/obtener-cortes', requireLogin, async (req, res) => {
    try {
        const query = `SELECT * FROM cortes WHERE user_id = ?`;
        const [results] = await pool.execute(query, [req.session.userId]);
        res.status(200).json(results);
    } catch (error) {
        console.error('Error al obtener los cortes:', error);
        res.status(500).json({ error: 'Error al obtener los cortes' });
    }
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Ruta de logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Sesión cerrada exitosamente' });
    });
});

// Manejo de errores
app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Entorno: ${process.env.NODE_ENV || 'development'}`);
});