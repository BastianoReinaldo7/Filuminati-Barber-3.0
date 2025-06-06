const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3005;

// Configurar body-parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar sesión
app.use(
    session({
        secret: 'secretofiluminati',
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false } // Cambia a true si usas HTTPS
    })
);

// Configurar conexión a la base de datos
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'barberia',
    port: 3305,
});

// Conectar a la base de datos
connection.connect((err) => {
    if (err) {
        console.error('Error al conectar a MySQL:', err);
        process.exit(1); // Salir si no se puede conectar a la base de datos
    }
    console.log('Conectado a la base de datos MySQL');
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
        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(contrasena, 10);

        const query = `INSERT INTO usuarios (nombre, apellido, correo, comuna, contrasena) VALUES (?, ?, ?, ?, ?)`;

        connection.query(query, [nombre, apellido, correo, comuna, hashedPassword], (err, results) => {
            if (err) {
                console.error('Error al registrar el usuario:', err);
                return res.status(500).json({ error: 'Error al registrar el usuario' });
            }

            res.status(201).json({ message: 'Usuario registrado exitosamente' });
        });
    } catch (error) {
        console.error('Error al encriptar la contraseña:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Ruta para iniciar sesión
app.post('/login', (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    const query = `SELECT * FROM usuarios WHERE correo = ?`;

    connection.query(query, [correo], async (err, results) => {
        if (err) {
            console.error('Error en la consulta de inicio de sesión:', err);
            return res.status(500).json({ error: 'Error en la consulta' });
        }

        if (results.length > 0) {
            const user = results[0];

            // Comparar la contraseña encriptada
            const isMatch = await bcrypt.compare(contrasena, user.contrasena);
            if (isMatch) {
                req.session.loggedin = true;
                req.session.userId = user.id; // Guardar el ID del usuario en la sesión
                req.session.nombre = user.nombre;
                return res.status(200).json({ message: 'Inicio de sesión exitoso' });
            }
        }
        res.status(401).json({ error: 'Credenciales incorrectas' });
    });
});

// Ruta para agregar un nuevo corte
app.post('/agregar-corte', requireLogin, (req, res) => {
    const { fecha, tipo_servicio, descripcion } = req.body;
    const user_id = req.session.userId; // Obtener el ID del usuario desde la sesión

    if (!fecha || !tipo_servicio || !descripcion) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    const query = `INSERT INTO cortes (user_id, fecha, tipo_servicio, descripcion) VALUES (?, ?, ?, ?)`;
    connection.query(query, [user_id, fecha, tipo_servicio, descripcion], (err, results) => {
        if (err) {
            console.error('Error al agregar el corte:', err);
            return res.status(500).json({ error: 'Error al agregar el corte' });
        }
        res.status(200).json({ success: true });
    });
});

// Ruta para obtener los cortes del usuario
app.get('/obtener-cortes', requireLogin, (req, res) => {
    const user_id = req.session.userId; // Obtener el ID del usuario desde la sesión

    const query = `SELECT * FROM cortes WHERE user_id = ?`;
    connection.query(query, [user_id], (err, results) => {
        if (err) {
            console.error('Error al obtener los cortes:', err);
            return res.status(500).json({ error: 'Error al obtener los cortes' });
        }
        res.status(200).json(results);
    });
});

// Ruta para servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Middleware para manejar errores 404
app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

// Middleware para manejar errores generales
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});