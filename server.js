require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pg = require('pg');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

// Configuración de la base de datos
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middleware de sesión
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: 'tu_secreto_de_sesion', // Cambia esto por un secreto fuerte
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 días
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de EJS
app.set('view engine', 'ejs');

// Ruta raíz
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Ruta para mostrar el formulario de registro de usuarios
app.get('/register', (req, res) => {
  res.render('register');
});

// Ruta para manejar el registro de usuarios
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Verificar si el usuario ya existe
    const userQuery = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userQuery.rows.length > 0) {
      return res.status(400).send('El usuario ya existe');
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar el nuevo usuario en la base de datos
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);

    res.redirect('/login');
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta para mostrar el formulario de inicio de sesión
app.get('/login', (req, res) => res.render('login'));

// Ruta para manejar el inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userQuery = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userQuery.rows.length > 0) {
      const user = userQuery.rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        req.session.userId = user.id;
        return res.redirect('/dashboard');
      }
    }
    res.status(401).send('Credenciales incorrectas');
  } catch (err) {
    res.status(500).send('Error en el servidor');
  }
});

// Middleware para proteger rutas
function ensureAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Ruta del dashboard protegida
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { userId: req.session.userId });
});

// Ruta de logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).send('Error al cerrar sesión');
      }
      res.redirect('/login');
    });
  });
  
  


// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
