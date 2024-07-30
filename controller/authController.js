const pool = require('../db'); // Configura esto con tu conexión de base de datos
const bcrypt = require('bcrypt');

exports.login = async (req, res) => {
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
};

exports.ensureAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

