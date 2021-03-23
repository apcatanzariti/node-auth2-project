const router = require("express").Router();
const bcrypt = require('bcryptjs');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { findBy, add } = require('./../users/users-model');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const credentials = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  // hash the password
  const hash = bcrypt.hashSync(credentials.password, rounds);
  credentials.password = hash;
  
  add(credentials)
  .then(user => {
    res.status(201).json(user);
  })
  .catch(err => {
    res.status(500).json({ message: 'invalid credentials' });
  })
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body;
  findBy(username)
  .then(user => {
    if (user[0] && bcrypt.compareSync(password, user[0].password)) {
    const token = buildToken(user);
    res.status(200).json({ message: `${user[0].username} is back!`, token });
    } else {
      res.status(401).json({ message: 'Invalid credentials 😨' });
    }
  })
  .catch(err => {
    res.status(500).json({ error: err.message, message: 'something went wrong while logging in'});
  })
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };

  const config = {
    expiresIn: '1d'
  };

  return jwt.sign(payload, JWT_SECRET, config);
};

module.exports = router;
