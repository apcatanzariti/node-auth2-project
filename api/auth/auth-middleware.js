const { JWT_SECRET } = require('../secrets/index'); // use this secret!
const { findBy } = require('./../users/users-model');
const jwt = require('jsonwebtoken');

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
 const token = req.headers.authorization;

 if (!token) {
  res.status(401).json({ message: 'Token required' });
 } else {
   jwt.verify(token, JWT_SECRET, (err, decoded) => {
     if (err) {
       res.status(401).json({ message: 'Token invalid' });
     } else {
       req.body.decodedJwt = decoded;
       next();
     }
   })
 }
};


//***************NOT WORKING YET - always falls into sad path**************//

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 // fish the token from req
  // fish the actual role from the token
  // compare that against the role coming in through args
  // if they're the same proceed otherwise bounce
  const token = req.headers.authorization;
  const actualRole = jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log(err.message);
    } else {
      console.log(decoded);
    }
  });

  if (role_name !== actualRole) {
    console.log(token);
    res.status(403).json({ message: 'This is not for you' });
  } else {
    next();
  }
};




const checkUsernameExists = (req, res, next) => {
  const { username } = req.body;

  findBy(username)
    .then(user => {
      if (!user) {
        res.status(401).json({ message: 'Invalid credentials' });
      } else {
        next();
      }
    })
    .catch(err => {
      res.status(500).json({ error: err.message, message: 'something went wrong while checking username' });
    })
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
 
  const role = req.body.role_name;
  const trimmed_role = role.trim();
 
 if (!trimmed_role || trimmed_role === '') {
   req.body.role_name = 'student';
   next();
 } else if (trimmed_role === 'admin') {
  res.status(422).json({ message: 'Role name can not be admin' });
 } else if (trimmed_role.length > 32) {
  res.status(422).json({ message: 'Role name can not be longer than 32 chars' });
 } else {
   req.body.role_name = trimmed_role;
   next();
 }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
