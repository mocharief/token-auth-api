var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');
var passport	  = require('passport');
var config      = require('./config/database'); // get db config file
var User        = require('./app/models/user'); // get the mongoose model
var port        = process.env.PORT || 8080;
var jwt         = require('jwt-simple');
var cors        = require('cors');
 
// get our request parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
 
// log to console
app.use(morgan('dev'));
app.use(cors());
 
// Use the passport package in our application
app.use(passport.initialize());
 
// demo Route (GET http://localhost:8080)
app.get('/', function(req, res) {
  res.send('Hello! The API is at http://localhost:' + port + '/api');
});
 
// Start the server
app.listen(port);
console.log('token_auth_api: http://localhost:' + port);

// connect to database
mongoose.connect(config.database);
 
// pass passport for configuration
require('./config/passport')(passport);
 
// bundle our routes
var apiRoutes = express.Router();
 
// create a new user account (POST http://localhost:8080/api/signup)
apiRoutes.post('/signup', function(req, res) {
  if (!req.body.name || !req.body.password || !req.body.sebagai) {
    res.json({success: false, msg: 'Silahkan isi data Anda'});
  } else {
    var newUser = new User({
      name: req.body.name,
      password: req.body.password,
      sebagai: req.body.sebagai
    });
    // save the user
    newUser.save(function(err) {
      if (err) {
        return res.json({success: false, msg: 'Username telah ada.'});
      }
      res.json({success: true, msg: 'Berhasil menambahkan ' + newUser.sebagai +' baru'});
    });
  }
});
 
// connect the api routes under /api/*
app.use('/api', apiRoutes);

// route to authenticate a user (POST http://localhost:8080/api/authenticate)
apiRoutes.post('/authenticate', function(req, res) {
  User.findOne({
    name: req.body.name
  }, function(err, user) {
    if (err) throw err;
 
    if (!user) {
      res.send({success: false, msg: 'Autentikasi gagal, username tidak ditemukan.'});
    } else {
      // check if password matches
      user.comparePassword(req.body.password, function (err, isMatch) {
        if (isMatch && !err) {
          // if user is found and password is right create a token
          var token = jwt.encode(user, config.secret);
          // return the information including token as JSON
          res.json({success: true, token: 'JWT ' + token});
        } else {
          res.send({success: false, msg: 'Autentikasi gagal. Password salah.'});
        }
      });
    }
  });
});


// route to a restricted info (GET http://localhost:8080/api/memberinfo)
apiRoutes.get('/memberinfo', passport.authenticate('jwt', { session: false}), function(req, res) {
  var token = getToken(req.headers);
  if (token) {
    var decoded = jwt.decode(token, config.secret);
    User.findOne({
      name: decoded.name
    }, function(err, user) {
        if (err) throw err;

        if(user){
          res.json({
            data: user
          })
        }
    });
  } else {
    return res.status(403).send({success: false, msg: 'Tidak ada token.'});
  }
});
 
getToken = function (headers) {
  if (headers && headers.authorization) {
    var parted = headers.authorization.split(' ');
    if (parted.length === 2) {
      return parted[1];
    } else {
      return null;
    }
  } else {
    return null;
  }
};

//route akses datauser (POST http://localhost:8080/api/datauser)
apiRoutes.get('/datauser', passport.authenticate('jwt', { session: false}), function(req, res) {
  var token = getToken(req.headers);

  if (token) {
    var decoded = jwt.decode(token, config.secret);
    User.find({}, function(err, user) {
        if (err) throw err;
 
        if (decoded.sebagai == 'admin') {
          res.json(user);
        } else {
          return res.status(403).send('YOU ARE FORBIDDEN');
        }
    });
  } else {
    return res.status(403).send({success: false, msg: 'Tidak ada token.'});
  }
});