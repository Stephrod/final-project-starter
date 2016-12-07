const bcrypt = require('bcrypt');
const passport = require('passport');
const User = require('../models/UserModel');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const LocalStrategy = require('passport-local');

const signinStrategy = new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }).exec()
    .then(user => {
      if(!user) {
        return done (null, false);
      }

    bcrypt.compare(password, user.password, function(err, isMatch){
      if (err) {
        return done (null, false);
      }

      if (!isMatch) {
        return done (null, false);
      }

      return done (null, user);
    });
  })
  .catch(err => done(err, false));
});

passport.use(`signinStrategy`, signinStrategy);
