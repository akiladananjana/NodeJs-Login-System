const localStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const initialize = (passport, getUserByEmail, getUserById) => {
  const authenticateUser = async (email, password, done) => {
    const user = getUserByEmail(email);

    if (user == null) {
      return done(null, false, { message: "No User with that Email...!" });
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Password is incorrect...!" });
      }
    } catch (error) {
      return done(error);
    }
  };

  // instruct passport to use local strategy,
  // and tell form data passed as "email" for username (because passport use "username" "password" as default)
  passport.use(new localStrategy({ usernameField: "email" }, authenticateUser));

  // attach authenticated user id to req.session.passport.user (as session data)
  passport.serializeUser((user, done) => {
    console.log("serializeUser");
    return done(null, user.id);
  });

  // attach full user info to req.user object. This uses user id from req.session.passport.user to query user.
  passport.deserializeUser((id, done) => {
    console.log("deserializeUser");
    return done(null, getUserById(id));
  });
};

module.exports = initialize;
