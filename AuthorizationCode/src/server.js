const express = require('express');
const GitHubStrategy = require('passport-github2').Strategy;
const passport = require('passport');
const session = require('express-session');

/** CONFIG PARAMETERS */
const PORT = 8080;
const SESSION_CONFIG = { secret: 'abc', saveUninitialized: true, resave: true };
const REDIRECTS = { successRedirect: '/user', failureRedirect: '/login' };
const GITHUB_CREDENTIALS = {
    clientID: '<your github client_id>',
    clientSecret: 'your github client_secret',
    callbackURL: 'http://localhost:8080/github/redirect'
}

/** INITIALIZE */
// Passport
passport.use(new GitHubStrategy(GITHUB_CREDENTIALS, tokenHandler));
passport.serializeUser(connectToDatabase);
passport.deserializeUser(connectToDatabase);

// Express
const app = express();
app.use(session(SESSION_CONFIG));
app.use(passport.initialize());
app.use(passport.session());

/** DEFINE ENDPOINTS */
// view static files
const servePublicFiles = express.static(__dirname + '/public', { extensions: ['html'] });
const serveUserFiles = express.static(__dirname + '/user', { extensions: ['html'] });
app.use('/', servePublicFiles);
app.use('/user', [ensureAuthenticated, serveUserFiles]);

// login with github
app.get('/github/login', passport.authenticate('github'));
app.get('/github/redirect', passport.authenticate('github', REDIRECTS));

// general logout
app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

/** START SERVER */
app.listen(PORT, () => console.log(`Oauth AC example server listening on port ${PORT}`));

/**********************************************************************************************/
/**********************************************************************************************/

/** MIDDELWARES */
function ensureAuthenticated(req, res, next) {
    return req.isAuthenticated() ? next() : res.redirect('/login');
}

function tokenHandler(access, refresh, user, next){
    return next(null, user);
}

function connectToDatabase(user, next){
    // Normally you would check the user from the
    // token against the users in your database.
    // Here we just use token user as user.
    return next(null, user);
}