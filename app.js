require('dotenv').config();
let express = require('express'),
    app = express(),
    jwt = require('jsonwebtoken'),
    passport = require('passport'),
    bodyParser = require('body-parser'),
    JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt,
    Admin = require('./database/admin'),
    Key = require('./database/key'),
    cors = require('cors');
Server = require('./database/server');
const { OutlineVPN } = require('outlinevpn-api');
let jwtOption = {};
jwtOption.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOption.secretOrKey = process.env.SECRET;

let myS = new JwtStrategy(jwtOption, (payload, done) => {
    let email = payload.email;
    let name = payload.name;
    Admin.findByAdminemail(email)
        .then(admin => {
            if (admin.name == name) {
                done(null, admin);
            }
        })
        .catch(err => done(err, null));
})

let adminRoute = require('./route/admin')(express, jwt, passport, bodyParser);
let guestRoute = require('./route/guest')(express, bodyParser);

passport.use(myS);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());
app.use('/admin', adminRoute);
app.use('/', guestRoute);

app.listen(process.env.PORT, _ => {
    console.log(`Server is running at ${process.env.PORT}`);
});