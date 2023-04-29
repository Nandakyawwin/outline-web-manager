module.exports = (express) => {
    let router = express.Router();
    let jwt = require('jsonwebtoken'),
        passport = require('passport');
    let bcrypt = require('../helper/pass');
    let Admin = require('../database/admin');
    let Key = require('../database/key');
    // login route

    router.post('/login', (req, res) => {

        let email = req.body.email;
        let password = req.body.password;

        Admin.findByAdminemail(email)
            .then(admin => {
                bcrypt.compare(password, admin.password)
                    .then(result => {
                        if (result) {
                            let payload = { email: admin.email, name: admin.name };
                            let token = jwt.sign(payload, process.env.SECRET);
                            res.json({ con: true, token: token, name: admin });
                        } else {
                            res.json({ con: false, msg: 'password wrong' })
                        }
                    }).catch(err => res.send({ con: false, msg: err }));
            })
            .catch(err => res.send({ con: false, msg: "admin login error" }));
    });

    // Register route

    router.post('/register', (req, res) => {
        let name = req.body.name;
        let email = req.body.email;
        let password = req.body.password;
        bcrypt.encrypt(password)
            .then(result => {
                let adminobj = {
                    'email': email,
                    'name': name,
                    'password': result
                };
                Admin.save_admin(adminobj)
                    .then(admin => res.send({ con: true, msg: admin }))
                    .catch(err => res.send({ con: false, msg: err }));

            })
            .catch(err => res.send({ con: false, msg: err }));
    });

    // check key route

    router.post('/check/key', (req, res) => {
        let sskey = req.body.sskey;
        Key.find_key(sskey)
            .then(admin => res.send({ con: true, msg: admin }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    return router;

}