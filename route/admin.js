module.exports = (express, bodyParser) => {
    let router = express.Router();
    let jwt = require('jsonwebtoken'),
        passport = require('passport'),
        bcrypt = require('../helper/pass'),

        // Database file import
        Admin = require('../database/admin'),
        Server = require('../database/server'),
        Key = require('../database/key');
    const axios = require('axios');
    const https = require('https');
    const agent = new https.Agent({ rejectUnauthorized: false });

    const { OutlineVPN } = require('outlinevpn-api');
    ///////////////////////////////////////////////////////////
    ///////////////                          //////////////////
    //////////////                           //////////////////
    //////////////      Admin Account          ////////////////
    //////////////                           //////////////////
    //////////////                           //////////////////
    ///////////////////////////////////////////////////////////

    // Admin login route

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

    // Admin Register route

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

    // Admin all 
    router.get('/all', (req, res) => {
        Admin.all_admin()
            .then(result => res.json({ con: true, msg: result }))
            .catch(err => res.json({ con: false, msg: err }));

    });


    // Admin update
    router.post('/update', (req, res) => {
        let adminobj = {
            name: req.body.name,
            email: req.body.email,
            password: req.body.password
        };

        Admin.update_admin(adminobj)
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin Delete
    router.post('/delete', (req, res) => {
        let adminName = req.body.name;
        Admin.delete_admin(adminName)
            .then(result => res.json({ con: true, msg: result }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    ///////////////////////////////////////////////////////////
    ///////////////                          //////////////////
    //////////////                           //////////////////
    //////////////      Admin Server         //////////////////
    //////////////                           //////////////////
    //////////////                           //////////////////
    ///////////////////////////////////////////////////////////

    // Admin Server Part

    // Admin all server

    router.get('/all/server', (req, res) => {
        Server.all_server()
            .then(result => res.json({ con: true, msg: result }))
            .catch(err => res.json({ con: false, msg: err }));

    })

    // getServer => server info (url)

    router.get('/info/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).getServer()
                    .then(data => res.json({ con: true, msg: data }))
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })



    router.post('/create/server', (req, res) => {
        let serverObj = {
            name: req.body.name,
            url: req.body.url
        };
        Server.save_server(serverObj)
            .then(result => res.json({ con: true, msg: result }))
            .catch(err => res.json({ con: false, msg: err }));
    })
    // getDataUsage => server all data usage
    // /metrics/transfer
    router.get('/getDataUsage/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).getDataUsage()
                    .then(data => res.json({ con: true, msg: data }))
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })

    // Admin delete server

    router.post('/delete/server', (req, res) => {
        let serverid = req.query.serverid;
        Server.delete_server(serverid)
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })


    // Admin Server Part 

    // Admin Key Part


    ///////////////////////////////////////////////////////////
    //////////////                           //////////////////
    //////////////                           //////////////////
    //////////////        Admin Key          //////////////////
    //////////////                           //////////////////
    //////////////                           //////////////////
    ///////////////////////////////////////////////////////////


    // getUsers => all sskeys
    // /access-keys
    router.get('/getUsers/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                // let url = `${result[0].url}/access-keys`;
                // axios.get(url, { httpsAgent: agent })
                //     .then(resp => { res.json({ con: true, msg: resp.data }) });
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).getUsers()
                    .then(data => res.json({ con: true, msg: data }))
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })

    //
    // getUser Info => get one sskey by (id)

    router.post('/getUser/:serverid/:id', (req, res) => {
        let serverid = req.param('serverid');
        let id = req.param('id');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).getUser(id)
                    // 
                    .then(data => res.json({ con: true, msg: data }))
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })


    router.post('/updateKey/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(data => {
                res.send(data);
            }).catch
            (err => res.json({ con: false, msg: err }));
    })


    router.get('/info/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).getServer()
                    .then(data => res.json({ con: true, msg: data }))
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })

    router.post('/createUser/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                new OutlineVPN({
                    apiUrl: result[0].url,
                    fingerprint: process.env.OUTLINE_API_FINGERPRINT
                }).createUser()
                    .then(data => {
                        let keyObj = {
                            name: req.body.name,
                            keyid: data.id,
                            url: result[0].url,
                            sskey: data.accessUrl,
                            datalimit: req.body.datalimit,
                            datelimit: req.body.datelimit
                        };
                        Key.save_key(keyObj)
                            .then(result => res.json({ con: true, msg: result }))
                            .catch(err => res.json({ con: false, msg: err }));
                    })
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => res.json({ con: false, msg: err }));
    })

    router.post('/registerUser/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
                let keyObj = {
                    name: req.body.name,
                    keyid: req.body.keyid,
                    url: result[0].url,
                    sskey: req.body.sskey,
                    datalimit: req.body.datalimit,
                    datelimit: req.body.datelimit
                };
                Key.save_key(keyObj)
                    .then(result => res.json({ con: true, msg: result }))
                    .catch(err => res.json({ con: false, msg: err }));
                // res.send(keyObj)
            })
            .catch(err => res.json({ con: false, msg: err }));
    })


    // sskey Check
    router.post('/key', (req, res) => {
        let key = {
            sskey: req.body.sskey
        };
        Key.find_key(key.sskey)
            .then(re => {
                Key.find_key_id(re._id)
                    .then(data => {
                        new OutlineVPN({
                            apiUrl: data.url,
                            fingerprint: process.env.OUTLINE_API_FINGERPRINT
                        }).getDataUserUsage(data.keyid)
                            .then(result => res.json({ con: true, msg: result, data }))
                            .catch(err => res.json({ con: false, msg: err }));
                    })
                    .catch(err => res.json({ con: false, msg: err }));
            })
            .catch(err => console.log(err));
    })



    // Admin all keys

    router.get('/all/keys', (req, res) => {
        Key.all_key()
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin delete key

    router.post('/delete/key', (req, res) => {
        let sskey = req.body.sskey;
        Key.delete_key(sskey)
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin delete key

    // Admin Key Part

    return router;

}   