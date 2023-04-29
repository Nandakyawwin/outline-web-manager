module.exports = (express, bodyParser) => {
    let router = express.Router();
    let jwt = require('jsonwebtoken'),
        passport = require('passport'),
        bcrypt = require('../helper/pass'),

        // Database file import
        Admin = require('../database/admin'),
        Server = require('../database/server'),
        Key = require('../database/key');

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




    // renameServer => rename server (name,url)

    router.post('/rename/server', (req, res) => {
        let apiURL = req.body.url;
        let name = req.body.name;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).renameServer(name)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // getDataUsage => server all data usage

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


    // setDefaultDataLimit => server/setting/Default data limit

    router.post('/setDefaultDataLimit', (req, res) => {
        let apiURL = req.body.url;
        let bytes = req.body.bytes;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).setDefaultDataLimit(bytes)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })



    // deleteDefaultDataLimit => server/setting/Delete Default data limit

    router.post('/deleteDefaultDataLimit', (req, res) => {
        let apiURL = req.body.url;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).deleteDefaultDataLimit()
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })



    // setHostnameForAccessKeys => set hostname for access keys

    router.post('/setHostnameForAccessKeys', (req, res) => {
        let apiURL = req.body.url;
        let hostname = req.body.hostname;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).setHostnameForAccessKeys(hostname)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));

    })


    // setPortForNewAccessKeys => set port for new access keys

    router.post('/setPortForNewAccessKeys', (req, res) => {
        let apiURL = req.body.url;
        let port = req.body.port;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).setPortForNewAccessKeys(port)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // getDataUserUsage => sskey data usage (id)

    router.post('/getDataUserUsage', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).getDataUserUsage(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // getShareMetrics => get Share metrics

    router.post('/getShareMetrics', (req, res) => {
        let apiURL = req.body.url;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).getShareMetrics()
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })


    // setShareMetrics => set share metrics

    router.post('/setShareMetrics', (req, res) => {
        let apiURL = req.body.url;
        let bool = req.body.bool;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).setShareMetrics(Boolean(bool))
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })


    // Admin Post Server

    router.post('/create/server', (req, res) => {
        let serverObj = {
            name: req.body.name,
            url: req.body.url
        };
        Server.save_server(serverObj)
            .then(result => res.json({ con: true, msg: result }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // Admin Post Server

    // Admin Update Server

    router.post('/update/server', (req, res) => {
        let serverObj = {
            name: req.body.name,
            url: req.body.url
        };
        Server.update_server(serverObj)
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin Update Server

    // Admin server paginate

    router.post('/server/paginate/:start/:count', (req, res) => {
        let start = req.param('start');
        let count = req.param('count');

        Server.paginate(Number(start), Number(count))
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    });


    // Admin delete server

    router.post('/delete/server', passport.authenticate('jwt', { session: false }), (req, res) => {
        let id = req.body.movieid;
        Movie.destroy(String(id))
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

    router.get('/getUsers/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(result => {
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


    // createUser => create key

    // Admin create key
    router.post('/create/key', (req, res) => {

        Key.save_key(keyObj)
            .then(result => res.json({ con: true, msg: `Result is ${result} and obj is ${keyObj}` }))
            .catch(err => res.json({ con: false, msg: err }));

    });

    router.post('/updateKey/:serverid', (req, res) => {
        let serverid = req.param('serverid');
        Server.findServerbyname(Number(serverid))
            .then(data => {
                let keyObj = {
                    name: req.body.name,
                    sskey: req.body.sskey,
                    datalimit: req.body.datalimit,
                    datelimit: req.body.datelimit,
                    url: data[0].url
                };
                Key.save_key(keyObj)
                    .then(result => res.json({ con: true, msg: result }))
                    .catch(err => res.json({ con: false, msg: err }));
            }).catch
            (err => res.json({ con: false, msg: err }));
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

    // new OutlineVPN({
    //     apiUrl: data[0].url,
    //     fingerprint: process.env.OUTLINE_API_FINGERPRINT
    // }).getServer()
    //     .then(result => res.json({ con: true, msg: result, data }))
    //     .catch(err => res.json({ con: false, msg: err }));

    router.post('/key', (req, res) => {
        let key = {
            name: req.body.sskey
        };
        Key.find_key(key.name)
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
    // deleteUser => delete key (id)

    router.post('/deleteUser', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).deleteUser(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // renameUser => rename key (id,name)

    router.post('/renameUser', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).deleteUser(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // addDataLimit => add data limit (id,byte)

    router.post('/addDataLimit', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        let bytes = req.body.bytes;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).addDataLimit(id, bytes)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // deleteDataLimit => delete data limit (id)

    router.post('/deleteDataLimit', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).deleteDataLimit(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // disableUser => disable user (id)

    router.post('/disableUser', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).disableUser(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })

    // enableUser => enable user (id)

    router.post('/enableUser', (req, res) => {
        let apiURL = req.body.url;
        let id = req.body.id;
        new OutlineVPN({
            apiUrl: apiURL,
            fingerprint: process.env.OUTLINE_API_FINGERPRINT
        }).enableUser(id)
            .then(data => res.json({ con: true, msg: data }))
            .catch(err => res.json({ con: false, msg: err }));
    })


    // Admin all keys

    router.get('/all/keys', (req, res) => {
        Key.all_key()
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin all keys


    // Admin create key

    // Admin update Key

    router.post('/update/key', (req, res) => {
        let keyObj = {
            name: req.body.name,
            sskey: req.body.sskey,
            datalimit: req.body.datalimit
        };

        Key.update_key(keyObj)
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    })

    // Admin update Key

    // Admin paginate key

    router.get('/key/paginate/:start/:count', (req, res) => {
        let start = req.param('start');
        let count = req.param('count');

        Key.paginate(Number(start), Number(count))
            .then(result => res.send({ con: true, msg: result }))
            .catch(err => res.send({ con: false, msg: err }));
    });

    // Admin paginate key

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