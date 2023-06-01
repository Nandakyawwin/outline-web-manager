let db = require('./db');
let { OutlineVPN } = require('outlinevpn-api');
let Server = db.Server;

let all_server = () => {
    return new Promise((resolve, reject) => {
        Server.find({}, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
}


let server = (url) => {
    return new Promise((resolve, reject) => {
        let outlinevpn = new OutlineVPN({
            apiUrl :  url
        })
        let user =  outlinevpn.getUsers();
        return user;
    })
}

let save_server = (serverObj) => {
    return new Promise((resolve, reject) => {
        serverObj['since'] = new Date();
        let server = new Server(serverObj);
        server.save((err, data) => {
            if (err) reject(err);
            resolve(data)
        })
    })
};

let update_server = (serverObj) => {
    return new Promise((resolve, reject) => {
        Server.findOne({ name: serverObj.name }, (error, data) => {
            if (error) {
                reject(error);
            } else {
                data.name = serverObj.name;
                data.url = serverObj.url;
                data.save((err, res) => {
                    if (err) reject(err);
                    resolve(res);
                })
            }
        })
    })
};

let delete_server = (serverid) => {
    return new Promise((resolve, reject) => {
        Server.deleteOne({ serverid: serverid }, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
}

let paginate = (start, count) => {
    let paginateObj = {
        sort: { since: -1 },
        lean: true,
        page: start,
        limit: count
    };
    return new Promise((resolve, reject) => {
        Server.paginate({}, paginateObj, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
}


let findServerbyname = (serverid) => {
    return new Promise((resolve, reject) => {
        Server.find({ serverid: serverid }, (error, data) => {
            if (error) reject(error)
            resolve(data);
        })
    })
}

module.exports = {
    all_server,
    save_server,
    update_server,
    delete_server,
    paginate,
    findServerbyname,
    server
}


