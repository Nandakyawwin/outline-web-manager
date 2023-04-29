let db = require('./db');

let Key = db.Key;

let all_key = () => {
    return new Promise((resolve, reject) => {
        Key.find({}, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
};

let save_key = (keyObj) => {
    return new Promise((resolve, reject) => {
        keyObj['since'] = new Date();
        let key = new Key(keyObj);
        key.save((error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
};

let update_key = (keyObj) => {
    return new Promise((resolve, reject) => {
        if (error) {
            reject(error);
        } else {
            data.name = keyObj.name;
            data.sskey = keyObj.sskey;
            data.datalimit = keyObj.datalimit;
            data.save((error, data) => {
                if (error) reject(error);
                resolve(data);
            })
        }
    })
};

let delete_key = (sskey) => {
    return new Promise((resolve, reject) => {
        Key.deleteOne({ sskey: sskey }, (error, data) => {
            if (error) reject(error);
            resolve('Ok!Ads has been removed!');
        })
    })
};

let find_key = (sskey) => {
    return new Promise((resolve, reject) => {
        Key.findOne({ sskey: { $eq: sskey } }, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
}
let find_key_id = (id) => {
    return new Promise((resolve, reject) => {
        Key.findById(id, (error, data) => {
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
        Key.paginate({}, paginateObj, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
}

module.exports = {
    all_key,
    save_key,
    find_key,
    find_key_id,
    update_key,
    delete_key,
    paginate
}