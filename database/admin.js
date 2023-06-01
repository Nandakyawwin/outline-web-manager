let db = require('./db');
let Admin = db.Admin;


let all_admin = () => {
    return new Promise((resolve, reject) => {
        Admin.find({}, (error, data) => {
            if (error) reject(error);
            resolve(data);
        })
    })
};


let save_admin = (adminObj) => {
    return new Promise((resolve, reject) => {
        adminObj['since'] = new Date();
        adminObj['role'] = 'admin';
        let admin = new Admin(adminObj);
        admin.save((err, data) => {
            if (err) reject(err);
            resolve(data)
        })
    })
};

let update_admin = (adminObj) => {
    return new Promise((resolve, reject) => {
        Admin.findOne({ email: adminObj.email }, (error, data) => {
            if (error) {
                reject(error);
            } else {
                data.email = adminObj.email;
                data.name = adminObj.name;
                data.password = adminObj.password;

                data.save((error, result) => {
                    if (error) reject(error);
                    resolve(result);
                })
            }
        })
    })
};

let delete_admin = (admin_name) => {
    return new Promise((resolve, reject) => {
        Admin.deleteOne({ name: admin_name }, (error, data) => {
            if (error) reject(error);
            resolve('Ok! Admin account is removed!');
        })
    })
}

let findByAdminemail = (findemail) => {
    return new Promise((resolve, reject) => {
        Admin.findOne({ email: findemail }, (error, data) => {
            if (data == null || data == undefined) reject('No admin',error);
            resolve(data);
        })
    })
}

module.exports = {
    all_admin,
    save_admin,
    findByAdminemail,
    update_admin,
    delete_admin
}


 // admin email= sawpyaephyokyaw2023@gmail.com
 // password   = admin@sppk@2023