const mongoose = require('mongoose')
paginate = require('mongoose-paginate');
let url = 'mongodb://127.0.0.1:27017/outlineDB';
const connect = mongoose.connect(url, { useNewUrlParser: true });
let autoI = require('simple-mongoose-autoincrement');
let Schema = mongoose.Schema;


let ServerScheme = new Schema({
    name: { type: String },
    url: { type: String },
    since: { type: Date, required: true },

});


let AdminScheme = new Schema({
    email: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, required: true },
    password: { type: String, required: true },
    since: { type: Date, required: true },

});

let KeyScheme = new Schema({
    name: { type: String },
    keyid: { type: Number },
    sskey: { type: String },
    url: { type: String },
    datalimit: { type: String },
    datelimit: { type: String },
    since: { type: Date }
})


ServerScheme.plugin(autoI, { field: 'serverid' });
ServerScheme.plugin(paginate);
let Server = mongoose.model('server', ServerScheme);

AdminScheme.plugin(autoI, { field: 'adminId' });
AdminScheme.plugin(paginate);
let Admin = mongoose.model('admin', AdminScheme);

KeyScheme.plugin(autoI, { field: 'keyId' });
KeyScheme.plugin(paginate);
let Key = mongoose.model('key', KeyScheme);

module.exports = {
    Server,
    Key,
    Admin,
}