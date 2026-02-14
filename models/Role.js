const  mongoose = require("../db");

const roleSchema = new mongoose.Schema({
    roleName :{type : String , required : true , unique : true , uppercase : true},
    permissions :{type :[String], required : true , default :[]},
    description : {type : String}
},{timestamps : true});

module.exports = mongoose.model("Role", roleSchema);