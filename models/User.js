const mongoose = require("../db");
const { randomUUID }= require("crypto");

const userSchema = new mongoose.Schema({
    userId : {type : String , default : randomUUID , unique : true , index : true},
    username : {type : String , required : true , trim : true},
    email : {type : String , required : true , unique : true , lowercase : true , match :[/^\S+@\S+\.\S+$/ , "Please enter a valid email"]},
    passwordHash : {type : String , required : true},
    role : {type : mongoose.Schema.Types.ObjectId , ref : "Role" , required : true},
    isActive :{type : Boolean , default : true},
    lastLogin : {type : Date}
},{timestamps : true});

module.exports = mongoose.model("User" , userSchema);