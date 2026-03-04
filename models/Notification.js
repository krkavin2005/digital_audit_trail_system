const mongoose = require("../db");

const notificationSchema = new mongoose.Schema({
    userId :{type : mongoose.Scheam.Types.ObjectId , ref :"User", required : true},
    type :{type : String , required : true},
    documentId :{type : String , required : true},
    message :{type : String , required : true},
    isRead :{type : Boolean , default : false}
},{timestamps : true});

module.exports = mongoose.model("Notification", notificationSchema);