const mongoose = require("../db");
const {randomUUID}= require("crypto");

const documentSchema = new mongoose.Schema({
    documentId :{type : String , default : randomUUID , unique : true , index : true},
    orginalName :{type : String , required : true},
    storedName :{type : String , required : true},
    uploadedBy :{type : mongoose.Schema.Types.ObjectId , ref :"User", required : true},
    fileHash :{type : String , required : true},
    size :{type : Number , required : true},
    mimeType :{type : String , required : true},
    isDeleted :{type : Boolean , default : false}
},{timestamps : true});

module.exports = mongoose.model("Document", documentSchema);