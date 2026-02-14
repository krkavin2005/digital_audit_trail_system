const mongoose = require("../db");

const verificationReportSchema = new mongoose.Schema({
    reportId : {type : String , required : true , unique : true},
    verifiedAt : {type : Date , required : true},
    totalRecords : {type : Number},
    status : {type : String , enum :["VALID","TAMPERED"], required : true},
    brokenAt : {type : Number},
    expectedHash : {type : String},
    foundHash : {type : String},
    verifier : {type : String , default : "SYSTEM"},
    renderedString : {type : String , required : true},
    signature: {type : String}
},{versionKey : false});

module.exports = mongoose.model("VerificationReport", verificationReportSchema);