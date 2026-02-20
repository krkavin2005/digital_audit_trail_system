const mongoose = require("../db");
const {randomUUID} = require("crypto");

const workflowHistorySchema = new mongoose.Schema({
    historyId :{type : String , default : randomUUID , unique : true , index : true},
    documentId :{type : String , required : true},
    fromState :{type : String , required : true},
    toState :{type : String , required : true},
    actedBy :{type : mongoose.Schema.Types.ObjectId , ref :"User" , required : true},
    actorRole :{type : String , required : true},
    comment :{type : String}
},{timestamps : true});

module.exports = mongoose.model("WorkflowHistory", workflowHistorySchema);