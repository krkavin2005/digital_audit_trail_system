const mongoose = require("../db");

const auditEventSchema = new mongoose.Schema({
    eventId: {type : Number , required : true , index : true},
    actorId : String,
    actor : {type : String , required : true},
    actorRole : String,
    action : String,
    target : String,
    timestamp: {type : Date , required : true},
    prevHash : String,
    hash : {type : String , required : true , index : true}
},{versionKey : false});

auditEventSchema.pre(["updateOne",,"updateMany","deletOne","deleteMany","findOneAndUpdate","findOneAndDelete","findByIdAndDelete"],
    ()=> {
        throw new Error("Modification attempt detected. Audit events are immutable");
    }
);

module.exports = mongoose.model("AuditEvent", auditEventSchema);