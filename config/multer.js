const {randomUUID}= require("crypto");
const multer = require("multer");
const path = require("path");

const allowedTypes =["application/pdf","image/png","image/jpeg","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/msword","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","application/vnd.ms-exel"];

const storage = multer.diskStorage({
    destination : function(req , file , cb){
        cb(null,"uploads/");
    },
    filename : function(req , file , cb){
        const name = randomUUID() + path.extname(file.originalname);
        cb(null , name);
    }
});

const docupload = multer({
    storage,
    limits :{fileSize : 25 * 1024 * 1024},
    fileFilter :(req , file , cb)=>{
        if(allowedTypes.includes(file.mimetype)) cb(null , true);
        else cb(new Error("Invalid file type"), false);
    }
});
module.exports = docupload;