const {randomUUID}= require("crypto");
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
    destination : function(req , file , cb){
        cb(null,"uploads/");
    },
    filename : function(req , file , cb){
        const name = randomUUID() + path.extname(file.originalname);
        cb(null , name);
    }
});

const docupload = multer({storage});
module.exports = docupload;