const jwt = require("jsonwebtoken");
const User = require("../models/User");

async function authMiddleware(req , res , next){
    try{
        const authHeader = req.headers.authorization;
        if(!authHeader || !authHeader.startsWith("Bearer ")){
            return res.status(401).json({message :"No token provided"});
        }
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token , process.env.JWT_SECRET);
        const user = await User.findOne({userId : decoded.userId}).populate("role");
        if(!user) return res.status(401).json({message : "User Not Found"});
        if(!user.isActive) return res.status(403).json({message : "User Disabled"});
        req.user = user;
        next();
    }catch(err){
        return res.status(401).json({message :"Invalid or expired token"});
    }
}

module.exports = authMiddleware;