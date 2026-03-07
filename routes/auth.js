const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const user = require("../models/User");
const User = require("../models/User");
const { logAction } = require("../services/auditService");
const router = express.Router();
require("dotenv").config();

router.post("/login", async(req , res)=>{
    try{
        const {email , password} = req.body;
        if(!email || !password){
            return res.status(400).json({message :"Email and password required"});
        }
        const user = await User.findOne({email}).populate("role");
        console.log(user);
        if(!user){
            return res.status(401).json({message :"Invalid credentials"});
        }
        if(!user.isActive){
            return res.status(403).json({message :"Account disabled"});
        }
        const isMatch = await bcrypt.compare(password , user.passwordHash);
        if(!isMatch){
            return res.status(401).json({message :"Invalid credentials"});
        }
        const token = jwt.sign({userId : user.userId},process.env.JWT_SECRET,{expiresIn :"1h"});
        user.lastLogin = new Date();
        await user.save();
        logAction(user ,"LOGIN","System");
        res.json({message :"Login successful", token});
    }catch(err){
        console.error(err);
        res.status(500).json({message :"Server error"});
    }
});

module.exports = router;