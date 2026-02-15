const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const router = express.Router();

router.get("/protected", authMiddleware , permissionMiddleware(PERMISSIONS.AUDIT_VIEW), (req , res)=>{
    res.json({
        message : "Access granted",
        user :{
            email: req.user.email,
            role : req.user.role.roleName
        }
    })
});

module.exports = router;