require("../db");
const bcrypt = require ("bcrypt");
const User = require("../models/User");
const Role = require("../models/Role");

async function seedAdmin(){
    console.log("Seeding admin user ...");
    const adminRole = await Role.findOne({roleName : "ADMIN"});
    if(!adminRole){
        console.log("ADMIN role not found. Seed roles first.");
        process.exit(1);
    }
    const exist = await User.findOne({email : "admin@system.com"});
    if(exist){
        console.log("Admin already exists.");
        process.exit(0);
    }
    const passwordHash = await bcrypt.hash("admin123",10);
    await User.create({
        username : "System Admin",
        email : "admin@system.com",
        passwordHash,
        role : adminRole._id
    });
    console.log("Admin user created.");
    process.exit(0);
}
seedAdmin().catch(err => confirm.error(err));