require("../db");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const Role = require("../models/Role");

async function seedEmployee(){
    console.log("Seeding employee user...");
    const employeeRole = await Role.findOne({roleName :"EMPLOYEE"});
    if(!employeeRole){
        console.log("EMPLOYEE role not found. Seed roles first.");
        process.exit(1);
    }
    const exist = await User.findOne({email : "employee@system.com"});
    if(exist){
        console.log("Employee already exists.");
        process.exit(0);
    }
    const passwordHash = await bcrypt.hash("employee123", 10);
    await User.create({username :"Test Employee", email :"employee@system.com", passwordHash , role : employeeRole._id});
    console.log("Employee user created");
    process.exit(0);
}

seedEmployee().catch(err =>{
    console.error(err);
    process.exit(1);
});