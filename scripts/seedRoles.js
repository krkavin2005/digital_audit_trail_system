require("../db");
const Role = require("../models/Role");
const PERMISSIONS = require("../config/permissions");

async function seedRoles(){
    console.log("Seeding roles . . .");
    const roles = [
        {
            roleName : "ADMIN",
            permissions : Object.values(PERMISSIONS),
            description : "Full system access"
        },
        {
            roleName : "MANAGER",
            permissions :[PERMISSIONS.FILE_UPLOAD , PERMISSIONS.FILE_VIEW , PERMISSIONS.REPORT_GENERATE],
            description : "Manages files and reports"
        },
        {
            roleName : "EMPLOYEE",
            permissions : [PERMISSIONS.FILE_UPLOAD , PERMISSIONS.FILE_VIEW],
            description : "Basic file access"
        },
        {
            roleName : "AUDITOR",
            permissions :[PERMISSIONS.AUDIT_VIEW , PERMISSIONS.REPORT_GENERATE],
            description : "Audit and compliance access"
        }
    ];
    for(const role of roles){
        const exists = await Role.findOne({roleName : role.roleName});
        if(!exists){
            await Role.create(role);
            console.log(`${role.roleName} created`);
        }
    }
    console.log("Role seeding complete.");
    process.exit(0);
}

seedRoles().catch(err =>{
    console.error(err)
    process.exit(1);
});