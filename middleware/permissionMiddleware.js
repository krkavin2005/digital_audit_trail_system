function permissionMiddleware(requiredPermission){
    return(req , res , next)=>{
        if(!req.user || !req.user.role){
            console.log(req.user);
            return res.status(403).json({message :"Access Denied"});
        }
        const userPermissions = req.user.role.permissions;
        if(!userPermissions.includes(requiredPermission)){
            return res.status(403).json({message :"Insufficient permission"});
        }
        next();
    };
}

module.exports = permissionMiddleware;