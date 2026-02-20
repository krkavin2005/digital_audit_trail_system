const STATES ={
    INITIAL :"INITIAL",
    DRAFT :"DRAFT",
    APPROVED :"APPROVED",
    SUBMITTED :"SUBMITTED",
    REJECTED :"REJECTED",
    ARCHIVED :"ARCHIVED"
};

const TRANSITIONS ={
    DRAFT :{
        SUBMITTED :["EMPLOYEE"]
    },
    SUBMITTED :{
        APPROVED :["MANAGER"],
        REJECTED :["MANAGER"]
    },
    rejected :{
        draft :["EMPLOYEE"]
    },
    APPROVED :{
        ARCHIVED :["EMPLOYEE"]
    },
    REJECTED :{
        DRAFT :["OWNER"]
    }
};

function canDelete(document , user){
    if((document.status === STATES.APPROVED || document.status === STATES.ARCHIVED)&& user.role.roleName ==="ADMIN") return true;
    if(document.status === STATES.DRAFT && user._id.equals(document.uploadedBy)) return true;
    return false;
}

function canTransition(document , nextState , user){
    const currentState = document.status;
    if(!TRANSITIONS[currentState]) return false;
    const allowedRoles = TRANSITIONS[currentState][nextState];
    if(!allowedRoles) return false;
    if(!allowedRoles.includes(user.role.roleName)) return false;
    if(currentState === "draft"&& nextState ==="submitted"&& !document.uploadedBy.equals(user._id)) return false;
    return true;
}

module.exports ={STATES , canTransition , canDelete};