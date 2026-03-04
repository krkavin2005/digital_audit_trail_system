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
        SUBMITTED :["EMPLOYEE","MANAGER"]
    },
    SUBMITTED :{
        APPROVED :["MANAGER","ADMIN"],
        REJECTED :["MANAGER","ADMIN"]
    },
    rejected :{
        draft :["EMPLOYEE"]
    },
    APPROVED :{
        ARCHIVED :["ADMIN"]
    },
    REJECTED :{
        DRAFT :["EMPLOYEE"]
    }
};

const SLA_RULES ={
    SUBMITTED : 1,
    APPROVED : 7
};

const ESCALATION_BUFFER_DAYS = 2;

const TERMINALS =[STATES.ARCHIVED];

function canDelete(document , user){
    if((document.status === STATES.APPROVED || document.status === STATES.ARCHIVED)&& user.role.roleName ==="ADMIN") return true;
    if(document.status === STATES.DRAFT && user._id.equals(document.uploadedBy)) return true;
    return false;
}

function canTransition(document , nextState , user , comment = null){
    const currentState = document.status;
    if(TERMINALS.includes(currentState)){
        return {allowed : false , reason :"Terminal Document cannot be transitioned"};
    }
    if(!TRANSITIONS[currentState]||!TRANSITIONS[currentState][nextState]) return {allowed : false , reason:"Invalid State Transition"};
    const allowedRoles = TRANSITIONS[currentState][nextState];
    if(!allowedRoles.includes(user.role.roleName)) return {allowed : false , reason :"Role not allowed for transition"};
    if(nextState === STATES.REJECTED && (!comment || comment.trim()==="")) return {allowed : false , reason :"Rejection requires a comment"};
    if(currentState === STATES.SUBMITTED && (nextState === STATES.APPROVED || nextState === STATES.REJECTED)&& document.uploadedBy.equals(user._id)){
        return {allowed : false , reason :"Cannot approve own doc"};
    }
    if(currentState === STATES.DRAFT && nextState === STATES.SUBMITTED && !document.uploadedBy.equals(user._id)) {
        return {alloed : false , reason :"Not the owner of the file"};
    }
    if(currentState === STATES.REJECTED && nextState === STATES.DRAFT){
        if(!document.uploadedBy.equals(user._id)){
            return {allowed : false , reason:"Resubmition only by owner"}
        }
    }
    return {allowed : true};
}

function isOverdue(doc){
    if(!SLA_RULES[doc.status]) return false;
    const now = new Date();
    const diffms = now - doc.statusChangedAt;
    const diffDays = diffms /(1000 * 60 * 60 * 24);
    return diffDays > SLA_RULES[doc.status];
}

function shouldEscalate(doc){
    console.log(doc.status);
    if(!SLA_RULES[doc.status]) return false;
    if(doc.isEscalated) return false;
    const now = new Date();
    const diffDays = (now - doc.statusChangedAt)/(1000 * 60 * 60 * 24);
    return diffDays > SLA_RULES[doc.status]+ ESCALATION_BUFFER_DAYS;
}

module.exports ={STATES , canTransition , canDelete , isOverdue , shouldEscalate};