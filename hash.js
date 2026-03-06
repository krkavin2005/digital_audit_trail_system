const bcrypt = require("bcrypt");
const {randomUUID} = require("crypto");

bcrypt.hash("auditor123", 10).then(hash => {
    console.log(hash);
});
const id = randomUUID();
console.log((id));
