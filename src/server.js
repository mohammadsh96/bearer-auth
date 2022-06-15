'use strict';
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const express = require("express");
const app = express();

const notFoundHandler = require("./handlers/404");
const errorHandler = require("./handlers/500");

const signinRouters=require("./auth/routes/signin");
const signupRouters=require("./auth/routes/signup");
const secretRouters=require("./auth/routes/secret");
const getUsersRouters=require("./auth/routes/allusers");

app.use(express.json());
app.use(signinRouters);
app.use(signupRouters);
app.use(secretRouters);
app.use(getUsersRouters);

app.use("*", notFoundHandler);
app.use(errorHandler); 

function start(PORT) {
    app.listen(PORT, () => {
        console.log(`Listen and Running on port ${PORT}`);
    });
}

module.exports = {
    app: app,
    start: start,
};