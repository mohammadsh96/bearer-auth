'use strict';
const express = require('express');
const signinRouters=express.Router();
const basicAuth=require('../middlewear/basic');
const logger=require("../middlewear/logger");

signinRouters.post('/signin',basicAuth,(req,res)=>{
res.status(200).json(req.user);
})
signinRouters.use(logger);

module.exports=signinRouters;