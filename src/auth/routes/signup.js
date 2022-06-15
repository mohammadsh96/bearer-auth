'use strict';
const express = require('express');
const signupRouters=express.Router();
const {users}=require('../model/user.model');
const bcrypt = require('bcrypt');
const logger=require("../middlewear/logger");

signupRouters.get('/',(req,res)=>{
    res.send("use /signup , signin , ");
})
signupRouters.post('/signup',async(req,res)=>{
    try {
        req.body.password = await bcrypt.hash(req.body.password, 10);
        const record = await users.create(req.body);
        res.status(201).json(record);
      } catch (e) { res.status(403).send('this username is already used , try again'); }

})
signupRouters.use(logger);
module.exports=signupRouters;
