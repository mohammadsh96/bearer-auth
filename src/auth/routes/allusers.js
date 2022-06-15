'use strict';
const express = require('express');
const getUsersRouters=express.Router();
const {users}=require('../model/user.model');
const bearerAuth = require('../middlewear/bearer');
const logger=require("../middlewear/logger");

getUsersRouters.get('/users',bearerAuth,async(req,res,next)=>{
    try {
        const userRecords = await users.findAll({});
        const UserNameOnly = userRecords.map(user => user.username);
        res.status(200).json(UserNameOnly);
      } catch (e) {
        console.error(e);
        next(e);
      }
})

getUsersRouters.use(logger);
module.exports=getUsersRouters;