'use strict';
const express = require('express');
const secretRouters=express.Router();
const bearerAuth=require('../middlewear/bearer');
const logger=require("../middlewear/logger");

secretRouters.get('/secret',bearerAuth,(req,res)=>{
    res.status(200).json({
        'message': 'You are authorized to view the user orders',
        'user': req.user
    });})

    secretRouters.use(logger);

module.exports=secretRouters;