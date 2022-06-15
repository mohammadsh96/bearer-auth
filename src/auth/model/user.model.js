'use strict';

require("dotenv").config();
const {sequelize,DataTypes}=require("./index.model");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET = process.env.API_SECRET || "mohammadsh96";

const users = 
    sequelize.define("users", {
        username: {
            type: DataTypes.STRING,
            allowNull: false,
            unique : true,
        },
        password: {
            type: DataTypes.STRING,
            allowNull: true,
          },
          token: {
            type: DataTypes.VIRTUAL,
            get() {return jwt.sign({ username: this.username }, SECRET);
          }
    }},{ 
        sequelize,
        tableName: 'users',
        timestamps: false,
        });

users.authenticateBasic = async function (username, password) {
    const user = await users.findOne({ where: { username: username } })
    const valid = await bcrypt.compare(password, user.password)
    if (valid) {
        let newToken = jwt.sign({ username: user.username }, SECRET,{expiresIn : '15 min'});//reqire a new token in 15 min
        // console.log('************************', newToken);
        user.token = newToken;
        return user;
    }
    else {
        throw new Error("Invalid user");
    }
}

users.authenticateBearer = async function (token) {
    const parsedToken = jwt.verify(token, SECRET);
    console.log('parsedToken >>>>>>>>>>>>>>>>>>', parsedToken);
    const user = await users.findOne({ where: { username: parsedToken.username } });
    if (user.username) {
        return user;
    } else {
        throw new Error("Invalid Token");
    }
}

module.exports = {users:users};