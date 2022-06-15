'use strict';
process.env.SECRET = "TEST_SECRET";

const base64 = require('base-64');
const middleware = require('../src/auth/middlewear/basic');

const users=require("../src/auth/model/user.model");
process.env.SECRET = "TEST_SECRET";
const { app } = require('../src/server'); 
const supertest = require('supertest');
const { sequelize } = require('../src/auth/model/index.model');

const mockRequest = supertest(app);

let userData = {
  testUser: { username: 'user', password: 'password' },
};
let accessToken = null;

beforeAll(async () => {
  await sequelize.sync();
});
afterAll(async () => {
  await sequelize.drop();
});

describe('Auth Router', () => {

  it('add a new user', async () => {

    const response = await mockRequest.post('/signup').send(userData.testUser);
    const userObject = response.body;

    expect(response.status).toBe(201);
    expect(userObject.token).toBeDefined();
    expect(userObject.id).toBeDefined();
    expect(userObject.username).toEqual(userData.testUser.username);
  });

  it(' signin at basicauth', async () => {
    let { username, password } = userData.testUser;

    const response = await mockRequest.post('/signin')
      .auth(username, password);

    const userObject = response.body;
    expect(response.status).toBe(200);
    expect(userObject.token).toBeDefined();
    expect(userObject.id).toBeDefined();
    expect(userObject.username).toEqual(username);
  });

  it('signin user at bearer auth token', async () => {
    let { username, password } = userData.testUser;

   
    const response = await mockRequest.post('/signin')
      .auth(username, password);

    accessToken = response.body.token;

    
    const bearerResponse = await mockRequest
      .get('/users')
      .set('Authorization', `Bearer ${accessToken}`);

    
    expect(bearerResponse.status).toBe(200);
  });

  it(' wrong password  or username ', async () => {

    const response = await mockRequest.post('/signin')
      .auth('admin', 'xyz')
    const { user, token } = response.body;

    expect(response.status).toBe(403);
    expect(response.text).toEqual("Invalid Signin");
    expect(user).not.toBeDefined();
    expect(token).not.toBeDefined();
  });

  it('not signup username', async () => {

    const response = await mockRequest.post('/signin')
      .auth('nobody', 'xyz')
    const { user, token } = response.body;

    expect(response.status).toBe(403);
    expect(response.text).toEqual("Invalid Signin");
    expect(user).not.toBeDefined();
    expect(token).not.toBeDefined();
  });

  it(' invalid token', async () => {

  
    const response = await mockRequest.get('/users')
      .set('Authorization', `Bearer foobar`)
    const userList = response.body;

   
    expect(response.status).toBe(403);
    expect(response.text).toEqual("Invalid Signin");
    expect(userList.length).toBeFalsy();
  });

  it(' valid token', async () => {

    const response = await mockRequest.get('/users')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(response.status).toBe(200);
    expect(response.body).toBeTruthy();
    expect(response.body).toEqual(expect.anything());
  });

  it('Secret Route fails with invalid token', async () => {
    const response = await mockRequest.get('/secret')
      .set('Authorization', `bearer accessgranted`);

    expect(response.status).toBe(403);
    expect(response.text).toEqual("Invalid Signin");
  });
});
let userInfo = {
    admin: { username: 'admin-basic', password: 'password' },
  };
  
  
  beforeAll(async () => {
    await sequelize.sync();
 
  });
  afterAll(async () => {
    await sequelize.drop();
  });
  
  describe('Auth Middleware', () => {
  
    
    const req = {};
    const res = {
      status: jest.fn(() => res),
      send: jest.fn(() => res),
    }
    const next = jest.fn();
  
    describe('user authentication', () => {
  
      it('loger test', () => {
        const basicAuthString = base64.encode('username:password');
  
        
        req.headers = {
          authorization: `Basic ${basicAuthString}`,
        };
  
          middleware(req, res, next)
          .then(() => {
            expect(next).not.toHaveBeenCalled();
            expect(res.status).not.toHaveBeenCalledWith(200);
          });
  
      });
  
      it('admin login', () => {
        let basicAuthString = base64.encode(`${userInfo.admin.username}:${userInfo.admin.password}`);
  
        
        req.headers = {
          authorization: `Basic ${basicAuthString}`,
        };
  
         middleware(req, res, next)
          .then(() => {
            expect(next).not.toHaveBeenCalledWith("Invalid Signin");
          });
  
      });
    });
  });
  