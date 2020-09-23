const express = require('express');
const router = express.Router();

const {
  activationController,
  regController,
  loginController,
  forgotPasswordController,
  resetPasswordController,
} = require('../Controllers/userController');

module.exports = () => {
  router.post('/register', regController);
  router.put('/login', loginController);
  router.get('/activation/:token', activationController);
  router.put('/forgot-password', forgotPasswordController);
  router.put('/resetpassword/:token', resetPasswordController);
  return router;
};
