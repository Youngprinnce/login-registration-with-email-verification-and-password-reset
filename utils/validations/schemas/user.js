const joi = require('joi');

const loginSchema = joi.object().keys({
  email: joi.string().email().required().label('Email').trim(),
  password: joi.string().required().min(6).trim().label('Password'),
});

const registrationSchema = joi.object().keys({
  email: joi.string().email().required().label('Email').trim(),
  name: joi.string().required().alphanum().min(5).max(30).trim(),
  password: joi
    .string()
    .required()
    .min(8)
    .trim()
    .regex(/^(?:(?=.*\d)(?=.*[A-Z]).*)$/)
    .label('Password')
    .trim(),
});

module.exports = {
  loginSchema,
  registrationSchema,
};
