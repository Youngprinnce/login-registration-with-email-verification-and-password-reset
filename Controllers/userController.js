const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const mailgun = require('mailgun-js');
const { sendSuccess, sendError } = require('../utils/responseHandler');

const regController = async (req, res) => {
  // VALIDATE USER BEFORE SAVE
  const { error, value } = await User.regValidations(req.body);
  if (error) {
    return sendError(res, error.details[0].message);
  }

  //Destructure filtered value...
  const { name, email } = value;

  //CHECK IF EMAIL EXIST IN THE DATABASE
  const emailExist = await User.findOne({ email });
  if (emailExist) {
    const message = 'Email already exist, try another one';
    return sendError(res, [], message);
  }

  // CREATE AND ASSIGN A TOKEN
  const token = jwt.sign(value, process.env.TOKEN_SECRET, { expiresIn: '20m' });

  // CREATE EMAIL VERICATION MESSAGE
  const link = `<div>
      <p>Hey ${name}

      <p>Click this link to verify email address</>

      <p>${process.env.CLIENT_URL}/api/activation/${token}</p>

      <p>All The Best</p>
    </div>
    `;

  //EMAIL CONFIGURATION
  const mg = await mailgun({
    apiKey: process.env.MAILGUN_API_KEY,
    domain: process.env.MAILGUN_DOMAIN,
  });
  const data = {
    from: '"youngprinnce 👻" <' + process.env.EMAIL_ADDRESS + '>', // sender address
    to: `${email}`, // list of receivers
    subject: 'Verification Link ✔', // Subject line
    text: 'hello', // plain text body
    html: link,
  };
  await mg.messages().send(data, (err, body) => {
    if (err) {
      return res.status(400).json({ error: err });
    } else {
      const message = `Verification token has been sent to ${email}`;
      return sendSuccess(res, [], message);
    }
  });
};

const loginController = async (req, res) => {
  // VALIDATE USER BEFORE SAVE
  const { error, value } = await User.loginValidations(req.body);
  if (error) {
    return sendError(res, error.details[0].message);
  }

  const { email, password } = value;

  //CHECK IF EMAIL EXIST IN THE DATABASE
  const user = await User.findOne({ email });
  if (!user) {
    const message = 'Email not found';
    return sendError(res, [], message);
  }

  //CHECK FOR PASSWORD BCRYPT
  const validPass = await user.comparePassword(password);
  if (!validPass) {
    const message = 'Invalid password';
    return sendError(res, [], message);
  }

  const message = 'Login Successful';
  return sendSuccess(res, [], message);
};

const activationController = async (req, res) => {
  //Retrive token from URL
  const token = req.params.token;

  //Verify token
  const verified = jwt.verify(token, process.env.TOKEN_SECRET);
  if (!verified) {
    const message = 'Incorrect or expired link! Register again';
    return sendError(res, [], message);
  }

  //Destructure email from...
  const { email } = verified;

  //CHECK IF EMAIL EXIST IN THE DATABASE
  const emailExist = await User.findOne({ email });
  if (emailExist) {
    const message = 'Email already exist, try another one';
    return sendError(res, [], message);
  }

  //Else, save new user to database
  const user = new User({ ...verified });

  try {
    await user.save();
    const message = 'SignUp Success';
    return sendSuccess(res, [], message);
  } catch (err) {
    const message = 'Registration failed';
    return sendError(res, [], message);
  }
};

const forgotPasswordController = async (req, res) => {
  const { email } = req.body;

  //CHECK IF EMAIL EXIST IN THE DATABASE
  const user = await User.findOne({ email });
  if (!user) {
    const message = 'User with this email does not exist';
    return sendError(res, [], message);
  }

  // CREATE AND ASSIGN A TOKEN
  const token = jwt.sign({ _id: user._id }, process.env.FORGOT_PASSWORD_TOKEN, {
    expiresIn: '20m',
  });

  // CREATE EMAIL PASSWORD RESET MESSAGE
  const link = `<div>

      <p>Click this link to reset password</>

      <p>${process.env.CLIENT_URL}/api/resetpassword/${token}</p>

      <p>All The Best</p>
    </div>
    `;

  //EMAIL CONFIGURATION
  const mg = await mailgun({
    apiKey: process.env.MAILGUN_API_KEY,
    domain: process.env.MAILGUN_DOMAIN,
  });

  const data = {
    from: '"youngprinnce 👻" <' + process.env.EMAIL_ADDRESS + '>', // sender address
    to: `${email}`, // list of receivers
    subject: 'Password rest Link ✔', // Subject line
    text: 'hello',
    html: link, // plain text body
  };

  const resetLink = await User.updateOne({ resetLink: token });
  if (!resetLink) {
    const message = 'reset password link error';
    return sendError(res, [], message);
  }

  try {
    await mg.messages().send(data);
    const message = `Password reset link has been sent to ${email}`;
    return sendSuccess(res, [], message);
  } catch (error) {
    const message = 'reset password link error';
    return sendError(res, [err], message);
  }
};

const resetPasswordController = async (req, res) => {
  //Retrive token from URL
  const token = req.params.token;
  const password = req.body.password;

  //Verify token
  const verified = await jwt.verify(token, process.env.FORGOT_PASSWORD_TOKEN);
  if (!verified) {
    const message = 'Incorrect or Expired Link! Register Again';
    return sendError(res, [], message);
  }


  if (!verified) {
    const message = 'Incorrect or Expired Link! Register Again';
    return sendError(res, [], message);
  }

  //Destructure user data from...
  const { _id } = verified;

  //Check user with token
  const user = await User.findOne({ resetLink: token });
  if (!user) {
    const message = 'User with this token does not exist';
    return sendError(res, [err], message);
  }

  //HASH USER PASSWORD USING BCRYPT
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  //Update Password
  const updatePassword = await User.findByIdAndUpdate({ _id }, { password: hashedPassword });
  if (!updatePassword) {
    const message = 'Error reseting password';
    return sendError(res, [], message);
  }

  const message = `Your password has been changed`;
  return sendSuccess(res, [], message);
};

module.exports = {
  regController,
  loginController,
  activationController,
  forgotPasswordController,
  resetPasswordController,
};
