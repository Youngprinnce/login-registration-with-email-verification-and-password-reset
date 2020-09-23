const users = require('./users');
const routes = (app) => {
  app.use('/api', users());
};

module.exports = routes;
