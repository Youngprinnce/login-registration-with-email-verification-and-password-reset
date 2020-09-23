require('dotenv').config();
const express = require('express');
const routes = require('./routes/routes');
const InitiateMongoServer = require('./config/db');

const app = express();

//Initiate Mongo Server
InitiateMongoServer();

//Express Configuration
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Read the host address and the port from the environment
const hostname = process.env.HOST;
const port = process.env.PORT;

//Routes
routes(app);

// Start a TCP server listening for connections on the given port and host
app.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
