require("dotenv").config({ path: __dirname + "/.env" });
const express = require("express");
const cors = require("cors");

//JWT is meant for authorizing requests, and not encrypting data
//It is to verify the sender and the data has not been altered along the way
const jwt = require("jsonwebtoken");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");

dotenv.config();

const userService = require("./user-service.js");

const app = express();

const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

// JSON Web Token Setup
var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

// Configure its options
var jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt");

// IMPORTANT - this secret should be a long, unguessable string
// (ideally stored in a "protected storage" area on the
// web server, a topic that is beyond the scope of this course)
// We suggest that you generate a random 64-character string
// using the following online tool:
// https://lastpass.com/generatepassword.php

jwtOptions.secretOrKey = process.env.JWT_SECRET;

var strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  console.log("payload received", jwt_payload);

  if (jwt_payload) {
    // The following will ensure that all routes using
    // passport.authenticate have a req.user._id, req.user.userName, req.user.userName & req.user.password
    // that matches the request payload data
    next(null, {
      _id: jwt_payload._id,
      userName: jwt_payload.userName,
      password: jwt_payload.password,
    });
  } else {
    next(null, false);
  }
});
//Tell passport to use our "strategy"
passport.use(strategy);
//Add passport as application-level middleware
app.use(passport.initialize());
//Connect to database using user service
userService
  .connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log("API listening on: " + HTTP_PORT);
    });
  })
  .catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
  });
/* TODO Add Your Routes Here */

//---------------------------------------------------- REGISTER -----------------------------------------------------
app.post("/api/user/register", function (req, res) {
  console.log(req.body);
  userService
    .registerUser(req.body)
    .then((data) => {
      console.log(data);
      res.json({ msg: data });
    })
    .catch((err) => {
      //The 422 error code communicates back to the client that
      //the server understands the content type of the request and the syntax is correct but was unable to process the data
      console.log(err);
      res.status(422).json({ Error: err });
    });
});

//---------------------------------------------------- LOGIN -----------------------------------------------------
//POST route responsible for validating the user from the body of the request
//Generate token to be sent in reponse by invoking .checkUser() method of userService
app.post("/api/user/login", function (req, res) {
  userService
    .checkUser(req.body)
    .then((user) => {
      //If userObj is returned generate a payload obj that has two properties:_id and userName.

      //create two const variables, privat key and payload object
      let payload = {
        _id: user._id,
        userName: user.userName,
        password: user.password,
      };

      //Create a JWT once private key and payload object have been created
      const token = jwt.sign(payload, process.env.JWT_SECRET);

      res.status(200).json({ message: "Login Successful", token: token });
    })
    .catch((err) => {
      res.status(422).json({ msg: "Error 422: User not found." });
    });
});

//Protected using the passport.authenticate() middleware
//GET the users favourites using a get request to the USER service
app.get(
  "/api/user/favourites",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .getFavourites(req.user._id)
      .then((data) => {
        console.log(data);
        res.json(data);
      })
      .catch((err) => {
        res.json({ msg: err });
      });
  }
);
//This route is responsible for adding a specific favourite, send as the 'id' route paramter
//to the user's list of favourites only if they provided a valid JWT
//PUT
app.put(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    //user id as first param, and route parameter as the second param
    userService
      .addFavourite(req.user._id, req.params.id)
      .then((data) => {
        res.json(data);
      })
      .catch((err) => {
        res.status(404).json({ msg: err });
      });
  }
);

//DELETE
app.delete(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .removeFavourite(req.user._id, req.params.id)
      .then((data) => {
        res.status(200).json(data);
      })
      .catch((err) => {
        res.json({ msg: err });
      });
  }
);
