require('dotenv').config();
require('./config/database.js').connect();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const User = require("./model/User.js");
const auth = require("./middleware/auth.js");

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
    res.send("<h1>Hello Abhishek</h1>");
})

app.post("/register", async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;
        if (!(firstname && lastname && email && password)) {
            res.status(400).json("All the fields are mandatory");
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(401).json("User already exists");
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            firstname,
            lastname,
            email,
            password: hashedPassword
        })
        const token = jwt.sign(
            { user_id: user._id },
            process.env.SECRET_KEY,
            { expiresIn: "3h" }
        )
        user.token = token;
        user.password = undefined;
        res.status(201).json(user);
    } catch (error) {
        console.log(error);
    }
})


app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!(email && password)) {
            res.status(400).json("All the fields are mandatory.");
        }
        const user = await User.findOne({ email });
        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                { user_id: user._id, email },
                process.env.SECRET_KEY,
                { expiresIn: "3h" }
            );
            user.token = token;
            user.password = undefined;
            // res.status(200).json(user);

            //setting up token in cookie
            const options = {
                expires: new Date(Date.now() + 7 * 60 * 60 * 1000),
                httpOnly: true
            }
            res.status(200).cookie("token", token, options).json({
                success: true,
                token,
                user
            })
        }
        res.status(400).json("Invalid email or password.");
    } catch (error) {
        console.log(error);
    }
})

app.get("/logout", auth, (req, res) => {
    res.clearCookie("token");
    res.status(200).json({
        success: true,
        message: "Logged out successfully"
    })
})

app.get("/dashboard", auth, async (req, res) => {
    res.send("Welcome to sensitive information");
})


module.exports = app;
