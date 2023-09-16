const jwt = require("jsonwebtoken");

const auth = (req, res, next) => {
    const token = req.cookies.token || req.body.token || req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
        return res.status(403).json("Token is missing");
    }
    try {
        const decode = jwt.verify(token, process.env.SECRET_KEY);
        console.log(decode);
        //we can our own values in request
        //we can also bring informatin from db about the user using the id in decode and set that information in req.user
        req.user = decode;
    } catch (error) {
        return res.status(401).json("Invalid token");
    }
    return next();
}

module.exports = auth;