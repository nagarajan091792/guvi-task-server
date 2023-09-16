const express = require('express');
const as = express();
const cors = require('cors');
const mongodb = require('mongodb');
const mongoClient = mongodb.MongoClient;
const dotenv = require('dotenv').config();
const URL = process.env.DB;
const bcryptjs = require('bcryptjs');
const jwt = require("jsonwebtoken");
const SECRET=process.env.SECRET;

as.use(express.json());
as.use(cors({
    orgin: "*"
}));

//Authorize-------------------------------------------------------------
const authenticate = (req, res, next) => {
  try {
    if (req.headers.authorization) {
      let decodedToken = jwt.verify(req.headers.authorization, SECRET);
      if (decodedToken) {
        req.userid = decodedToken._id;
        next();
      } else {
        res.status(401).json({ message: "Unauthorized" });
      }
    } else {
      res.status(401).json({ message: "Invaild Token" });
    }
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};
 
 
 
//login---------------------------------//
as.post("/", async function (req, res) {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db("guvi_task");
        const temp = await db.collection("users").findOne({ email: req.body.email })
        if (temp) {
            const match = await bcryptjs.compare(req.body.password, temp.password);
            if (match) {
                const token = jwt.sign({ _id: temp._id }, SECRET,{expiresIn:"90min"});
                console.log(token)
                res.json({ message: "successfully logged in", token ,id:temp._id,profile:temp.username})
            } else {
                res.json({ message: "incorrect password" })
            }
        } else { res.json({ message: "user not found,Kindly register before logging in" }) }
        await connection.close();

    } catch (error) {
        console.log(error);
    }
})
//register-------------------------------//
as.post("/register", async function (req, res) {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db("guvi_task");
        const oldUser = await db
        .collection("users")
        .findOne({ email: req.body.email });
      if (oldUser) {
        return res.json({ message: "User Already Exists!!" });
      }
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        req.body.password = hash;
        await db.collection("users").insertOne(req.body);
        await connection.close();
        res.json({
            message: "user registered added successfully"
        })
    } catch (error) {
        console.log(error);
    }
})


as.get("/", (req, res) =>
  res.send(`Server Active`)
);

as.listen(process.env.PORT || 5000,() => console.log(`Server Active`));