const { PrismaClient } = require("@prisma/client")
const express = require("express")
const app = express()
const prisma = new PrismaClient()
app.use(express.json())
const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var cors = require('cors')
app.use(cors())

const authToken = (req, res, next) => {
    console.log("1. Request Headers:", req.headers);

    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    console.log("2. Authorization Header:", authHeader);
    console.log("3. Extracted Token:", token);

    if (!token) {
        return res.status(401).json({ message: "Token not valid. Please log in." });
    }

    jwt.verify(token, "jarom", (err) => {
        if (err) {
            return res.status(403).json({ message: "Token is invalid or expired." });
        }
        next();
    });
};

app.post("/register", async (req, res) => {
    const userdata = req.body

    const existinguser = await prisma.user.findUnique({
        where: {
            email: userdata.email
        }
    })
    if (existinguser === null) {

        const hashedpassword = await bcrypt.hash(userdata.password, 10)

        const newuser = await prisma.user.create({
            data: {
                name: userdata.name,
                email: userdata.email,
                password: hashedpassword
            }
        })
        res.json({
            message: "new user created",
            newuser
        })

    } else {
        res.json({
            message: "go login first"
        })
    }


})

app.post('/login', async (req, res) => {
    const userdata = req.body
    const existinguser = await prisma.user.findUnique({
        where: {
            email: userdata.email
        }
    })
    if (existinguser === null) {
        res.json({
            message: "go register first"
        })
    } else {

        const user = await bcrypt.compare(userdata.password, existinguser.password)

        if (user) {
            const { password, ...userdata } = existinguser
            var accesstoken = jwt.sign({ user_id: existinguser.user_id }, 'jarom', {
                expiresIn: '30s'
            });
            var refreshtoken = jwt.sign({ user_id: existinguser.user_id }, 'jarom', {
                expiresIn: '60s'
            });
            await prisma.token.create({
                data: {
                    user_id: existinguser.user_id,
                    refreshtoken: refreshtoken

                }
            })
            res.json({
                message: 'loged in',
                userdata,
                token: {
                    accesstoken,
                    refreshtoken
                }
            })
        } else {
            res.json({
                message: "invalid user and password"
            })
        }


    }
})

app.post('/refresh', async (req, res) => {
    const userdata = req.body
    const tokenvalid = await prisma.token.findFirst({
        where: {
            refreshtoken: userdata.refreshtoken
        }
    })
    if (!tokenvalid) {
        res.json({
            message: "token not available"
        })
    } else {
        jwt.verify(tokenvalid.refreshtoken, 'jarom', function (err) {
            if (err) {
                res.json({
                    message: "token is invalid"
                })
            } else {

                var accesstoken = jwt.sign({ user_id: tokenvalid.user_id }, 'jarom', {
                    expiresIn: '30s'
                });
                res.json({
                    accesstoken
                })
            }
        });
    }
})

app.post('/project', authToken, async (req, res) => {
    const userdata = req.body
    const newproject = await prisma.project.create({
        data: {
            id: Number(userdata.id),
            name: userdata.name,
            age: userdata.age
        }
    })
    res.json({
        message: "project added",
        newproject
    })
})

app.get("/project", authToken, async (req, res) => {
    const projectinfo = await prisma.project.findMany()
    res.json({
        data: projectinfo
    })
})




app.listen(9000)