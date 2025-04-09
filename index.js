const express = require('express')
const mongoose  = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const authMiddleware = require('./auth.middleware')

require('dotenv').config()
const app = express()

app.use(express.json())
app.use(cookieParser())

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    }
})

const User = mongoose.model("User", userSchema)


app.post('/register', async(req,res) => {
    try {
        const {username, password, role} = req.body
        const hashedPassword = await bcrypt.hash(password, 10)
        const newUser =  User({username, password:hashedPassword , role})
        await newUser.save()
        return res.status(200).send(newUser.role, "Created Successfully")
    } catch (error) {
        return res.status(200).send(error.message)
    }
})

app.post('/login', async(req,res) => {
    try {
        const {username, password} = req.body
        const user = await User.findOne({username})
        const isAuthenticated = await bcrypt.compare(password, user.password)
        if(!isAuthenticated){
            return res.status(200).send("Login Failed")
        }
        const token = jwt.sign({id: user._id, role: user.role}, process.env.JWT_SECRET, {expiresIn: '7d'})
        res.cookie("token", token, {
            maxAge: 7 * 60 * 60 * 1000,
            httpOnly: true,
            secure: false
        })

        return res.status(200).send("Logged in Successfully")
    } catch (error) {
        return res.status(200).send(error.message)
    }
})

app.get('/user',authMiddleware, async(req,res) => {
    try {
        const role = req.user.role
        console.log("Role", role)
        if(role != "user"){
            return res.status(404).send("404 Error")
        }
        return res.status(200).json({message:"Welcome User"})
    } catch (error) {
        return res.send(error.message)
    }
})
app.get('/admin',authMiddleware, async(req,res) => {
    try {
        const role = req.user.role
        if(role != "admin"){
            return res.status(404).send("404 Error")
        }
        return res.status(200).json({message:"Welcome Admin"})
    } catch (error) {
        res.send(error.message)
    }
})

app.listen(process.env.PORT, () => {
    try {
        mongoose.connect(process.env.MONGO_URI)
        .then(()=> console.log("Database connected Successfully"))
        .catch(err => console.log(err))
        console.log("Server is Running ...")
    } catch (error) {
        console.error(error.message)
    }
})