//Imports
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

const app = express()

// Config JSON response
app.use(express.json())

//Models
const User = require('./models/User');

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({ message: "Hello, Welcome to our API" })
})

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.peg2eqq.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp`
  )
  .then(() => {
    app.listen(3000)
    console.log('Connected to Database!')
  })
  .catch((err) => console.log(err))

// Register User
app.post('/auth/register', async(req, res) => {

  const {username, email, password, confirmpassoword} = req.body

  // validations
  if(!username) {
    return res.status(400).json({ message: "Username is required" })
  }

  if(!email) {
    return res.status(400).json({ message: "Email is required" })
  }

  if(!password) {
    return res.status(400).json({ message: "Password is required" })
  }

  if(password !== confirmpassoword) {
    return res.status(400).json({ message: "Password is not match" })
  }

  // Check if user exists
  const userExist = await User.findOne({ email: email })

  if(userExist) {
    return res.status(422).json({ message: "User already exists" })
  }

  // create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // create user
  const user = new User({
    username,
    email,
    password: passwordHash,
  })

  try {

    await user.save()

    res.status(201).json({ message: "User created successfully" })

  } catch(error) {
    console.log(error)
    res.status(500).json({message: "A server error occurred, please try again later!" })
  }
})

// Login User
app.post("/auth/login", async(req, res) => {
  const { username, password} = req.body

  //validations
  if(!username) {
    return res.status(400).json({ message: "Username is required" })
  }

  if(!password) {
    return res.status(400).json({ message: "Password is required" })
  }

  // check if user exist
  const user = await User.findOne({ username: username })

  if(!user){
    return res.status(404).json({ message: "Invalid credentials" })
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if(!checkPassword) {
    return res.status(422).json({ message: "Invalid credentials" })
  }

  try {
    const secret = process.env.secret
    const token = jwt.sign(
      {
      id: user._id,
      },
      secret
    )

    res.status(200).json({ message: "User logged successfully", token: token })

  } catch (err) {
    console.log(err)
    res.status(500).json({ message: "A server error occurred, please try again later!" })
  }

})

// Private Route
app.get("/user/:id", checkToken ,async(req, res) => {

  const id = req.params.id

  // check if user exist
  const user = await User.findById(id, '-password')

  if(!user) {
    return res.status(404).json({ message: "User not found" })
  }

  res.status(200).json({ user })

})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token) {
    return res.status(401).json({ message: "You are not authenticated" })
  }

  try{
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
  }catch(error) {
    res.status(400).json({msg: "Invalid Token"})
  }
}
