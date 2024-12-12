const mongoose = require('mongoose')

const userSchema =  new mongoose.Schema({
  name:String,
  password: String,
  googleId:String,
  displayName:String,
  email:String,
  image:String,
},{timestamps:true});

const userDb = mongoose.model("users",userSchema)

module.exports = userDb