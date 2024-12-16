const dotenv = require('dotenv');
dotenv.config(); 
const mongoose = require('mongoose')

const Db = process.env.MONGODB_URI;


const connectToDatabase  = async () => {
  try {
    await mongoose.connect(Db,{
      serverSelectionTimeoutMS: 5000, 
    })
    console.log('Connected to MongoDB successfully!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error.message);
  }
}
connectToDatabase ();

