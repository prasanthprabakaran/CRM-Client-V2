import mongoose from "mongoose";

// const MONGO_URL = process.env.MONGO_URL;
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);

    console.log("MongoDB is Connected 👍😊");
  } catch (err) {
    console.log(err);
  }
};

export default connectDB;
