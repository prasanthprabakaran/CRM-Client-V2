import mongoose from 'mongoose'

const connectTestDB = async () => {
    const conn = await mongoose.connect(process.env.MONGO_URI_TEST)
    return conn
}

export default connectTestDB