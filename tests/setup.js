import mongoose from 'mongoose'
import * as dotenv from 'dotenv'
dotenv.config()

const connectTestDB = async () => {
    await mongoose.connect(process.env.MONGO_URL_TEST)
}

const disconnectTestDB = async () => {
    await mongoose.connection.dropDatabase() // Clean up the test database after tests
    await mongoose.connection.close()
}

export { connectTestDB, disconnectTestDB }