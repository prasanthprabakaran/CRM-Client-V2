import User from '../models/User.js'
import Task from '../models/Task.js'
import bcrypt from 'bcrypt'

// @desc Get all users
// @route GET /users
// @access Private

export const getAllUsers = async (req,res) => {
     // Get all users from MongoDB
     const users = await User.find().select('-password').lean()

     // If no users
     if(!users?.length) {
        return res.status(400).json({ message: 'No users found'})
     }

     res.json(users)
}



// @desc Create new user
// @route POST /users
// @access Private

export const createNewUser = async (req,res) => {
    const { username,firstname,lastname,email,password,roles } =req.body;

    //Confirm data
    if(!username || !password || !email || !firstname ) {
        return res.status(400).json({ message: 'All fields are required'})
    }

    // Check for duplicate
    const duplicate = await User.findOne({email}).lean().exec()

    if(duplicate) {
        return res.status(409).json({message: 'Duplicate user'})
    }

    // Hash password
    const NO_OF_ROUNDS = 10
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
    const hashedPwd = await bcrypt.hash(password, salt)

    const userObject = (!Array.isArray(roles) || !roles.length)
    ? { username, firstname, lastname, email, "password": hashedPwd }
    : { username, firstname, lastname, email, "password": hashedPwd, roles }

    // Create and store new user
    const user = await User.create(userObject)

    if (user) {
        res.status(201).json({ message: `New user ${username} created`})
    } else {
        res.status(400).json({ message: 'Invalid user data received' })
    }

}

// @desc Update a user
// @route PATCH /users
// @access Private

export const updateUser = async (req,res) => {
    const { id, username,roles, active, password } = req.body

    // Confirm data
    if(!id || !username || !Array.isArray(roles) || !roles.length || typeof active !== 'boolean') {
        return res.status(400).json({ message: 'All fields except password are required '})
    }

    // Does the user exist to update?
    const user = await User.findById(id).exec()

    if(!user) {
        return res.status(400).json({ message: 'User not found' })
    }

    // Check for duplicate
    const duplicate = await User.findOne({ username }).collation({ locale: 'en', strength: 2 }).lean().exec()

    // Allow updates to the original user
    if (duplicate && duplicate?._id.toString() !== id) {
        return res.status(409).json({ message: 'Duplicate username'})
    }

    user.username = username
    user.roles = roles
    user.active = active

    if(password) {
        // Hash password
        user.password = await bcrypt.hash(password, 10) // salt rounds
    }

    const updateUser = await user.save()

    res.join({ message: `${updateUser.username} updated`})

}

// @desc Delete a user
// @route DELETE /users
// @access Private

export const deleteUser = async (req,res) => {
    const { id } = req.body

    // Confirm data
    if (!id) {
        return res.status(400).json({ message: 'User ID Required' })
    }

    // Does the user still have assigned Tasks?
    const task = await Task.findOne({ user: id }).lean().exec()
    if(task) {
        return res.status(400).json({ message: 'User has assigned notes'})
    }

    // Does the user exist to delete?
    const user = await User.findById(id).exec()

    if(!user) {
        return res.status(400).json({ message: 'User not found' })
    }

    const result = await user.deleteOne()

    const reply = `Username ${result.username} with ID ${result._id} deleted`

    res.json(reply)
}

const userController = { getAllUsers,createNewUser,updateUser,deleteUser};

export default userController
