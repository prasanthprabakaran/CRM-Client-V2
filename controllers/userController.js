import User from '../models/User.js'
import Task from '../models/Task.js'
import bcrypt from 'bcrypt'
import asyncHandler from '../middleware/asyncHandler.js'

// @desc Get all users
// @route GET /users
// @access Private
export const getAllUsers = asyncHandler(async (req, res) => {
    const users = await User.find().select('-password').lean()

    if (!users?.length) {
        return res.status(400).json({ message: 'No users found' })
    }

    res.json(users)
})

// @desc Create new user
// @route POST /users
// @access Private
export const createNewUser = asyncHandler(async (req, res) => {
    const { username, firstname, lastname, email, password, roles } = req.body

    const duplicate = await User.findOne({ email }).lean().exec()

    if (duplicate) {
        return res.status(409).json({ message: 'Duplicate user' })
    }

    const NO_OF_ROUNDS = 10
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
    const hashedPwd = await bcrypt.hash(password, salt)

    const userObject = (!Array.isArray(roles) || !roles.length)
        ? { username, firstname, lastname, email, password: hashedPwd }
        : { username, firstname, lastname, email, password: hashedPwd, roles }

    const user = await User.create(userObject)

    if (user) {
        res.status(201).json({ message: `New user ${username} created` })
    } else {
        res.status(400).json({ message: 'Invalid user data received' })
    }
})

// @desc Update a user
// @route PATCH /users/:id
// @access Private
export const updateUser = asyncHandler(async (req, res) => {
    const { id } = req.params
    const { username, roles, active, password } = req.body

    const user = await User.findById(id).exec()

    if (!user) {
        return res.status(404).json({ message: 'User not found' })
    }

    const duplicate = await User.findOne({ username })
        .collation({ locale: 'en', strength: 2 })
        .lean()
        .exec()

    if (duplicate && duplicate?._id.toString() !== id) {
        return res.status(409).json({ message: 'Duplicate username' })
    }

    user.username = username
    user.roles = roles
    user.active = active

    if (password) {
        user.password = await bcrypt.hash(password, 10)
    }

    const updatedUser = await user.save()

    res.json({ message: `${updatedUser.username} updated` })
})

// @desc Delete a user
// @route DELETE /users/:id
// @access Private
export const deleteUser = asyncHandler(async (req, res) => {
    const { id } = req.params

    const task = await Task.findOne({ user: id }).lean().exec()
    if (task) {
        return res.status(400).json({ message: 'User has assigned tasks' })
    }

    const user = await User.findById(id).exec()

    if (!user) {
        return res.status(404).json({ message: 'User not found' })
    }

    const result = await user.deleteOne()

    res.json({ message: `Username ${result.username} with ID ${result._id} deleted` })
})

const userController = { getAllUsers, createNewUser, updateUser, deleteUser }

export default userController