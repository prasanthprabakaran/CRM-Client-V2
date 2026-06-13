import Task from '../models/Task.js'
import User from '../models/User.js'
import asyncHandler from '../middleware/asyncHandler.js'

// @desc Get all tasks
// @route GET /tasks
// @access Private
export const getAllTasks = asyncHandler(async (req, res) => {
    const tasks = await Task.find().lean()

    if (!tasks?.length) {
        return res.status(400).json({ message: 'No tasks found' })
    }

    const tasksWithUser = await Promise.all(tasks.map(async (task) => {
        const user = await User.findById(task.user).lean().exec()
        return { ...task, username: user.username }
    }))

    res.json(tasksWithUser)
})

// @desc Create new task
// @route POST /tasks
// @access Private
export const createNewTask = asyncHandler(async (req, res) => {
    const { user, title, text } = req.body

    const duplicate = await Task.findOne({ title }).lean().exec()

    if (duplicate) {
        return res.status(409).json({ message: 'Duplicate task title' })
    }

    const task = await Task.create({ user, title, text })

    if (task) {
        return res.status(201).json({ message: 'New task created' })
    } else {
        return res.status(400).json({ message: 'Invalid task data received' })
    }
})

// @desc Update a task
// @route PATCH /tasks/:id
// @access Private
export const updateTask = asyncHandler(async (req, res) => {
    const { id } = req.params
    const { user, title, text, completed } = req.body

    const task = await Task.findById(id).exec()

    if (!task) {
        return res.status(404).json({ message: 'Task not found' })
    }

    const duplicate = await Task.findOne({ title }).lean().exec()

    if (duplicate && duplicate?._id.toString() !== id) {
        return res.status(409).json({ message: 'Duplicate task title' })
    }

    task.user = user
    task.title = title
    task.text = text
    task.completed = completed

    const updatedTask = await task.save()

    res.json({ message: `'${updatedTask.title}' updated` })
})

// @desc Delete a task
// @route DELETE /tasks/:id
// @access Private
export const deleteTask = asyncHandler(async (req, res) => {
    const { id } = req.params

    const task = await Task.findById(id).exec()

    if (!task) {
        return res.status(404).json({ message: 'Task not found' })
    }

    const result = await task.deleteOne()

    res.json({ message: `Task '${result.title}' with ID ${result._id} deleted` })
})

const tasksController = { getAllTasks, createNewTask, updateTask, deleteTask }

export default tasksController