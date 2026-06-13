import express from 'express'
const router = express.Router()
import tasksController from '../controllers/tasksController.js'
import verifyJWT from '../middleware/verifyJWT.js'
import validate from "../middleware/validate.js"
import { createTaskSchema, updateTaskSchema } from "../validators/taskSchemas.js"

router.use(verifyJWT)

router.route('/')
    .get(tasksController.getAllTasks)
    .post(validate(createTaskSchema), tasksController.createNewTask)

router.route('/:id')
    .patch(validate(updateTaskSchema), tasksController.updateTask)
    .delete(tasksController.deleteTask)

export const tasksRouter = router