import express from 'express'
const router = express.Router();
import tasksController from '../controllers/tasksController.js';
import verifyJWT from '../middleware/verifyJWT.js';

router.use(verifyJWT)

router.route('/')
    .get(tasksController.getAllTasks)
    .post(tasksController.createNewTask)
    .patch(tasksController.updateTask)
    .delete(tasksController.deleteTask)

export const tasksRouter = router