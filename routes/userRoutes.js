import express from "express"
const router = express.Router()
import { getAllUsers, createNewUser, updateUser, deleteUser } from "../controllers/userController.js"
import verifyJWT from '../middleware/verifyJWT.js'
import validate from "../middleware/validate.js"
import { createUserSchema, updateUserSchema } from "../validators/userSchemas.js"

router.use(verifyJWT)

router.route('/')
    .get(getAllUsers)
    .post(validate(createUserSchema), createNewUser)

router.route('/:id')
    .patch(validate(updateUserSchema), updateUser)
    .delete(deleteUser)

export const userRouter = router