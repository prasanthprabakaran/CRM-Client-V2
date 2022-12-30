import express from "express";
const router = express.Router();
import {getAllUsers,createNewUser,updateUser,deleteUser} from "../controllers/userController.js";
import verifyJWT from '../middleware/verifyJWT.js';

router.use(verifyJWT)

router
  .route("/")
  .get(getAllUsers)
  .post(createNewUser)
  .patch(updateUser)
  .delete(deleteUser);

// router.route('/register').post(register);

// router.route('/login').post(login);

// router.route('/forgetpassword').post(forgetpassword);

// router.route('/resetpassword/:resetToken').put(resetpassword);

export const userRouter = router;
