import express from 'express';
const router = express.Router();
import { getPrivateRoute } from '../controllers/private.js';
import protect from '../middleware/auth.js';

router.route("/").get(protect, getPrivateRoute);

export const privateRouter = router;