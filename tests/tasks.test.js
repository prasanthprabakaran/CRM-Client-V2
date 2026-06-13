import request from 'supertest'
import express from 'express'
import cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv'
dotenv.config()

import { connectTestDB, disconnectTestDB } from './setup.js'
import { authRouter } from '../routes/authRoutes.js'
import { tasksRouter } from '../routes/taskRoutes.js'
import errorHandler from '../middleware/errorHandler.js'
import User from '../models/User.js'
import bcrypt from 'bcrypt'

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use('/auth', authRouter)
app.use('/tasks', tasksRouter)
app.use(errorHandler)

let accessToken
let testUserId
let createdTaskId

beforeAll(async () => {
    await connectTestDB()

    // Seed a user
    const salt = await bcrypt.genSalt(10)
    const hashedPwd = await bcrypt.hash('password123', salt)
    const user = await User.create({
        username: 'taskuser',
        firstname: 'Task',
        lastname: 'User',
        email: 'taskuser@example.com',
        password: hashedPwd,
        active: true,
        roles: ['Employee']
    })

    testUserId = user._id.toString()

    // Login to get accessToken
    const res = await request(app)
        .post('/auth')
        .send({ username: 'taskuser', password: 'password123' })

    accessToken = res.body.accessToken
})

afterAll(async () => {
    await disconnectTestDB()
})

describe('GET /tasks', () => {
    it('should return 401 when not authenticated', async () => {
        const res = await request(app).get('/tasks')
        expect(res.statusCode).toBe(401)
    })

    it('should return tasks or empty message when authenticated', async () => {
        const res = await request(app)
            .get('/tasks')
            .set('Authorization', `Bearer ${accessToken}`)

        expect([200, 400]).toContain(res.statusCode)
    })
})

describe('POST /tasks', () => {
    it('should create a task with valid data', async () => {
        const res = await request(app)
            .post('/tasks')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                user: testUserId,
                title: 'Test Task',
                text: 'This is a test task'
            })

        expect(res.statusCode).toBe(201)
        expect(res.body.message).toContain('created')

        const { Task } = await import('../models/Task.js')
        const task = await Task.findOne({ title: 'Test Task' })
        createdTaskId = task._id.toString()
    })

    it('should return 409 on duplicate title', async () => {
        const res = await request(app)
            .post('/tasks')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                user: testUserId,
                title: 'Test Task',
                text: 'Duplicate title task'
            })

        expect(res.statusCode).toBe(409)
    })

    it('should return 400 when required fields are missing', async () => {
        const res = await request(app)
            .post('/tasks')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ title: 'No user or text' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })
})

describe('PATCH /tasks/:id', () => {
    it('should update a task with valid data', async () => {
        const res = await request(app)
            .patch(`/tasks/${createdTaskId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                user: testUserId,
                title: 'Updated Task',
                text: 'Updated text',
                completed: true
            })

        expect(res.statusCode).toBe(200)
        expect(res.body.message).toContain('updated')
    })

    it('should return 400 when required fields are missing', async () => {
        const res = await request(app)
            .patch(`/tasks/${createdTaskId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ title: 'Missing fields' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })
})

describe('DELETE /tasks/:id', () => {
    it('should delete a task by id', async () => {
        const res = await request(app)
            .delete(`/tasks/${createdTaskId}`)
            .set('Authorization', `Bearer ${accessToken}`)

        expect(res.statusCode).toBe(200)
        expect(res.body.message).toContain('deleted')
    })

    it('should return 404 for non-existent task', async () => {
        const mongoose = await import('mongoose')
        const fakeId = new mongoose.default.Types.ObjectId()
        const res = await request(app)
            .delete(`/tasks/${fakeId}`)
            .set('Authorization', `Bearer ${accessToken}`)

        expect(res.statusCode).toBe(404)
    })
})