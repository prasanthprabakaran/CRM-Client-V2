import request from 'supertest'
import express from 'express'
import cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv'
dotenv.config()

import { connectTestDB, disconnectTestDB } from './setup.js'
import { authRouter } from '../routes/authRoutes.js'
import { userRouter } from '../routes/userRoutes.js'
import errorHandler from '../middleware/errorHandler.js'
import User from '../models/User.js'
import bcrypt from 'bcrypt'

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use('/auth', authRouter)
app.use('/users', userRouter)
app.use(errorHandler)

let accessToken
let createdUserId

beforeAll(async () => {
    await connectTestDB()

    // Seed an admin user to authenticate with
    const salt = await bcrypt.genSalt(10)
    const hashedPwd = await bcrypt.hash('password123', salt)
    await User.create({
        username: 'adminuser',
        firstname: 'Admin',
        lastname: 'User',
        email: 'admin@example.com',
        password: hashedPwd,
        active: true,
        roles: ['Admin']
    })

    // Login to get accessToken
    const res = await request(app)
        .post('/auth')
        .send({ username: 'adminuser', password: 'password123' })

    accessToken = res.body.accessToken
})

afterAll(async () => {
    await disconnectTestDB()
})

describe('GET /users', () => {
    it('should return all users when authenticated', async () => {
        const res = await request(app)
            .get('/users')
            .set('Authorization', `Bearer ${accessToken}`)

        expect(res.statusCode).toBe(200)
        expect(Array.isArray(res.body)).toBe(true)
    })

    it('should return 401 when not authenticated', async () => {
        const res = await request(app).get('/users')
        expect(res.statusCode).toBe(401)
    })
})

describe('POST /users', () => {
    it('should create a new user with valid data', async () => {
        const res = await request(app)
            .post('/users')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                username: 'newuser',
                firstname: 'New',
                lastname: 'User',
                email: 'newuser@example.com',
                password: 'password123'
            })

        expect(res.statusCode).toBe(201)
        expect(res.body.message).toContain('created')

        const user = await User.findOne({ email: 'newuser@example.com' })
        createdUserId = user._id.toString()
    })

    it('should return 409 on duplicate email', async () => {
        const res = await request(app)
            .post('/users')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                username: 'anotheruser',
                firstname: 'Another',
                email: 'newuser@example.com',
                password: 'password123'
            })

        expect(res.statusCode).toBe(409)
    })

    it('should return 400 when required fields are missing', async () => {
        const res = await request(app)
            .post('/users')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ username: 'incomplete' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })
})

describe('PATCH /users/:id', () => {
    it('should update a user with valid data', async () => {
        const res = await request(app)
            .patch(`/users/${createdUserId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                username: 'updateduser',
                roles: ['Employee'],
                active: true
            })

        expect(res.statusCode).toBe(200)
        expect(res.body.message).toContain('updated')
    })

    it('should return 400 when required fields are missing', async () => {
        const res = await request(app)
            .patch(`/users/${createdUserId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ username: 'onlyusername' })

        expect(res.statusCode).toBe(400)
        expect(res.body).toHaveProperty('errors')
    })
})

describe('DELETE /users/:id', () => {
    it('should delete a user by id', async () => {
        const res = await request(app)
            .delete(`/users/${createdUserId}`)
            .set('Authorization', `Bearer ${accessToken}`)

        expect(res.statusCode).toBe(200)
        expect(res.body.message).toContain('deleted')
    })

    it('should return 404 for non-existent user', async () => {
        const fakeId = new (await import('mongoose')).default.Types.ObjectId()
        const res = await request(app)
            .delete(`/users/${fakeId}`)
            .set('Authorization', `Bearer ${accessToken}`)

        expect(res.statusCode).toBe(404)
    })
})